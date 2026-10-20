"""Built-in Python Native AST Driver.

Extracts language-agnostic NormalizedAST representation using Python's standard library
ast module. Operates purely in-process with zero external dependencies.
"""
from __future__ import annotations

import ast
import functools
import io
import os
from pathlib import Path
import tokenize
from typing import Dict, FrozenSet, List, NamedTuple, Optional, Set, Tuple, Union

from aegis_core.ast.schema import (
    CallSiteNode,
    DefinitionNode,
    ImportNode,
    MutationPoint,
    NormalizedAST,
    _add_binding,
)


# Callables that import the module named by their literal first argument (or ``name=``).
# "module": returns that module; "package" (the __import__ family): returns its top-level
# package, or the module itself when a fromlist is passed.
_DYNAMIC_IMPORTERS = {
    "importlib.import_module": "module",
    "__import__": "package",
    "builtins.__import__": "package",
    "__builtins__.__import__": "package",
    "importlib.__import__": "package",
}

_SCOPE_NODES = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def _literal_str(node: Optional[ast.AST]) -> Optional[str]:
    """The value of a string built only from literals (``'a'``, ``'a' + 'b'``, ``f'ab'``), else None.

    Iterative so a long generated concatenation does not exhaust the recursion limit.
    """
    parts: List[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            parts.append(current.value)
        elif isinstance(current, ast.JoinedStr):
            stack.extend(reversed(current.values))
        elif isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            stack.extend((current.right, current.left))
        else:
            return None
    return "".join(parts)


def _call_argument(call: ast.Call, position: int, keyword: str) -> Optional[ast.AST]:
    if len(call.args) > position:
        return call.args[position]
    return next((k.value for k in call.keywords if k.arg == keyword), None)


def _render_arg(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return repr(node.value)[:64]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, (int, float)):
        return f"-{node.operand.value!r}"[:64]
    chain: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        chain.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        chain.append(cur.id)
        return ".".join(reversed(chain))[:64]
    return "<expr>"


def _call_args(call: ast.Call) -> Dict[str, str]:
    args: Dict[str, str] = {}
    for idx, arg in enumerate(call.args):
        args["*" if isinstance(arg, ast.Starred) else f"#{idx}"] = "" if isinstance(arg, ast.Starred) else _render_arg(arg)
    for kw in call.keywords:
        args[kw.arg if kw.arg else "**"] = _render_arg(kw.value) if kw.arg else ""
    return args


def _resolve_relative(name: str, package: Optional[str]) -> str:
    """``importlib.import_module``'s resolution of a leading-dot name; ``name`` when it cannot resolve."""
    level = len(name) - len(name.lstrip("."))
    bits = (package or "").rsplit(".", level - 1)
    if not package or len(bits) < level:  # no package, or beyond the top-level package
        return name
    return f"{bits[0]}.{name[level:]}" if name[level:] else bits[0]


def _chain_base(func: ast.AST) -> ast.AST:
    while isinstance(func, ast.Attribute):
        func = func.value
    return func


@functools.lru_cache(maxsize=None)
def _decodes_ascii_as_itself(encoding: str) -> bool:
    """True when every ASCII byte decodes to itself in any context under ``encoding``.

    Every two-byte ASCII sequence is probed, so a stateful codec's shift sequence
    (utf-7 ``+``, hz ``~{``, iso2022 ESC, unicode_escape ``\\``) shows up as a change,
    plus an IDNA A-label: idna is the one stdlib codec whose trigger is longer than two
    bytes. A codec that fails the probe in any way counts as not transparent (fail closed).
    """
    probe = bytes(b for hi in range(128) for lo in range(128) for b in (hi, lo)) + b".xn--ls8h."
    try:
        return probe.decode(encoding) == probe.decode("ascii")
    except (LookupError, ValueError, TypeError):
        return False


def read_python_source(path: Union[str, Path]) -> str:
    """Decode a Python source file with the encoding CPython chooses for it.

    Honours a UTF-8 BOM and a PEP 263 coding cookie on line 1 or 2. Line endings are
    normalised before the cookie search because CPython counts ``\\r`` and ``\\r\\n`` as
    line breaks there; ``tokenize.open`` splits on ``\\n`` only, so it would honour a cookie
    CPython ignores (a CR-only file whose fourth line declares utf-7) and decode different
    code than CPython runs. Raises SyntaxError for an unknown or conflicting declaration,
    UnicodeDecodeError for bytes the encoding cannot decode, and UnicodeError for an
    encoding that does not decode ASCII to itself (utf-7, hz, iso2022, unicode_escape,
    utf-16, EBCDIC): there the code's meaning depends on the decoder, so it is refused.
    """
    data = Path(path).read_bytes()
    universal = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    encoding, _ = tokenize.detect_encoding(io.BytesIO(universal).readline)
    if encoding not in ("utf-8", "utf-8-sig") and not _decodes_ascii_as_itself(encoding):
        raise UnicodeError(f"source encoding {encoding!r} does not decode ASCII to itself")
    return data.decode(encoding)


def _import_bindings(tree: ast.AST) -> Dict[str, Tuple[str, ...]]:
    """Every qualified name each imported name is bound to, file-wide (any scope or order).

    ``import importlib as il`` -> il: importlib; ``from importlib import import_module``
    -> import_module: importlib.import_module. Multi-valued like the policy maps, so a
    rebinding can add a meaning but never hide one.
    """
    table: Dict[str, List[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    _add_binding(table, a.asname, a.name)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name != "*":
                    _add_binding(table, a.asname or a.name, f"{node.module}.{a.name}")
    return {name: tuple(quals) for name, quals in table.items()}


def _alias_pairs(names: List[ast.alias]) -> Tuple[Tuple[str, str], ...]:
    """(bound_name, original_name) for every real ``as`` rebinding in an import."""
    return tuple((a.asname, a.name) for a in names if a.asname and a.asname != a.name)


class _Frame(NamedTuple):
    kind: str  # "module", "function" or "class"
    parent: Optional["_Frame"]
    bound: Set[str]  # the names a def, class or import binds directly in this scope


_FUNCTION_LIKE = (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _bound_name_calls(tree: ast.AST) -> Set[int]:
    """ids of the bare-name calls whose callee a def, class or import binds where Python's lookup
    finds it: the call's scope, then enclosing function and module scopes (a class body only for
    code directly in it). Parameters, assignments and plain ``import x`` do not bind; order inside
    a scope is not modelled (a call before a later def, a def under ``if False:``)."""
    pending: List[Tuple[int, str, _Frame]] = []
    stack: List[Tuple[ast.AST, _Frame]] = [(tree, _Frame("module", None, set()))]
    while stack:
        node, frame = stack.pop()
        if isinstance(node, _SCOPE_NODES):
            frame.bound.add(node.name)
            inner = _Frame("class" if isinstance(node, ast.ClassDef) else "function", frame, set())
            body = {id(child) for child in node.body}
            stack.extend((child, inner if id(child) in body else frame) for child in ast.iter_child_nodes(node))
            continue
        if isinstance(node, ast.Import):
            frame.bound.update(a.asname for a in node.names if a.asname)
        elif isinstance(node, ast.ImportFrom):
            frame.bound.update(a.asname or a.name for a in node.names if a.name != "*")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            pending.append((id(node), node.func.id, frame))
        frame = _Frame("function", frame, set()) if isinstance(node, _FUNCTION_LIKE) else frame
        stack.extend((child, frame) for child in ast.iter_child_nodes(node))
    bound: Set[int] = set()
    for call_id, name, frame in pending:
        scope: Optional[_Frame] = frame
        while scope is not None and not (name in scope.bound and (scope.kind != "class" or scope is frame)):
            scope = scope.parent
        if scope is not None:
            bound.add(call_id)
    return bound


class _PythonASTVisitor:
    """Collects the NormalizedAST parts in one pre-order pass (``walk``).

    The pass uses an explicit stack, not ``ast.NodeVisitor`` recursion, so nesting depth is
    bounded by what CPython parses rather than by the recursion limit: a long generated method
    chain or concatenation is checked instead of failing as unverifiable. Each ``visit_*``
    handler runs when its node is entered; scopes are popped when the node is left.
    """

    def __init__(self, file_path: str, bindings: Optional[Dict[str, Tuple[str, ...]]] = None):
        self.file_path = file_path
        self.bindings = bindings or {}
        self._binding_sets = {name: frozenset(quals) for name, quals in self.bindings.items()}
        self._dynamic_cache: Dict[int, Optional[Tuple[str, FrozenSet[str]]]] = {}
        self._bound_calls: Set[int] = set()
        self.dunder_all: Optional[Set[str]] = None
        self.scope_stack: List[str] = []
        self.class_stack: List[str] = []

        self.definitions: List[DefinitionNode] = []
        self.call_sites: List[CallSiteNode] = []
        self.imports: List[ImportNode] = []
        self.mutation_points: List[MutationPoint] = []

    def walk(self, tree: ast.AST) -> None:
        self._bound_calls = _bound_name_calls(tree)
        stack: List[Tuple[ast.AST, bool]] = [(tree, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                self.scope_stack.pop()
                if isinstance(node, ast.ClassDef):
                    self.class_stack.pop()
                continue
            handler = getattr(self, f"visit_{type(node).__name__}", None)
            if handler is not None:
                handler(node)
            if isinstance(node, _SCOPE_NODES):
                stack.append((node, True))
            stack.extend((child, False) for child in reversed(list(ast.iter_child_nodes(node))))

    def visit_Assign(self, node: ast.Assign):
        # Extract __all__ = ["func1", "func2"]
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    self.dunder_all = set()
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            self.dunder_all.add(elt.value)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            imported = (alias.asname or alias.name,)
            self.imports.append(
                ImportNode(
                    source=alias.name,
                    imported_symbols=imported,
                    line=node.lineno,
                    aliases=_alias_pairs([alias]),
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom):
        source = node.module or ""
        symbols = tuple(alias.asname or alias.name for alias in node.names)
        self.imports.append(
            ImportNode(
                source=source,
                imported_symbols=symbols,
                line=node.lineno,
                aliases=_alias_pairs(node.names),
            )
        )

    def visit_ClassDef(self, node: ast.ClassDef):
        class_name = node.name
        is_exported = (
            class_name in self.dunder_all
            if self.dunder_all is not None
            else not class_name.startswith("_")
        )
        self.definitions.append(
            DefinitionNode(
                name=class_name,
                kind="class",
                line=node.lineno,
                is_exported=is_exported,
            )
        )
        self.class_stack.append(class_name)
        self.scope_stack.append(class_name)

    def _visit_func(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]):
        func_name = node.name
        class_name = self.class_stack[-1] if self.class_stack else None
        is_method = class_name is not None
        kind = "method" if is_method else "function"

        if self.dunder_all is not None:
            is_exported = func_name in self.dunder_all
        else:
            is_exported = not func_name.startswith("_")

        self.definitions.append(
            DefinitionNode(
                name=func_name,
                kind=kind,
                line=node.lineno,
                is_exported=is_exported,
                class_name=class_name,
            )
        )

        self.scope_stack.append(func_name)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _importer_kinds(self, target: str) -> FrozenSet[str]:
        """Kinds of the dynamic importers ``target`` names, as written or through an import binding.

        Same answer as testing every spelling ``qual + rest`` of the target, at one set lookup
        per known importer instead of one string per binding of its head.
        """
        head, dot, tail = target.partition(".")
        rest = dot + tail
        quals = self._binding_sets.get(head, frozenset())
        return frozenset(
            kind
            for name, kind in _DYNAMIC_IMPORTERS.items()
            if name == target or (name.endswith(rest) and name[: len(name) - len(rest)] in quals)
        )

    def _call_targets(self, func: ast.AST) -> List[str]:
        """Dotted call targets; a chain on a dynamic import resolves to the imported module."""
        parts: List[str] = []
        current = func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        tail = ".".join(reversed(parts))
        if isinstance(current, ast.Name):
            return [f"{current.id}.{tail}" if tail else current.id]
        if isinstance(current, ast.Call) and tail:
            return [f"{module}.{tail}" for module in self._modules_returned(current)]
        return []

    def _dynamic_import(self, call: ast.Call) -> Optional[Tuple[str, FrozenSet[str]]]:
        """(module name, importer kinds) when ``call`` imports a literal module name."""
        # Resolve a method chain from its innermost call outward, so resolving each link only
        # reads the cached link below it: recursion stays flat however long the chain.
        pending: List[ast.Call] = []
        node: ast.AST = call
        while isinstance(node, ast.Call) and id(node) not in self._dynamic_cache:
            pending.append(node)
            node = _chain_base(node.func)
        for link in reversed(pending):
            self._dynamic_cache[id(link)] = self._resolve_dynamic_import(link)
        return self._dynamic_cache[id(call)]

    def _resolve_dynamic_import(self, call: ast.Call) -> Optional[Tuple[str, FrozenSet[str]]]:
        kinds = frozenset().union(*(self._importer_kinds(t) for t in self._call_targets(call.func)))
        if not kinds:
            return None
        name = _literal_str(_call_argument(call, 0, "name")) or ""
        if name.startswith(".") and "module" in kinds:
            name = _resolve_relative(name, _literal_str(_call_argument(call, 1, "package")))
        return (name, kinds) if name else None

    def _modules_returned(self, call: ast.Call) -> List[str]:
        """Modules a dynamic import call evaluates to (both candidates when unsure)."""
        found = self._dynamic_import(call)
        if not found:
            return []
        name, kinds = found
        modules = [name] if "module" in kinds else []
        if "package" in kinds:
            modules.append(name.split(".")[0])
            if len(call.args) > 3 or any(k.arg == "fromlist" for k in call.keywords):
                modules.append(name)
        return list(dict.fromkeys(modules))

    def visit_Call(self, node: ast.Call):
        found = self._dynamic_import(node)
        if found:
            self.imports.append(ImportNode(source=found[0], line=node.lineno))

        caller_scope = self.scope_stack[-1] if self.scope_stack else None
        call_args = _call_args(node)
        shadowed = (id(node) in self._bound_calls) if isinstance(node.func, ast.Name) else None
        for target in self._call_targets(node.func):
            self.call_sites.append(
                CallSiteNode(
                    target=target,
                    line=node.lineno,
                    caller_scope=caller_scope,
                    args=call_args,
                    shadowed=shadowed,
                )
            )

    def visit_Compare(self, node: ast.Compare):
        # Extract comparison mutation points
        op_map = {
            ast.Eq: ("==", "!="),
            ast.NotEq: ("!=", "=="),
            ast.Lt: ("<", ">="),
            ast.Gt: (">", "<="),
            ast.LtE: ("<=", ">"),
            ast.GtE: (">=", "<"),
        }
        for op in node.ops:
            op_type = type(op)
            if op_type in op_map:
                orig, repl = op_map[op_type]
                self.mutation_points.append(
                    MutationPoint(
                        line=node.lineno,
                        col=getattr(node, "col_offset", 0),
                        original_op=orig,
                        replacement_op=repl,
                        mutation_type="comparison",
                    )
                )

    def visit_BinOp(self, node: ast.BinOp):
        bin_map = {
            ast.Add: ("+", "-"),
            ast.Sub: ("-", "+"),
            ast.Mult: ("*", "/"),
            ast.Div: ("/", "*"),
        }
        op_type = type(node.op)
        if op_type in bin_map:
            orig, repl = bin_map[op_type]
            self.mutation_points.append(
                MutationPoint(
                    line=node.lineno,
                    col=getattr(node, "col_offset", 0),
                    original_op=orig,
                    replacement_op=repl,
                    mutation_type="binary_op",
                )
            )


def parse_python_ast(
    source_or_path: Union[str, Path],
    file_path: Optional[str] = None,
) -> NormalizedAST:
    """Parse Python source code or file into a NormalizedAST instance."""
    resolved_path = str(file_path or source_or_path)
    # With an explicit file_path a str is always source text: a one-line source that names
    # an existing file must not be swapped for that file. os.path.isfile, not Path.is_file,
    # because the latter raises OSError (ENAMETOOLONG) on a long one-line source.
    if isinstance(source_or_path, Path) or (
        file_path is None
        and isinstance(source_or_path, str)
        and "\n" not in source_or_path
        and os.path.isfile(source_or_path)
    ):
        content = read_python_source(source_or_path)
        resolved_path = str(source_or_path)
    else:
        content = str(source_or_path)

    try:
        tree = ast.parse(content, filename=resolved_path)
    except SyntaxError as exc:
        raise ValueError(f"Failed to parse Python AST for {resolved_path}: {exc}") from exc

    visitor = _PythonASTVisitor(file_path=resolved_path, bindings=_import_bindings(tree))
    visitor.walk(tree)

    return NormalizedAST(
        file_path=resolved_path,
        language="python",
        definitions=tuple(visitor.definitions),
        call_sites=tuple(visitor.call_sites),
        imports=tuple(visitor.imports),
        mutation_points=tuple(visitor.mutation_points),
        metadata={"parser": "stdlib_ast"},
    )
