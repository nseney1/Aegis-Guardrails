"""Normalized AST data contracts and serialization schemas."""
from __future__ import annotations

from dataclasses import dataclass, field
import ast
import json
import os
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "canonical_spelling",
    "DefinitionNode",
    "SymbolDef",
    "CallSiteNode",
    "ImportNode",
    "MutationPoint",
    "NormalizedAST",
]


def _normalize_ast_token(token: str) -> str:
    """Normalize trigger/symbol identifier by stripping leading '@', trailing '()', and whitespace."""
    t = token.strip()
    if t.startswith("@"):
        t = t[1:].strip()
    if t.endswith("()"):
        t = t[:-2].strip()
    return t


def canonical_spelling(token: str) -> str:
    """A matching spelling; serialized nodes retain the driver's original text."""
    t = _normalize_ast_token(token)
    if t.startswith("node:"):
        t = t[5:]
    if t.startswith("::"):  # Rust's absolute root is not a relative import.
        t = t[2:]
    return t.replace("::", ".").replace("/", ".")


def _dotted_name(node: ast.AST) -> Optional[str]:
    """``a.b.c`` for a Name/Attribute chain (only the attributes when the base is not a Name).

    Iterative so a generated attribute chain thousands of links long resolves instead of
    exhausting the recursion limit.
    """
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts)) or None


def _extract_python_decorators_from_tree(tree: ast.AST) -> Tuple[str, ...]:
    """Extract normalized decorator names from a parsed Python AST."""
    decorators: List[str] = []
    seen: set = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                dec_name = _dotted_name(target)
                if dec_name:
                    norm = _normalize_ast_token(dec_name)
                    if norm and norm not in seen:
                        seen.add(norm)
                        decorators.append(norm)
    return tuple(decorators)


def _extract_python_decorators_from_file(file_path: str) -> Tuple[str, ...]:
    """Extract decorator names from a Python file on disk; () when there is no such file.

    Decodes like CPython (BOM, coding cookie) and lets read, decode and syntax errors
    propagate: a caller judging decorators must not mistake an unreadable file for one
    without decorators.
    """
    if not file_path or not file_path.endswith(".py") or not os.path.isfile(file_path):
        return ()
    from aegis_core.ast.source import read_python_source

    source = read_python_source(file_path)
    if not source.strip():
        return ()
    return _extract_python_decorators_from_tree(ast.parse(source, filename=file_path))


# ── Import bindings: the plain form of an import, shared by policy checks ─────

def _as_names(value: Any) -> Tuple[str, ...]:
    """Every name a map value stands for: maps may hold one name or a sequence of them."""
    return (value,) if isinstance(value, str) else tuple(value or ())


def add_binding(table: Dict[str, List[str]], name: str, original: str) -> None:
    bound = table.setdefault(name, [])
    if original not in bound:
        bound.append(original)


_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*\Z")


def _driver_alias_pairs(data: Mapping[str, Any]) -> List[Tuple[str, str]]:
    """``(bound, original)`` pairs of a serialized import record.

    Reads ``aliases`` (pairs or a mapping) plus the single ``alias`` the TypeScript, Rust and
    Go drivers emit for a name bound to the whole import. That alias renames the import's one
    imported name (Rust ``use std::process::Command as Cmd`` -> ``("Cmd", "Command")``), or
    the module itself for a namespace import or an import of no names (TypeScript
    ``import * as cp from 'child_process'``, Go ``import ex "os/exec"``). Go's blank and dot
    imports bind no name, and a record that does not say which name the alias renames (several
    imported names, or text that is not an identifier) adds no pair.
    """
    raw = data.get("aliases") or ()
    pairs = [(str(b), str(o)) for b, o in (raw.items() if isinstance(raw, Mapping) else raw)]
    alias = data.get("alias")
    if isinstance(alias, str) and _IDENTIFIER.match(alias) and alias != "_":
        names = data.get("imported_symbols") or data.get("imported_names") or ()
        source = data.get("source") or data.get("module") or ""
        if data.get("is_wildcard") or not names:
            original = str(source)
        elif len(names) == 1:
            original = str(names[0])
        else:
            original = ""
        if original and original != alias and (alias, original) not in pairs:
            pairs.append((alias, original))
    return pairs


def _import_aliases(imp: Any) -> Dict[str, Tuple[str, ...]]:
    """Map each name an import binds via ``as`` to every name it aliases.

    Multi-valued because one statement may bind a name twice
    (``from m import a as x, b as x``); keeping only one original would hide the other.
    """
    pairs = _driver_alias_pairs(imp) if isinstance(imp, Mapping) else (getattr(imp, "aliases", None) or ())
    if isinstance(pairs, Mapping):
        pairs = pairs.items()
    table: Dict[str, List[str]] = {}
    for a, o in pairs:
        if a and o:
            add_binding(table, canonical_spelling(str(a)), canonical_spelling(str(o)))
    return {name: tuple(originals) for name, originals in table.items()}


def _extract_import_tuple(imp: Any) -> Tuple[str, Tuple[str, ...]]:
    """(source, symbols) of an import in its plain form: aliased names map back to originals."""
    if isinstance(imp, tuple) and len(imp) == 2 and isinstance(imp[0], str):
        return canonical_spelling(imp[0]), tuple(canonical_spelling(s) for s in imp[1])
    if isinstance(imp, str):
        return canonical_spelling(imp), ()
    if isinstance(imp, Mapping):
        src = canonical_spelling(str(imp.get("source") or imp.get("module") or ""))
        raw_syms = imp.get("imported_symbols") or imp.get("imported_names") or ()
    else:
        src = canonical_spelling(str(getattr(imp, "source", "") or getattr(imp, "module", "") or ""))
        raw_syms = getattr(imp, "imported_symbols", ()) or getattr(imp, "imported_names", ()) or ()
    aliases = _import_aliases(imp)
    syms = [canonical_spelling(str(s)) for s in raw_syms if s]
    out: List[str] = []
    expanded: set = set()
    for sym in syms:
        originals = aliases.get(sym)
        if not originals:
            out.append(sym)
            continue
        if sym in expanded:
            continue
        expanded.add(sym)
        out.extend(originals)
        # One bound name per alias pair; a surplus occurrence is a plain binding of the
        # same name in this statement (``from m import a as b, b``) and must be kept.
        if syms.count(sym) > len(originals):
            out.append(sym)
    return src, tuple(out)


# ── Reference spellings: every name a call or decorator may mean, for policy checks ──

def _split_reference(ref: str) -> tuple[str, str]:
    """(head, rest): the head is the bound name, ended by the first ``.`` or Rust ``::``.

    ``rest`` keeps its separator: ``sp.run`` -> ``("sp", ".run")``, ``Cmd::new`` ->
    ``("Cmd", "::new")``.
    """
    cuts = [i for i in (ref.find("."), ref.find("::")) if i != -1]
    cut = min(cuts) if cuts else len(ref)
    return ref[:cut], ref[cut:]


def _dot_suffixes(name: str) -> list[str]:
    """``name`` and each part of it after a dot: exactly the patterns that match ``name``."""
    return [name, *(suffix for i, ch in enumerate(name) if ch == "." for suffix in (name[i:], name[i + 1:]))]


def _suffix_match(spelling: str, pattern: str) -> bool:
    if pattern.startswith("."):
        return spelling.endswith(pattern)
    return spelling == pattern or spelling.endswith(f".{pattern}")


def _dealias(target: str, aliases: Optional[Mapping[str, Any]]) -> list[str]:
    """Rewrite a reference through each alias of its head to plain form (``sp.run`` -> ``subprocess.run``)."""
    head, rest = _split_reference(target)
    if not aliases or head not in aliases:
        return []
    return [f"{orig}{rest}" for orig in _as_names(aliases[head])]


def _spellings(
    ref: str,
    imported_qual_map: Optional[Mapping[str, Any]],
    aliases: Optional[Mapping[str, Any]],
    *,
    qualify_heads: bool,
) -> list[str]:
    """Every spelling of ``ref``: as written and through each alias original, each also
    qualified through the import map (an exact key, else, for calls, its part before the
    first dot). The reference semantics that ``_SpellingIndex`` answers without listing."""
    ref = canonical_spelling(ref)
    out: list[str] = []
    for spelled in [ref, *_dealias(ref, aliases)]:
        out.append(spelled)
        if imported_qual_map:
            if spelled in imported_qual_map:
                out.extend(_as_names(imported_qual_map[spelled]))
            elif qualify_heads and "." in spelled:
                head, tail = spelled.split(".", 1)
                if head in imported_qual_map:
                    out.extend(f"{qual}.{tail}" for qual in _as_names(imported_qual_map[head]))
    return out


class _SpellingIndex:
    """Answers "does any spelling of this reference match the pattern" without listing them.

    Every spelling of ``head + rest`` is ``origin + rest`` or ``qual + w + rest``, where the
    origins (the head and its alias originals) and the qualifications depend only on the head,
    and a pattern matches a spelling iff it is one of the spelling's dot-suffixes. So a check
    is a few lookups in per-head suffix sets: a name bound N times and referenced M ways costs
    about N + M, not N * M. A map key that itself contains ``.`` or ``::`` (hand-built ASTs,
    never a driver) turns a whole reference into an exact key, so such maps enumerate
    ``_spellings`` instead.
    """

    def __init__(
        self,
        imported_qual_map: Optional[Mapping[str, Any]],
        aliases: Optional[Mapping[str, Any]],
        *,
        qualify_heads: bool,
    ):
        self._quals = {canonical_spelling(k): tuple(canonical_spelling(v) for v in _as_names(values))
                       for k, values in (imported_qual_map or {}).items()}
        self._aliases = {canonical_spelling(k): tuple(canonical_spelling(v) for v in _as_names(values))
                         for k, values in (aliases or {}).items()}
        self._qualify_heads = qualify_heads
        self._enumerate = any("." in key or "::" in key for key in self._quals)
        self._heads: dict[tuple[str, bool], tuple[frozenset[str], dict[str, frozenset[str]]]] = {}
        self._qual_suffixes: dict[str, frozenset[str]] = {}

    def matches(self, ref: str, pattern: str) -> bool:
        # An empty pattern names nothing. An empty reference needs no guard: it has no
        # spelling a non-empty pattern ends, and evaluate_forbid_ast drops empty ones anyway.
        ref, pattern = canonical_spelling(ref), canonical_spelling(pattern)
        if not pattern:
            return False
        if self._enumerate:
            spellings = _spellings(ref, self._quals, self._aliases, qualify_heads=self._qualify_heads)
            return any(_suffix_match(s, pattern) for s in spellings)
        if _suffix_match(ref, pattern):  # covers the suffixes that lie inside ``rest``
            return True
        head, rest = _split_reference(ref)
        if not pattern.endswith(rest):
            return False
        stem = pattern[: len(pattern) - len(rest)]
        origins, qualified = self._index(head, rest)
        if stem in origins:
            return True
        # qual + w + rest: the stem is a dot-suffix of some qual followed by w
        for w in ("", *(stem[i:] for i, ch in enumerate(stem) if ch == ".")):
            quals = qualified.get(w)
            if quals is not None and stem[: len(stem) - len(w)] in quals:
                return True
        return False

    def _index(self, head: str, rest: str) -> tuple[frozenset[str], dict[str, frozenset[str]]]:
        # Calls qualify an origin through its part before the first dot (w is the remainder),
        # except an undotted origin followed by ``::``; decorators only qualify a bare origin.
        mode = rest.startswith("::") if self._qualify_heads else not rest
        key = (head, mode)
        if key not in self._heads:
            origins = [head, *_as_names(self._aliases.get(head))]
            members: dict[str, set[str]] = {}
            for origin in origins:
                if self._qualify_heads:
                    origin_head = origin.partition(".")[0]
                    w = origin[len(origin_head):]
                    if origin_head in self._quals and not (mode and not w):
                        members.setdefault(w, set()).add(origin_head)
                elif mode and origin in self._quals:
                    members.setdefault("", set()).add(origin)
            self._heads[key] = (
                frozenset(s for origin in origins for s in _dot_suffixes(origin)),
                {w: self._suffixes_of(names) for w, names in members.items()},
            )
        return self._heads[key]

    def _suffixes_of(self, names: set[str]) -> frozenset[str]:
        sets = []
        for name in names:
            if name not in self._qual_suffixes:
                self._qual_suffixes[name] = frozenset(
                    s for qual in _as_names(self._quals[name]) for s in _dot_suffixes(qual)
                )
            sets.append(self._qual_suffixes[name])
        return sets[0] if len(sets) == 1 else frozenset().union(*sets)


def _call_target(call_item: Any) -> str:
    if isinstance(call_item, str):
        return _normalize_ast_token(call_item)
    if isinstance(call_item, Mapping):
        return _normalize_ast_token(str(call_item.get("target") or call_item.get("name") or ""))
    return _normalize_ast_token(str(getattr(call_item, "target", "") or getattr(call_item, "name", "") or ""))


def _decorator_name(decorator_item: Any) -> str:
    if isinstance(decorator_item, str):
        raw = decorator_item
    elif isinstance(decorator_item, Mapping):
        raw = str(decorator_item.get("name") or decorator_item.get("target") or "")
    else:
        raw = str(getattr(decorator_item, "name", "") or getattr(decorator_item, "target", "") or decorator_item)
    return _normalize_ast_token(raw).split("(", 1)[0].strip()


def _decorator_pattern(pattern: str) -> str:
    return _normalize_ast_token(pattern).split("(", 1)[0].strip()


@dataclass(frozen=True)
class DefinitionNode:
    """Represents a declared symbol (function, method, class, or constant)."""

    name: str
    kind: str = "function"
    line: int = 1
    is_exported: bool = False
    class_name: Optional[str] = None
    decorators: Tuple[str, ...] = ()

    @property
    def is_method(self) -> bool:
        return self.kind == "method" or bool(self.class_name)

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
            "line": self.line,
            "is_exported": self.is_exported,
            "class_name": self.class_name,
        }
        if self.decorators:
            res["decorators"] = list(self.decorators)
        return res

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DefinitionNode:
        raw_decs = data.get("decorators") or ()
        return cls(
            name=str(data["name"]),
            kind=str(data.get("kind", "function")),
            line=int(data.get("line", 1)),
            is_exported=bool(data.get("is_exported", False)),
            class_name=str(data["class_name"]) if data.get("class_name") else None,
            decorators=tuple(str(d) for d in raw_decs),
        )


SymbolDef = DefinitionNode


@dataclass(frozen=True)
class CallSiteNode:
    """Represents an invocation of a target identifier or member expression.

    ``shadowed``: whether a def, class or import binding of a bare-name target is visible at the
    call, from a driver that resolves scope; None (omitted) makes policy use file-wide bindings.
    """
    target: str
    line: int = 1
    caller_scope: Optional[str] = None
    args: Dict[str, Any] = field(default_factory=dict)
    shadowed: Optional[bool] = None
    kind: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {"target": self.target, "line": self.line, "caller_scope": self.caller_scope}
        if self.args:
            res["args"] = dict(self.args)
        if self.shadowed is not None:
            res["shadowed"] = self.shadowed
        if self.kind is not None:
            res["kind"] = self.kind
        return res

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CallSiteNode:
        raw_args = data.get("args") or {}
        args = {str(k): v for k, v in (raw_args.items() if isinstance(raw_args, Mapping) else raw_args)}
        return cls(
            target=str(data["target"]),
            line=int(data.get("line", 1)),
            caller_scope=str(data["caller_scope"]) if data.get("caller_scope") else None,
            args=args,
            shadowed=data["shadowed"] if isinstance(data.get("shadowed"), bool) else None,
            kind=str(data["kind"]) if data.get("kind") is not None else None,
        )


@dataclass(frozen=True)
class ImportNode:
    """Represents an external or sibling module dependency.

    ``imported_symbols`` holds the names the import binds in the importing scope.
    ``aliases`` holds one ``(bound_name, original_name)`` pair per ``as`` rebinding:
    ``import os.path as osp`` -> ``("osp", "os.path")``; ``from os import path as p``
    -> ``("p", "path")``. Policy checks use it to judge the aliased form exactly like
    the plain form, so renaming an import cannot hide a forbidden API. ``from_dict``
    also turns the single ``alias`` of the TypeScript, Rust and Go drivers into a pair
    (``_driver_alias_pairs``); grouped member aliases use explicit pairs.
    """

    source: str
    imported_symbols: Tuple[str, ...] = ()
    line: int = 1
    is_type_only: bool = False
    aliases: Tuple[Tuple[str, str], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "source": self.source,
            "imported_symbols": list(self.imported_symbols),
            "line": self.line,
            "is_type_only": self.is_type_only,
        }
        # Omitted when empty so plain imports serialize exactly as before aliases existed.
        if self.aliases:
            res["aliases"] = [list(pair) for pair in self.aliases]
        return res

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ImportNode:
        source_val = data.get("source") if "source" in data else data.get("module", "")
        symbols = data.get("imported_symbols") if "imported_symbols" in data else data.get("imported_names", ())
        return cls(
            source=str(source_val),
            imported_symbols=tuple(str(s) for s in symbols),
            line=int(data.get("line", 1)),
            is_type_only=bool(data.get("is_type_only", False)),
            aliases=tuple(_driver_alias_pairs(data)),
        )


@dataclass(frozen=True)
class MutationPoint:
    """Location and replacement candidate for mutation testing."""

    line: int
    col: int
    original_op: str
    replacement_op: str
    mutation_type: str = "operator"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "line": self.line,
            "col": self.col,
            "original_op": self.original_op,
            "replacement_op": self.replacement_op,
            "mutation_type": self.mutation_type,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MutationPoint:
        orig = data.get("original_op") if "original_op" in data else data.get("original", "")
        rep = data.get("replacement_op") if "replacement_op" in data else data.get("mutated", "")
        col = data.get("col", data.get("column", 0))
        m_type = data.get("mutation_type") if "mutation_type" in data else data.get("kind", "operator")
        return cls(
            line=int(data["line"]),
            col=int(col),
            original_op=str(orig),
            replacement_op=str(rep),
            mutation_type=str(m_type),
        )


@dataclass(frozen=True, init=False)
class NormalizedAST:
    """Language-agnostic Normalized AST representation."""

    file_path: str = "<unknown>"
    language: str = "python"
    definitions: Tuple[DefinitionNode, ...] = ()
    call_sites: Tuple[CallSiteNode, ...] = ()
    imports: Tuple[ImportNode, ...] = ()
    mutation_points: Tuple[MutationPoint, ...] = ()
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        file_path: str = "<unknown>",
        language: str = "python",
        definitions: Sequence[Any] = (),
        call_sites: Sequence[Any] = (),
        imports: Sequence[Any] = (),
        mutation_points: Sequence[Any] = (),
        version: str = "1.0",
        metadata: Optional[Mapping[str, Any]] = None,
        *,
        symbols: Optional[Sequence[Any]] = None,
        calls: Optional[Sequence[Any]] = None,
        decorators: Optional[Sequence[Any]] = None,
    ) -> None:
        if not file_path:
            raise ValueError("file_path cannot be empty")
        if not language:
            raise ValueError("language cannot be empty")

        raw_defs = symbols if (symbols is not None and not definitions) else definitions
        coerced_defs: List[DefinitionNode] = []
        for d in raw_defs or ():
            if isinstance(d, DefinitionNode):
                coerced_defs.append(d)
            elif isinstance(d, Mapping):
                coerced_defs.append(DefinitionNode.from_dict(d))
            elif isinstance(d, str):
                coerced_defs.append(DefinitionNode(name=_normalize_ast_token(d)))
            else:
                coerced_defs.append(d)

        raw_calls = calls if (calls is not None and not call_sites) else call_sites
        coerced_calls: List[CallSiteNode] = []
        for c in raw_calls or ():
            if isinstance(c, CallSiteNode):
                coerced_calls.append(c)
            elif isinstance(c, str):
                coerced_calls.append(CallSiteNode(target=_normalize_ast_token(c)))
            elif isinstance(c, Mapping):
                coerced_calls.append(CallSiteNode.from_dict(c))
            else:
                coerced_calls.append(c)

        coerced_imports: List[ImportNode] = []
        for imp in imports or ():
            if isinstance(imp, ImportNode):
                coerced_imports.append(imp)
            elif isinstance(imp, str):
                norm = _normalize_ast_token(imp)
                coerced_imports.append(ImportNode(source=norm, imported_symbols=(norm.split(".")[-1],) if norm else ()))
            elif isinstance(imp, Mapping):
                coerced_imports.append(ImportNode.from_dict(imp))
            else:
                coerced_imports.append(imp)

        coerced_mutations: List[MutationPoint] = []
        for m in mutation_points or ():
            if isinstance(m, MutationPoint):
                coerced_mutations.append(m)
            elif isinstance(m, Mapping):
                coerced_mutations.append(MutationPoint.from_dict(m))
            else:
                coerced_mutations.append(m)

        meta_dict: Dict[str, Any] = dict(metadata) if metadata else {}
        if isinstance(meta_dict.get("allow_comments"), Mapping):
            meta_dict["allow_comments"] = {int(line): entries for line, entries in meta_dict["allow_comments"].items()}
        if isinstance(meta_dict.get("capabilities"), (list, tuple, set, frozenset)):
            meta_dict["capabilities"] = sorted(set(meta_dict["capabilities"]))
        if decorators is not None:
            meta_dict["decorators"] = [_normalize_ast_token(d) if isinstance(d, str) else str(d) for d in decorators]

        object.__setattr__(self, "file_path", file_path)
        object.__setattr__(self, "language", language)
        object.__setattr__(self, "definitions", tuple(coerced_defs))
        object.__setattr__(self, "call_sites", tuple(coerced_calls))
        object.__setattr__(self, "imports", tuple(coerced_imports))
        object.__setattr__(self, "mutation_points", tuple(coerced_mutations))
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "metadata", meta_dict)

    @property
    def symbols(self) -> Tuple[DefinitionNode, ...]:
        return self.definitions

    @property
    def calls(self) -> Tuple[str, ...]:
        return tuple(c.target if hasattr(c, "target") else str(c) for c in self.call_sites)

    @property
    def decorators(self) -> Tuple[str, ...]:
        meta_decs = self.metadata.get("decorators") if isinstance(self.metadata, dict) else None
        if meta_decs is not None:
            return tuple(_normalize_ast_token(str(d)) for d in meta_decs if d)
        def_decs: List[str] = []
        for d in self.definitions:
            for dec in getattr(d, "decorators", ()) or ():
                norm = _normalize_ast_token(str(dec))
                if norm and norm not in def_decs:
                    def_decs.append(norm)
        return tuple(def_decs) if def_decs else _extract_python_decorators_from_file(self.file_path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "file_path": self.file_path,
            "language": self.language,
            "definitions": [d.to_dict() for d in self.definitions],
            "call_sites": [c.to_dict() for c in self.call_sites],
            "imports": [i.to_dict() for i in self.imports],
            "mutation_points": [m.to_dict() for m in self.mutation_points],
            "metadata": dict(self.metadata),
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NormalizedAST:
        return cls(
            file_path=str(data["file_path"]),
            language=str(data["language"]),
            definitions=tuple(DefinitionNode.from_dict(d) for d in data.get("definitions", ())),
            call_sites=tuple(CallSiteNode.from_dict(c) for c in data.get("call_sites", ())),
            imports=tuple(ImportNode.from_dict(i) for i in data.get("imports", ())),
            mutation_points=tuple(
                MutationPoint.from_dict(m)
                for m in (data.get("mutation_points") if "mutation_points" in data else data.get("mutations", ()))
            ),
            version=str(data.get("version", "1.0")),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_json(cls, json_str: str) -> NormalizedAST:
        return cls.from_dict(json.loads(json_str))

