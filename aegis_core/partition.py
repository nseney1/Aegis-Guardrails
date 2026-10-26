"""The AST partition report (v4.2 #5): ``aegis check --partition --split A=GLOB[,GLOB...] --split B=...``.

Lanes are planned as globs. For every lane file the report builds the def, call and import
sets with the Python driver (and the Rust driver, when it is enabled for the workspace),
resolves each call and import through the file's own imports to the file it lands in, and
reports the edges whose two ends are in different lanes, plus a ``[FROZEN_SIGNATURES]``
block: the functions and classes on a boundary, with their signatures, which the lanes
must not change while they run in parallel.

It is a report, not a gate: it changes nothing but the events log, it exits 0 when it
finds edges, and what it says is exactly as good as static name resolution through
imports (see LIMITS, which every report prints). Each run appends a ``partition_check``
event holding the predicted edges, so a later merge conflict can be set against them.

**Lanes.** A file belongs to the lanes whose globs match it (the one target_paths matcher:
a glob without ``/`` also matches at any depth). A file in two lanes is an *overlap*: it
is reported and takes no part in the edges, because its lane is undecided. A file in no
lane is never an edge end.

**Resolution.** A module is looked up from the importing file's directory upward, nearest
first (``<dir>/a/b.py`` or ``<dir>/a/b/__init__.py``; for Rust ``<dir>/a/b.rs`` or
``<dir>/a/b/mod.rs``), which covers sibling imports, workspace-root packages and a
``src/`` layout. A call is followed when its first name is bound by an import
(``import m``, ``import m as x``, ``from m import f``, ``use crate::m::f``); anything else
(a method on an object, a name from a star import) is not guessed.
"""
from __future__ import annotations

import ast
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from aegis_core import baseline, events, primitives, team
from aegis_core.errors import AegisError
from aegis_core.match import matches, normalize_path

__all__ = ["LIMITS", "MAX_PREDICTED", "SOURCE", "Edge", "Frozen", "PartitionUsage", "Report", "check", "parse_splits"]

SOURCE = "aegis check --partition"
MAX_PREDICTED = 200  # edges kept in the event: the log is a metric, not an archive
MIN_LANES = 2
_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_USAGE = "--partition needs at least 2 --split NAME=GLOB[,GLOB...]"
LIMITS = (
    "Edges come from static name resolution through imports: a call on an object, a name reached through a "
    "re-export or a star import, and anything computed at run time are not followed.",
    "Only Python, and Rust when its driver is enabled, are analyzed; any other file in a lane is listed as not "
    "analyzed.",
    "A file that two lanes both match is an overlap and takes no part in the edges.",
    "The Python driver drops the level of a relative import, so a module is looked up from the importing file's "
    "directory upward, nearest first.",
    "Only the signatures of top-level functions and classes are frozen, and only for names that cross a boundary.",
)


class PartitionUsage(AegisError):
    """A ``--split`` that cannot be used. The message names the reason."""


# ── --split ──────────────────────────────────────────────────────────────────

def parse_splits(values: Optional[Iterable[str]]) -> Dict[str, Tuple[str, ...]]:
    """``NAME=GLOB[,GLOB...]`` values as an ordered mapping of lane name to its globs
    (normalized like rule paths, each once). Raises PartitionUsage for fewer than two
    lanes, a lane given twice, a malformed value, a name outside ``[A-Za-z0-9][A-Za-z0-9._-]*``,
    an empty glob, a control character or a glob that climbs out with ``..``."""
    lanes: Dict[str, Tuple[str, ...]] = {}
    for value in values or ():
        name, sep, rest = str(value).partition("=")
        if not sep or not name:
            raise PartitionUsage(f"--split: {str(value)!r} is not NAME=GLOB[,GLOB...]")
        if not _NAME.match(name):
            raise PartitionUsage(f"--split: lane name {name!r} must match [A-Za-z0-9][A-Za-z0-9._-]*")
        if name in lanes:
            raise PartitionUsage(f"--split: lane {name} is given twice")
        if not rest:
            raise PartitionUsage(f"--split: lane {name} has no glob")
        globs: List[str] = []
        for raw in rest.split(","):
            # Check before strip: C1 NEL is whitespace too, but must not disappear.
            problem = team.glob_problem(raw)
            if problem != "control":
                problem = team.glob_problem(raw.strip())
            clean = normalize_path(raw.strip())
            if problem == "control":
                raise PartitionUsage(f"--split: lane {name} has a glob with a control character")
            if problem == "empty":
                raise PartitionUsage(f"--split: lane {name} has an empty glob")
            if problem == "climbs":
                raise PartitionUsage(f"--split: lane {name}: glob {clean!r} climbs out of the workspace with '..'")
            if clean not in globs:
                globs.append(clean)
        lanes[name] = tuple(globs)
    if len(lanes) < MIN_LANES:
        raise PartitionUsage(_USAGE)
    return lanes


# ── Facts of one file ────────────────────────────────────────────────────────

@dataclass
class _Binding:
    """A name an import binds: a module (``file``) or a symbol of one (``file`` and ``original``)."""

    module: bool
    file: str
    original: Optional[str]
    target: str


@dataclass
class _Facts:
    language: str
    defs: Dict[str, Any]
    calls: List[Any]
    imports: List[Any]
    source_lines: List[str] = field(default_factory=list)


def _ancestors(directory: str) -> List[str]:
    """``directory`` and each directory above it, nearest first, ending with the workspace root ('')."""
    found: List[str] = []
    while directory and directory != ".":
        found.append(directory)
        directory = posixpath.dirname(directory)
    found.append("")
    return found


def _module_file(files: frozenset, importer: str, segments: Sequence[str], language: str) -> Optional[str]:
    if not segments:
        return None
    tail = "/".join(segments)
    for directory in _ancestors(posixpath.dirname(importer)):
        base = posixpath.join(directory, tail) if directory else tail
        options = (f"{base}.py", f"{base}/__init__.py") if language == "python" else (f"{base}.rs", f"{base}/mod.rs")
        for option in options:
            if option in files:
                return option
    return None


def _python_segments(source: str) -> List[str]:
    return [part for part in source.split(".") if part]


def _rust_segments(source: str) -> List[str]:
    return [part for part in source.split("::") if part and part not in ("crate", "self", "super")]


def _bindings(files: frozenset, importer: str, facts: _Facts) -> Tuple[Dict[str, _Binding], List[Tuple[int, _Binding, str]]]:
    """(the names the file's imports bind, every resolved import as (line, binding, bound name))."""
    bound: Dict[str, _Binding] = {}
    resolved: List[Tuple[int, _Binding, str]] = []
    rust = facts.language == "rust"
    for imp in facts.imports:
        segments = _rust_segments(imp.source) if rust else _python_segments(imp.source)
        aliases = dict(getattr(imp, "aliases", ()) or ())
        symbols = tuple(imp.imported_symbols or ())
        if not symbols:  # importlib.import_module("m"): an import, binding no name
            target = _module_file(files, importer, segments, facts.language)
            if target:
                resolved.append((imp.line, _Binding(True, target, None, imp.source), ""))
            continue
        for name in symbols:
            original = aliases.get(name, name)
            found: Optional[_Binding] = None
            if rust:
                for k in range(len(segments), 0, -1):
                    module = _module_file(files, importer, segments[:k], "rust")
                    if module is None:
                        continue
                    if k == len(segments):
                        sub = _module_file(files, importer, segments + [original], "rust")
                        found = (_Binding(True, sub, None, "::".join(segments + [original])) if sub
                                 else _Binding(False, module, original, "::".join(segments)))
                    elif k == len(segments) - 1 and original == segments[-1]:
                        found = _Binding(False, module, original, "::".join(segments[:-1]))
                    break
            elif segments and original == imp.source:  # import a.b.c  /  import a.b as x
                module = _module_file(files, importer, segments, "python")
                found = _Binding(True, module, None, imp.source) if module else None
            else:  # from m import name: a submodule, else a symbol of m
                sub = _module_file(files, importer, segments + [original], "python")
                if sub:
                    found = _Binding(True, sub, None, ".".join(segments + [original]))
                else:
                    module = _module_file(files, importer, segments, "python")
                    found = _Binding(False, module, original, imp.source) if module else None
            if found is not None:
                bound[name] = found
                resolved.append((imp.line, found, name))
    return bound, resolved


# ── Signatures ───────────────────────────────────────────────────────────────

def _format_arguments(args: ast.arguments) -> str:
    """The parameters as the author would write them (``name: ann = default``, ``name=default``)."""
    def one(arg: ast.arg, default: Optional[ast.expr]) -> str:
        text = arg.arg
        if arg.annotation is not None:
            text += f": {ast.unparse(arg.annotation)}"
        if default is not None:
            text += f" = {ast.unparse(default)}" if arg.annotation is not None else f"={ast.unparse(default)}"
        return text

    positional = list(args.posonlyargs) + list(args.args)
    defaults: List[Optional[ast.expr]] = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    parts = [one(arg, default) for arg, default in zip(positional, defaults)]
    if args.posonlyargs:
        parts.insert(len(args.posonlyargs), "/")
    if args.vararg is not None:
        parts.append("*" + one(args.vararg, None))
    elif args.kwonlyargs:
        parts.append("*")
    parts += [one(arg, default) for arg, default in zip(args.kwonlyargs, args.kw_defaults)]
    if args.kwarg is not None:
        parts.append("**" + one(args.kwarg, None))
    return ", ".join(parts)


def _function_signature(node: ast.AST) -> str:
    assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    keyword = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    returns = f" -> {ast.unparse(node.returns)}" if node.returns is not None else ""
    return f"{keyword} {node.name}({_format_arguments(node.args)}){returns}"


def _python_signature(tree: ast.Module, name: str) -> Optional[str]:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return _function_signature(node)
        if isinstance(node, ast.ClassDef) and node.name == name:
            bases = ", ".join(ast.unparse(base) for base in node.bases + node.keywords)  # type: ignore[operator]
            head = f"class {name}({bases})" if bases else f"class {name}"
            for member in node.body:
                if isinstance(member, ast.FunctionDef) and member.name == "__init__":
                    return f"{head}; __init__({_format_arguments(member.args)})"
            return head
    return None


def _rust_signature(lines: Sequence[str], line: int) -> Optional[str]:
    if not 1 <= line <= len(lines):
        return None
    text = re.split(r"[{;]", lines[line - 1], maxsplit=1)[0]
    return " ".join(text.split()) or None


# ── The report ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Edge:
    """One edge across a lane boundary: ``kind`` is ``import`` or ``call``; ``symbol`` the
    name it lands on (None for a whole module); ``target`` the name as written; ``def_line``
    where that name is defined in ``to_path`` (None when it is not a top-level def)."""

    kind: str
    from_lane: str
    to_lane: str
    from_path: str
    line: int
    to_path: str
    symbol: Optional[str]
    target: str
    def_line: Optional[int]

    def sort_key(self) -> Tuple[Any, ...]:
        return (self.from_lane, self.to_lane, self.from_path, self.line, self.kind, self.to_path, self.symbol or "")

    def as_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "from_lane": self.from_lane, "to_lane": self.to_lane, "from": self.from_path,
                "line": self.line, "to": self.to_path, "symbol": self.symbol, "target": self.target,
                "def_line": self.def_line}


@dataclass(frozen=True)
class Frozen:
    """A function or class on a boundary: where it is, its signature and who uses it."""

    lane: str
    path: str
    symbol: str
    line: int
    signature: str
    used_by: Tuple[Tuple[str, str, int], ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"lane": self.lane, "path": self.path, "symbol": self.symbol, "line": self.line,
                "signature": self.signature,
                "used_by": [{"lane": lane, "path": path, "line": line} for lane, path, line in self.used_by]}


@dataclass(frozen=True)
class Report:
    workspace: str
    listing: str
    lanes: Dict[str, Tuple[str, ...]]
    lane_files: Dict[str, int]
    analyzed: Dict[str, int]
    languages: Dict[str, int]
    files: int
    unassigned: int
    overlap: Tuple[Tuple[str, Tuple[str, ...]], ...]
    edges: Tuple[Edge, ...]
    frozen: Tuple[Frozen, ...]
    not_analyzed: Tuple[Tuple[str, str], ...]
    checked_at: Optional[float] = None
    warnings: Tuple[str, ...] = ()

    @property
    def files_analyzed(self) -> int:
        return sum(self.languages.values())

    def event_detail(self) -> Dict[str, Any]:
        """The ``partition_check`` event's detail: the lanes and the predicted edges (capped)."""
        predicted = [{"from_lane": e.from_lane, "to_lane": e.to_lane, "kind": e.kind, "from": e.from_path,
                      "to": e.to_path, "symbol": e.symbol} for e in self.edges[:MAX_PREDICTED]]
        return {
            "lanes": {name: list(globs) for name, globs in self.lanes.items()},
            "files": self.files_analyzed,
            "edges": len(self.edges),
            "frozen": len(self.frozen),
            "overlap": len(self.overlap),
            "predicted": predicted,
            "truncated": len(self.edges) > MAX_PREDICTED,
        }

    def as_dict(self) -> Dict[str, Any]:
        document = primitives.envelope(SOURCE, {
            "workspace": self.workspace,
            "listing": self.listing,
            "lanes": list(self.lanes),
            "files": self.files,
            "files_analyzed": self.files_analyzed,
            "unassigned": self.unassigned,
            "languages": dict(sorted(self.languages.items())),
        }, now=self.checked_at)
        document.update(
            lanes=[{"name": name, "globs": list(globs), "files": self.lane_files.get(name, 0),
                    "analyzed": self.analyzed.get(name, 0)} for name, globs in self.lanes.items()],
            overlap=[{"path": path, "lanes": list(names)} for path, names in self.overlap],
            edges=[e.as_dict() for e in self.edges],
            frozen_signatures=[f.as_dict() for f in self.frozen],
            not_analyzed=[{"path": path, "reason": reason} for path, reason in self.not_analyzed],
            limits=list(LIMITS),
            warnings=list(self.warnings),
        )
        return document


# ── The check ────────────────────────────────────────────────────────────────

def _read_facts(root: str, path: str, rust_ready: bool) -> Tuple[Optional[_Facts], Optional[str]]:
    """(facts, None) or (None, why the file is not analyzed)."""
    from pathlib import Path

    from aegis_core.ast.drivers.python import parse_python_ast

    ext = posixpath.splitext(path)[1].lower()
    full = os.path.join(root, *path.split("/"))
    try:
        if ext == ".py":
            tree = parse_python_ast(Path(full))
            language = "python"
        elif ext == ".rs" and rust_ready:
            from aegis_core.ast.runner import ASTDriverRunner

            tree = ASTDriverRunner().parse_file(full, workspace_root=root)
            language = "rust"
        elif ext == ".rs":
            return None, "no AST driver for .rs (enable the packaged driver: ast.packaged_drivers in .aegis/config.json)"
        else:
            return None, f"no partition support for {ext or 'extensionless'} files"
    except Exception as exc:  # a file the driver cannot read is listed, not fatal
        return None, f"cannot be parsed: {type(exc).__name__}"
    defs: Dict[str, Any] = {}
    for definition in tree.definitions:
        if definition.class_name is None and definition.name not in defs:
            defs[definition.name] = definition
    return _Facts(language, defs, list(tree.call_sites), list(tree.imports)), None


def _signature(root: str, path: str, facts: _Facts, symbol: str, cache: Dict[str, Any]) -> Optional[str]:
    full = os.path.join(root, *path.split("/"))
    if facts.language == "python":
        if path not in cache:
            try:
                from aegis_core.ast.drivers.python import read_python_source

                cache[path] = ast.parse(read_python_source(full))
            except (OSError, SyntaxError, UnicodeError, ValueError):
                cache[path] = None
        return None if cache[path] is None else _python_signature(cache[path], symbol)
    if path not in cache:
        try:
            with open(full, "rb") as handle:
                cache[path] = primitives.split_lines(handle.read().decode("utf-8", "replace"))
        except OSError:
            cache[path] = []
    return _rust_signature(cache[path], facts.defs[symbol].line)


def _rust_enabled(root: str) -> bool:
    from aegis_core.ast.runner import ASTDriverRunner

    try:
        return bool(ASTDriverRunner().registry.resolve_driver(".rs", workspace_root=root))
    except Exception:
        return False


def check(root: Any, lanes: Dict[str, Tuple[str, ...]], now: Optional[float] = None, record: bool = True) -> Report:
    """Build the partition report of the workspace at ``root`` for ``lanes`` (the result of
    ``parse_splits``) and, unless ``record`` is false, append a ``partition_check`` event.
    An event that cannot be written is a warning on the report, never a failure."""
    base = os.path.abspath(os.fspath(root))
    listed, listing = baseline.list_files(base)
    fileset = frozenset(listed)
    owners: Dict[str, List[str]] = {}
    for path in listed:
        names = [name for name, globs in lanes.items() if any(matches(glob, path) for glob in globs)]
        if names:
            owners[path] = names
    lane_of = {path: names[0] for path, names in owners.items() if len(names) == 1}
    overlap = tuple(sorted((path, tuple(names)) for path, names in owners.items() if len(names) > 1))
    rust_ready = _rust_enabled(base)

    facts: Dict[str, _Facts] = {}
    not_analyzed: List[Tuple[str, str]] = []
    for path in sorted(lane_of):
        found, why = _read_facts(base, path, rust_ready)
        if found is not None:
            facts[path] = found
        else:
            not_analyzed.append((path, why or "not analyzed"))

    raw: Dict[Tuple[Any, ...], Edge] = {}
    for path, own in facts.items():
        bound, resolved = _bindings(fileset, path, own)
        sep = "::" if own.language == "rust" else "."
        for line, binding, name in resolved:
            target = lane_of.get(binding.file)
            if target is None or target == lane_of[path]:
                continue
            symbol = binding.original
            landing = facts.get(binding.file)
            definition = landing.defs.get(symbol) if landing is not None and symbol else None
            edge = Edge("import", lane_of[path], target, path, line, binding.file, symbol, binding.target,
                        definition.line if definition is not None else None)
            raw[(edge.kind, path, line, binding.file, symbol)] = edge
        for call in own.calls:
            parts = [part for part in call.target.split(sep) if part]
            for k in range(len(parts), 0, -1):
                binding = bound.get(sep.join(parts[:k]))
                if binding is None:
                    continue
                rest = parts[k:]
                symbol = (rest[0] if rest else None) if binding.module else binding.original
                target_lane = lane_of.get(binding.file)
                if symbol and target_lane is not None and target_lane != lane_of[path]:
                    landing = facts.get(binding.file)
                    definition = landing.defs.get(symbol) if landing is not None else None
                    edge = Edge("call", lane_of[path], target_lane, path, call.line, binding.file, symbol,
                                call.target, definition.line if definition is not None else None)
                    raw[(edge.kind, path, call.line, binding.file, symbol)] = edge
                break
    edges = tuple(sorted(raw.values(), key=Edge.sort_key))

    uses: Dict[Tuple[str, str], List[Tuple[str, str, int]]] = {}
    for edge in edges:
        if edge.symbol and edge.def_line is not None:
            uses.setdefault((edge.to_path, edge.symbol), []).append((edge.from_lane, edge.from_path, edge.line))
    signatures: Dict[str, Any] = {}
    frozen: List[Frozen] = []
    for (path, symbol), users in sorted(uses.items()):
        text = _signature(base, path, facts[path], symbol, signatures)
        if text is not None:
            frozen.append(Frozen(lane_of[path], path, symbol, facts[path].defs[symbol].line, text,
                                 tuple(sorted(set(users), key=lambda u: (u[0], u[1], u[2])))))

    languages: Dict[str, int] = {}
    analyzed: Dict[str, int] = {}
    lane_files: Dict[str, int] = {}
    for path, names in owners.items():
        for name in names:
            lane_files[name] = lane_files.get(name, 0) + 1
    for path, own in facts.items():
        languages[own.language] = languages.get(own.language, 0) + 1
        analyzed[lane_of[path]] = analyzed.get(lane_of[path], 0) + 1
    report = Report(
        workspace=base, listing=listing, lanes=dict(lanes), lane_files=lane_files, analyzed=analyzed,
        languages=languages, files=len(listed), unassigned=len(listed) - len(owners), overlap=overlap, edges=edges,
        frozen=tuple(frozen), not_analyzed=tuple(not_analyzed), checked_at=now,
    )
    if not record:
        return report
    warnings: Tuple[str, ...] = ()
    exc = events.try_append(base, "partition_check", "edges" if edges else "clear", report.event_detail())
    if exc is not None:
        warnings = (f"event not recorded: {exc}",)
    return Report(**{**report.__dict__, "warnings": warnings}) if warnings else report
