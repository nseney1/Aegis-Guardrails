"""AST policy evaluation, extraction, and planned-symbol synthesis."""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
import io
import os
import re
import tokenize
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from aegis_core.errors import AegisError
from aegis_core.ast.literals import compare_literal, compare_options
from aegis_core.ast.schema import (
    NormalizedAST, _SpellingIndex, add_binding, _call_target, _decorator_name,
    _decorator_pattern, _extract_import_tuple, _extract_python_decorators_from_file,
    _extract_python_decorators_from_tree, _import_aliases, _normalize_ast_token, canonical_spelling,
)

__all__ = ["ASTExtractionError", "_match_ImportNode_against_pattern", "evaluate_forbid_ast", "evaluate_forbid_ast_delta", "evaluate_forbid_ast_structured", "extract_normalized_ast", "parse_allow_comments", "violation_messages"]
_ALLOW_COMMENT_RE = re.compile(r"#\s*aegis:\s*allow(?:\[([^\]]+)\])?(?:\s*[:\-]?\s*(.*))?$", re.IGNORECASE)
_ABSENT = object()


def _cond(value: Any, cond: Any, has_splat: bool) -> Optional[bool]:
    # The spec grammar only: a scalar literal, {in: [...]}, {not: cond}, {absent: bool}. Rule load
    # (verification.runner._forbid_ast_spec_error) refuses anything else; an unvalidated caller's
    # unknown operator is UNKNOWN, and no rule text ever reaches ``re``.
    if not isinstance(cond, Mapping):
        if value is _ABSENT:
            return None if has_splat else False
        return compare_literal(value, cond)
    res: Optional[bool] = True
    for op, target in cond.items():
        if op == "not":
            inner = _cond(value, target, has_splat)
            v = None if inner is None else not inner
        elif op == "absent":
            v = None if (value is _ABSENT and has_splat) else ((value is _ABSENT) == bool(target))
        elif op == "in":
            opts = target if isinstance(target, (list, tuple, set, frozenset)) else ()
            v = (None if has_splat else False) if value is _ABSENT else compare_options(value, opts)
        else:
            v = None
        if v is False:
            return False
        if v is None:
            res = None
    return res


def _site_args(site: Any) -> Dict[str, Any]:
    raw = site.get("args") if isinstance(site, Mapping) else getattr(site, "args", None)
    return dict(raw) if isinstance(raw, Mapping) else {}


def _driver_extracts_args(normalized_ast: Any) -> bool:
    meta = getattr(normalized_ast, "metadata", None)
    capabilities = meta.get("capabilities", ()) if isinstance(meta, Mapping) else ()
    return isinstance(capabilities, (list, tuple, set, frozenset)) and "args" in capabilities


def _match_where(site: Any, where: Mapping[str, Any], args_known: bool = True) -> Optional[bool]:
    args = _site_args(site)
    if not args_known:
        return None
    has_splat = "*" in args or "**" in args
    res: Optional[bool] = True
    for raw_key, cond in where.items():
        v = _cond(next((args[k] for k in (p.strip() for p in str(raw_key).split("|")) if k in args), _ABSENT), cond, has_splat)
        if v is False:
            return False
        if v is None:
            res = None
    return res


def _add_allow(by_line: Dict[int, List[Dict[str, Any]]], line_no: int, text: str) -> None:
    m = _ALLOW_COMMENT_RE.search(text)
    if m:
        rules = {r.strip() for r in m.group(1).split(",") if r.strip()} if m.group(1) else None
        by_line.setdefault(int(line_no), []).append({"rules": rules, "reason": (m.group(2) or "").strip()})


def parse_allow_comments(source: str, language: str = "python") -> Dict[int, List[Dict[str, Any]]]:
    # Non-Python overrides come only from parser comment tokens in metadata. Their
    # lexical boundaries (JS regex/templates, Rust raw strings) belong to each driver.
    if language.lower() != "python":
        return {}
    if not source or "aegis" not in source.lower():
        return {}
    by_line: Dict[int, List[Dict[str, Any]]] = {}
    try:
        for tok_type, tok_str, (srow, _), _, _ in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok_type == tokenize.COMMENT:
                _add_allow(by_line, srow, tok_str)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        for idx, line in enumerate(source.splitlines(), start=1):
            _add_allow(by_line, idx, line)
    return by_line


def _line_of(item: Any) -> Optional[int]:
    val = item.get("line") if isinstance(item, Mapping) else getattr(item, "line", None)
    return int(val) if isinstance(val, int) and val > 0 else None


def _allow_reason_for_line(allow_map: Mapping[int, List[Dict[str, Any]]], line: Optional[int], rule_id: Optional[str]) -> Optional[str]:
    for entry in (allow_map.get(line) or ()) if line else ():
        if not isinstance(entry, Mapping):
            continue
        rules = entry.get("rules")
        if rules is not None and not isinstance(rules, (list, tuple, set, frozenset)):
            continue
        if rules is None or not rule_id or rule_id in rules:
            return str(entry.get("reason") or "")
    return None


class ASTExtractionError(AegisError):
    def __init__(self, path: str, reason: str):
        super().__init__(f"cannot verify {path}: {reason}", code="AST_UNVERIFIABLE", path=path, reason=reason)


def is_size_limit_error(exc: BaseException) -> bool:
    """Recognize the typed native size reason through extraction wrappers."""
    from aegis_core.ast.driver_errors import ASTDriverError

    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, ASTDriverError) and getattr(exc, 'reason', None) == 'too_large':
            return True
        exc = exc.__cause__
    return False


def _uncertain_path_matches(target: str, pattern: str, *, prefix: bool = False) -> bool:
    """Unknown segments may expand; known components still rule out incompatible names."""
    target, pattern = canonical_spelling(target), canonical_spelling(pattern)
    if prefix and target.startswith('.') and not pattern.startswith('.'):
        return False
    parts = target.strip('.').split('.')
    wanted = pattern.strip('.').split('.')
    suffix = not prefix and (pattern.startswith('.') or '.' not in pattern)
    if suffix:
        parts.reverse()
        wanted.reverse()
    positions = {0}
    for part in parts:
        if (prefix or suffix) and len(wanted) in positions:
            return True
        if part in ('<expr>', '<computed>'):
            positions = set(range(min(positions), len(wanted) + 1)) if positions else set()
        else:
            positions = {index + 1 for index in positions if index < len(wanted) and wanted[index] == part}
        if not positions:
            return False
    return len(wanted) in positions


def _uncertain_token(value: str) -> bool:
    return '<expr>' in value or '<computed>' in value


def _match_ImportNode_against_pattern(imp: Any, pattern: str) -> bool:
    mod = canonical_spelling(pattern)
    if not mod:
        return False
    src, syms = _extract_import_tuple(imp)
    if src.startswith(".") and not mod.startswith("."):
        return False
    if src and (src == mod or src.startswith(f"{mod}.")):
        return True
    return any(s == mod or s.startswith(f"{mod}.") or (src and (f"{src}.{s}" == mod or f"{src}.{s}".startswith(f"{mod}."))) for s in syms)


def _namespace_alias(imp: Any, source: str, bound: str, original: str, language: str) -> bool:
    marker = imp.get('is_namespace') if isinstance(imp, Mapping) else getattr(imp, 'is_namespace', None)
    if isinstance(marker, bool):
        return marker
    if language in ('javascript', 'typescript'):
        symbols = imp.get('imported_symbols', ()) if isinstance(imp, Mapping) else getattr(imp, 'imported_symbols', ())
        return bound not in {canonical_spelling(str(name)) for name in symbols or ()}
    return original == source


def _eval_call_entry(raw_call: Any, raw_call_sites: Any, call_index: _SpellingIndex, defined_names: set[str], args_known: bool = True) -> Tuple[str, List[Tuple[Any, Optional[bool]]]]:
    if isinstance(raw_call, str):
        call = _normalize_ast_token(raw_call)
        where = None
        builtin_only = False
    elif isinstance(raw_call, Mapping):
        call = _normalize_ast_token(str(raw_call.get("name") or ""))
        where = raw_call.get("where") if isinstance(raw_call.get("where"), Mapping) else None
        builtin_only = bool(raw_call.get("builtin"))
    else:
        return "", []
    if not call:
        return "", []
    origins_by_head = {}
    possible_by_head = {}
    canonical_call = canonical_spelling(call)
    method_pattern = canonical_call.startswith('.') or '.' not in canonical_call
    hits: List[Tuple[Any, Optional[bool]]] = []
    for site in raw_call_sites:
        target = _call_target(site)
        normalized = canonical_spelling(target)
        head, separator, tail = normalized.partition('.')
        if head not in origins_by_head:
            origins = call_index.spellings(head) if call_index.is_bound(head) else [head]
            origins_by_head[head] = origins, [name for name in origins if _uncertain_token(name)]
        origins, unknown_origins = origins_by_head[head]
        raw_unknown = _uncertain_token(normalized)
        uncertain = raw_unknown or bool(unknown_origins)
        candidates = []
        if raw_unknown and method_pattern:
            candidates = [normalized]
        elif raw_unknown:
            if head not in possible_by_head:
                possible_by_head[head] = [name for name in origins
                                          if _uncertain_path_matches(name + '.<expr>', call)]
            candidates = [name + separator + tail for name in possible_by_head[head]]
        elif unknown_origins:
            candidates = [name + separator + tail for name in unknown_origins]
        compatible = call_index.matches(target, call) or any(_uncertain_path_matches(name, call) for name in candidates)
        if not target or not compatible:
            continue
        if builtin_only:
            spelled = call_index.spellings(target)
            shadowed = site.get("shadowed") if isinstance(site, Mapping) else getattr(site, "shadowed", None)
            if not isinstance(shadowed, bool):  # no driver verdict: the legacy file-wide test
                shadowed = call_index.is_bound(call) or call in defined_names
            if not (any(s in (f"builtins.{call}", f"__builtins__.{call}") for s in spelled) or (target == call and not shadowed)):
                continue
        verdict = _match_where(site, where, args_known) if where else True
        if verdict is not False and uncertain and not (
            method_pattern and call_index.matches(target, call)
        ):
            verdict = None
        if verdict is not False:
            hits.append((site, verdict))
    return call, hits


_KIND_LABELS = {"imports": "import", "calls": "call", "decorators": "decorator"}
_SNIPPET_MAX, _SNIPPET_KEEP = 240, 200


def _read_source(fp: str) -> Optional[str]:
    if not fp or not os.path.isfile(fp):
        return None
    try:
        from aegis_core.ast.drivers.python import read_python_source
        return read_python_source(fp) if fp.endswith(".py") else Path(fp).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _snippet(text: str) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= _SNIPPET_MAX:
        return collapsed
    # Minified sources: bounded memory, and the digest keeps the identity of the whole line exact.
    return f"{collapsed[:_SNIPPET_KEEP]}#{hashlib.sha256(collapsed.encode('utf-8', 'surrogatepass')).hexdigest()[:12]}"


def _decorator_hits(normalized_ast: NormalizedAST, forbidden: Any, fp: str, imported_qual_map: Mapping[str, Any], aliases: Mapping[str, Any], bound_origins: Mapping[str, Any]) -> List[str]:
    if not isinstance(forbidden, (list, tuple, set)) or not forbidden:
        return []
    try:
        raw_decs: list[Any] = list(getattr(normalized_ast, "decorators", None) or ())
    except Exception as exc:
        raise ASTExtractionError(str(fp), f"{type(exc).__name__}: {exc}") from exc
    meta = getattr(normalized_ast, "metadata", None)
    if isinstance(meta, dict) and isinstance(meta.get("decorators"), (list, tuple, set)):
        raw_decs.extend(meta["decorators"])
    for defn in getattr(normalized_ast, "definitions", ()) or ():
        d_decs = getattr(defn, "decorators", None) if not isinstance(defn, dict) else defn.get("decorators")
        if isinstance(d_decs, (list, tuple, set)):
            raw_decs.extend(d_decs)
    if not raw_decs and fp.endswith(".py") and os.path.isfile(fp):
        try:
            raw_decs.extend(_extract_python_decorators_from_file(fp))
        except Exception as exc:
            raise ASTExtractionError(fp, f"{type(exc).__name__}: {exc}") from exc
    names = list(dict.fromkeys(n for n in map(_decorator_name, raw_decs) if n))
    index = _SpellingIndex(imported_qual_map, aliases, qualify_heads=False, bound_origins=bound_origins)
    pats = (_decorator_pattern(raw) if isinstance(raw, str) else "" for raw in forbidden)
    return [dec for dec in pats if dec and any(index.matches(name, _decorator_pattern(dec)) for name in names)]


def evaluate_forbid_ast_structured(normalized_ast: NormalizedAST, forbid_spec: dict[str, Any], *, rule_id: Optional[str] = None, source: Optional[str] = None) -> list[dict[str, Any]]:
    """The one forbid_ast evaluator: a finding per matched site, imports then calls then decorators
    (each in spec order, sites by line). A finding is ``{rule, kind, pattern, path, line, snippet,
    unknown, override}``: ``line`` is 0 for a decorator; ``snippet`` is the site's source line with
    whitespace collapsed (``target(arguments)`` when no source exists); ``unknown`` marks a site
    whose ``where`` cannot be decided (advisory); ``override`` is the reason of a ``# aegis: allow``
    on that line naming this rule or none, and such a hit is kept, never dropped.

    ``source`` is the file text (allow comments and snippets); ``""`` means none. Without it the
    tree's own allow comments and the file it names are read, once."""
    if normalized_ast is None or not forbid_spec or not isinstance(forbid_spec, dict):
        return []
    fp = str(getattr(normalized_ast, "file_path", "") or "")
    parsed_imports: list[Any] = []
    imported_qual_map: dict[str, Any] = {}
    aliases: dict[str, Any] = {}
    bound_origins: dict[str, Any] = {}
    for imp in getattr(normalized_ast, "imports", ()) or ():
        src, syms = _extract_import_tuple(imp)
        bindings = _import_aliases(imp)
        member_aliases = []
        namespace_symbols = Counter()
        marker = imp.get('is_namespace') if isinstance(imp, Mapping) else getattr(imp, 'is_namespace', None)
        for name, originals in bindings.items():
            for orig in originals:
                namespace = _namespace_alias(imp, src, name, orig, normalized_ast.language)
                add_binding(bound_origins if src else aliases, name, f"{src}.{orig}" if src and not namespace else orig)
                if not namespace:
                    member_aliases.append(orig)
                elif normalized_ast.language == 'rust':
                    namespace_symbols[orig] += 1
        # A whole-module Rust alias also matches the bare module leaf. This is
        # an alternate import spelling, never a member to append to the source.
        module_leaf = src.rsplit('.', 1)[-1] if normalized_ast.language == 'rust' and any(
            src in originals for originals in bindings.values()) else ''
        import_syms = []
        for sym in () if marker is True else syms:
            if namespace_symbols[sym]:
                namespace_symbols[sym] -= 1
            else:
                import_syms.append(sym)
        parsed_imports.append((imp, (src, tuple(import_syms)), module_leaf))
        # Only actual plain bindings may qualify another reference's head. Aliased
        # originals belong to their own bound name, not a global table of leaf names.
        aliased_symbols = Counter(member_aliases if normalized_ast.language in ('javascript', 'typescript')
                                  else (orig for originals in bindings.values() for orig in originals))
        for sym in syms if src else ():
            if aliased_symbols[sym]:
                aliased_symbols[sym] -= 1
                continue
            if sym and marker is not True and (sym != src or marker is False or normalized_ast.language in ('javascript', 'typescript', 'rust')):
                add_binding(imported_qual_map, sym, f"{src}.{sym}")
    by_line = lambda hit: _line_of(hit[0]) or 0
    hits: List[Tuple[str, str, Any, Optional[bool]]] = []
    for raw_mod in forbid_spec["imports"] if isinstance(forbid_spec.get("imports"), (list, tuple, set)) else ():
        mod = _normalize_ast_token(raw_mod) if isinstance(raw_mod, str) else ""
        if mod:
            matched = sorted(((r, None if _uncertain_token(t[0]) else True) for r, t, leaf in parsed_imports
                              if (_uncertain_path_matches(t[0], mod, prefix=True) if _uncertain_token(t[0])
                                  else _match_ImportNode_against_pattern(t, mod) or mod == leaf)), key=by_line)
            hits.extend(("imports", mod, site, verdict) for site, verdict in matched)
    raw_call_sites = getattr(normalized_ast, "call_sites", ()) or ()
    call_index = _SpellingIndex(imported_qual_map, aliases, qualify_heads=True, bound_origins=bound_origins)
    defined_names = {str(getattr(d, "name", "") if not isinstance(d, Mapping) else d.get("name", "")) for d in (getattr(normalized_ast, "definitions", ()) or ()) if (getattr(d, "kind", "") if not isinstance(d, Mapping) else d.get("kind", "")) in ("function", "class")}
    for raw_call in forbid_spec["calls"] if isinstance(forbid_spec.get("calls"), (list, tuple, set)) else ():
        call, matched = _eval_call_entry(raw_call, raw_call_sites, call_index, defined_names, _driver_extracts_args(normalized_ast))
        hits.extend(("calls", call, site, verdict) for site, verdict in sorted(matched, key=by_line))
    hits.extend(("decorators", dec, None, True) for dec in _decorator_hits(normalized_ast, forbid_spec.get("decorators"), fp, imported_qual_map, aliases, bound_origins))
    if not hits:
        return []
    meta = getattr(normalized_ast, "metadata", None)
    text = source if isinstance(source, str) else _read_source(fp)
    language = str(getattr(normalized_ast, "language", "") or "").lower()
    if language != "python" and isinstance(meta, Mapping) and isinstance(meta.get("allow_comments"), dict):
        allows = meta["allow_comments"]
    elif isinstance(source, str):
        allows = parse_allow_comments(source, language)
    elif isinstance(meta, Mapping) and isinstance(meta.get("allow_comments"), dict):
        allows = meta["allow_comments"]
    else:
        allows = parse_allow_comments(text or "", language)
    # Universal newlines, as the parsers count lines; split once per call, never per finding.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if text else []
    findings: list[dict[str, Any]] = []
    for kind, pattern, site, verdict in hits:
        ln = _line_of(site) if site is not None else None
        if ln is not None and ln <= len(lines):
            snippet = _snippet(lines[ln - 1])
        elif kind == "calls":
            args = _site_args(site)
            snippet = f"{_call_target(site)}({','.join(f'{k}={args[k]}' for k in sorted(args))})"
        else:
            snippet = pattern if kind == "imports" else ""
        findings.append({"rule": rule_id or "", "kind": kind, "pattern": pattern, "path": fp, "line": ln or 0,
                         "snippet": snippet, "unknown": verdict is None,
                         "override": _allow_reason_for_line(allows, ln, rule_id)})
    return findings


def violation_messages(findings: Sequence[Mapping[str, Any]]) -> list[str]:
    """One message per distinct (kind, pattern) among the findings that are neither UNKNOWN nor
    allowed, in finding order: what a forbid_ast check reports."""
    kept = dict.fromkeys((f["kind"], f["pattern"]) for f in findings if not f["unknown"] and f["override"] is None)
    return [f"Forbidden {_KIND_LABELS[kind]} '{pattern}' matched rule forbid_ast.{kind}" for kind, pattern in kept]


def evaluate_forbid_ast(normalized_ast: NormalizedAST, forbid_spec: dict[str, Any]) -> list[str]:
    """Evaluate a NormalizedAST against declarative forbid_ast constraints (syntactic only, no regex).
    Aliased imports are judged as their plain form plus literal alias text; literal strings passed
    to ``__import__`` or ``importlib.import_module`` count as imports. Syntactic only, so out of
    scope: computed module names, ``getattr``/``globals`` and subscript access, ``f = subprocess.run``
    rebinding by assignment, functions as values, ``from x import *``, and relative ``__import__``.
    """
    return violation_messages(evaluate_forbid_ast_structured(normalized_ast, forbid_spec, source=""))


def _new_findings(head: Sequence[Dict[str, Any]], base: Optional[Sequence[Dict[str, Any]]]) -> list[dict[str, Any]]:
    """The confirmed head findings the base does not account for, keyed on (rule, pattern, snippet):
    a key is new when the head holds it more often than the base. The surplus is taken from head
    lines the key does not occupy at base first, then from the last line backwards."""
    confirmed = [f for f in head if not f["unknown"] and f["override"] is None]
    if base is None:
        return confirmed
    key = lambda f: (f["rule"], f["pattern"], f["snippet"])
    at_base = Counter(key(f) for f in base if not f["unknown"] and f["override"] is None)
    base_lines: Dict[Tuple[str, str, str], set] = {}
    for f in base:
        if not f["unknown"] and f["override"] is None:
            base_lines.setdefault(key(f), set()).add(f["line"])
    by_key: Dict[Tuple[str, str, str], List[int]] = {}
    for idx, f in enumerate(confirmed):
        by_key.setdefault(key(f), []).append(idx)
    chosen: set = set()
    for k, idxs in by_key.items():
        surplus = len(idxs) - at_base[k]
        if surplus > 0:
            seen = base_lines.get(k, set())
            fresh = [i for i in idxs if confirmed[i]["line"] not in seen]
            chosen.update((fresh + [i for i in reversed(idxs) if confirmed[i]["line"] in seen])[:surplus])
    return [f for idx, f in enumerate(confirmed) if idx in chosen]


def evaluate_forbid_ast_delta(spec: Any, head_ast: Any, base_ast: Any = None, *, rule_id: Optional[str] = None) -> list[dict[str, Any]]:
    """The findings ``head_ast`` adds over ``base_ast`` (all confirmed head findings without a base)."""
    base = evaluate_forbid_ast_structured(base_ast, spec, rule_id=rule_id) if base_ast is not None else None
    return _new_findings(evaluate_forbid_ast_structured(head_ast, spec, rule_id=rule_id), base)


def extract_normalized_ast(file_path: Union[str, Path], workspace_root: Optional[Union[str, Path]] = None, code: Optional[str] = None, ast_runner: Any = None, confine_root: Optional[Union[str, Path]] = None) -> Optional[NormalizedAST]:
    from aegis_core.ast.drivers.python import parse_python_ast, read_python_source
    path_str = str(file_path)
    ext = os.path.splitext(path_str)[1].lower()
    try:
        if code is not None and ext in ('.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.rs'):
            if ext == '.rs':
                from aegis_core.ast.drivers.rust import parse
            else:
                from aegis_core.ast.drivers.js import parse

            return parse(code, path_str)
        if code is not None and ext != ".py":
            raise ASTExtractionError(path_str, f"source parsing unsupported for extension '{ext}' until a native source parser is available")
        if ext == ".py":
            source_text = code if code is not None else read_python_source(path_str)
            tree = ast.parse(source_text, filename=path_str)
            norm_ast = parse_python_ast(source_text, file_path=path_str)
            decs = _extract_python_decorators_from_tree(tree)
            allows = {
                line: [{**entry, "rules": sorted(entry["rules"]) if entry["rules"] is not None else None}
                       for entry in entries]
                for line, entries in parse_allow_comments(source_text).items()
            }
            if decs or allows:
                meta = {**norm_ast.metadata, **({"decorators": list(decs)} if decs else {}), **({"allow_comments": allows} if allows else {})}
                object.__setattr__(norm_ast, "metadata", meta)
            return norm_ast
        if ast_runner is None:
            from aegis_core.ast.runner import ASTDriverRunner
            ast_runner = ASTDriverRunner()
        resolve = getattr(ast_runner, "resolve_driver", ast_runner.registry.resolve_driver)
        if not resolve(ext, workspace_root=workspace_root):
            return None
        return ast_runner.parse_file(path_str, workspace_root=workspace_root, **({"confine_root": confine_root} if confine_root is not None else {}))
    except Exception as exc:
        raise ASTExtractionError(path_str, f"{type(exc).__name__}: {exc}") from exc
