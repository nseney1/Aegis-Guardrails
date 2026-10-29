"""Layer 1 Runner — orchestrates all deterministic verification tools.

Runs mandatory checks on changed files and produces a combined evidence package.
The output feeds directly into the Arbiter as Layer 1 evidence.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import posixpath
import re
from aegis_core.match import first_match, is_test_path
from aegis_core.primitives import is_within, safe_parts
from aegis_core.workspace.layout import RULES_RELDIR
from typing import Any, Optional

from . import ToolEvidence
from . import persistence_checker
from . import call_graph
from . import import_guard
from . import mutation_tester

VerificationResult = ToolEvidence


_FORBID_AST_KEYS = ("imports", "calls", "decorators")
_CALL_SPEC_KEYS = frozenset({"name", "where", "builtin"})
_SCALARS = (str, int, float, bool, type(None))


def _condition_error(cond: object) -> Optional[str]:
    """Why a where condition is outside the spec grammar: a scalar, {in: [scalars]}, {not: condition}, {absent: bool}."""
    while isinstance(cond, dict) and list(cond) == ["not"]:
        cond = cond["not"]
    if isinstance(cond, _SCALARS):
        return None
    op, target = next(iter(cond.items())) if isinstance(cond, dict) and len(cond) == 1 else (None, None)
    if op == "in":
        ok = isinstance(target, (list, tuple)) and bool(target) and all(isinstance(t, _SCALARS) for t in target)
        return None if ok else "in needs a non-empty list of scalars"
    if op == "absent":
        return None if isinstance(target, bool) else "absent needs true or false"
    return f"unknown operator {op} (allowed: in, not, absent)" if op is not None else "a condition is a scalar or one operator: in, not, absent"


def _call_spec_error(at: str, entry: dict) -> Optional[str]:
    extra = sorted(str(key) for key in entry if key not in _CALL_SPEC_KEYS)
    if extra:
        return f"{at}: unknown key {extra[0]!r} (allowed: {', '.join(sorted(_CALL_SPEC_KEYS))})"
    if not (isinstance(entry.get("name"), str) and entry["name"].strip()) or not isinstance(entry.get("builtin", False), bool):
        return f"{at}: name must be a non-empty string and builtin true or false"
    where = entry.get("where")
    if "where" in entry and (not isinstance(where, dict) or not where):
        return f"{at}.where must map argument names to conditions"
    for arg, cond in (where or {}).items():
        named = isinstance(arg, str) and all(n.strip().isidentifier() or re.fullmatch(r"\s*#[0-9]+\s*", n) for n in arg.split("|"))
        reason = _condition_error(cond) if named else "argument names are identifiers or #N, joined by |"
        if reason:
            return f"{at}.where.{arg}: {reason}"
    return None


def _forbid_ast_spec_error(spec: object) -> Optional[str]:
    """Why a declared ``forbid_ast`` would enforce nothing as written; None when it is well-formed.

    evaluate_forbid_ast ignores what it cannot use (a list, a string where a list belongs,
    a misspelt key, an operator outside the where grammar), so a gate rule in such a shape
    would pass every file.
    """
    if not isinstance(spec, dict):
        return f"forbid_ast must map imports/calls/decorators to lists, not {type(spec).__name__}"
    unknown = sorted(str(key) for key in spec if key not in _FORBID_AST_KEYS)
    if unknown:
        listed = ", ".join(repr(key) for key in unknown)
        return f"unknown forbid_ast key {listed} (allowed: {', '.join(_FORBID_AST_KEYS)})"
    patterns = 0
    for key, value in spec.items():
        mapped = (lambda p: key == "calls" and isinstance(p, dict))
        if not isinstance(value, list) or not all(mapped(p) or (isinstance(p, str) and p.strip()) for p in value):
            return f"forbid_ast.{key} must be a list of non-empty strings, not {type(value).__name__}"
        errors = (_call_spec_error(f"forbid_ast.calls[{i}]", p) for i, p in enumerate(value) if mapped(p))
        error = next((e for e in errors if e), None)
        if error:
            return error
        patterns += len(value)
    return None if patterns else "forbid_ast declares no patterns"


def _base_holds(root: str, commit: str) -> bool:
    """Whether the reviewed base ``commit`` holds the directory ``root`` at all. git answers for the
    nearest enclosing work tree, which for a directory it does not track (a project inside a $HOME
    repository, a snapshot under a temp dir there) is another project whose base has no rules here."""
    from aegis_core import gitsafe, rule_integrity

    try:
        prefix = gitsafe.show_prefix(root).rstrip("/")
        if not prefix:
            return True
        res = gitsafe.run(["cat-file", "-t", f"{commit}:{prefix}"], root)
    except gitsafe.GitError as exc:
        raise rule_integrity.IntegrityError(str(exc)) from exc
    return res.returncode == 0 and res.stdout.strip() == b"tree"


def _discover_forbid_ast_rules(
    repo_root: str,
    reviewed: bool = True,
) -> tuple[list[tuple[Any, dict]], list[tuple[str, str]]]:
    """The workspace rules (aegis_core.rules, .aegis/rules/<type>/) that declare forbid_ast, as
    enforced: the reviewed BASE versions (aegis_core.rule_integrity.effective), so a branch can
    neither weaken a gate nor gate on a rule nobody reviewed; outside git, or when the base does
    not hold ``repo_root`` at all, the working tree. ``reviewed=False`` enforces the working tree
    as is: ``aegis check --record`` runs on an exported snapshot, which no base describes.

    Returns (rules, broken): a rule file that cannot be loaded and names forbid_ast, or
    whose forbid_ast is malformed, would enforce nothing, so each is returned as
    (relative path, reason) for the caller to fail closed on instead of being dropped.
    ``broken`` reads the working tree too, so a malformed new gate fails before it is merged.
    An unsafe rules tree or an unreadable BASE raises, which the caller also fails on.
    """
    from aegis_core import rule_integrity
    from aegis_core.rules import RuleCache, workspace_root

    root = workspace_root(repo_root)
    cache = RuleCache()
    try:
        if reviewed:
            served = rule_integrity.effective(root, cache)
            untracked = served.anchor is not None and not _base_holds(root, served.anchor.commit)
            enforced = cache.get(root) if untracked else served.ruleset
        else:
            enforced = cache.get(root)
    except rule_integrity.IntegrityError as exc:
        raise rule_integrity.IntegrityError(
            f"the reviewed (base) version of the rules cannot be read, so none is enforced: {exc}") from exc
    discovered: list[tuple[Any, dict]] = []
    broken: list[tuple[str, str]] = []
    for ruleset, collect in ((cache.get(root), False), (enforced, True)):
        for rule in ruleset.rules:
            if not rule.ok:
                # Only a file that names the key can declare it: a damaged note does not gate.
                if b"forbid_ast" in rule.raw and not collect:
                    broken.append((rule.path, rule.error or "cannot be loaded"))
                continue
            if rule.expired or "forbid_ast" not in rule.meta:
                continue
            spec = rule.meta.get("forbid_ast")
            spec_error = _forbid_ast_spec_error(spec)
            if spec_error:
                if (rule.path, spec_error) not in broken:
                    broken.append((rule.path, spec_error))
            elif collect:
                discovered.append((rule, spec))
    return discovered, broken


# The tests/ directory that holds each package's tests, most specific first.
_TEST_HOMES = (
    ("aegis_core/verification/", "unit/verification"),
    ("aegis_core/", "unit/core"),
    ("aegis_cli/", "unit/cli"),
    ("aegis_mcp/", "unit/mcp"),
    ("aegis_sdk/", "unit/sdk"),
)


def _find_test_file(filepath: str, repo_root: str) -> Optional[str]:
    """Find the test file for a source file by convention.

    Searches in tests/ directory using canonical prefix and subdirectory conventions:
      1. tests/test_<stem>.py
      2. tests/test_<clean_parent>_<stem>.py (e.g. tests/test_cli_checkpoint.py)
      3. tests/test_<parent>_<stem>.py
      4. tests/<clean_parent>/test_<stem>.py
      5. tests/test_<clean_parent>/test_<stem>.py
      6. Domain mappings (e.g. runner.py -> test_verification/test_layer1.py)
    Each name is tried in the source package's own test directory (_TEST_HOMES)
    before anywhere else.
    """
    relative = os.path.relpath(filepath, repo_root) if os.path.isabs(filepath) else filepath
    norm = posixpath.normpath(relative.replace("\\", "/"))
    aegis_package = norm.split("/", 1)[0] in {"aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk"}
    def _find_in_tests(*names: str) -> Optional[str]:
        for name in names:
            for prefix in ("", "unit/mcp", "unit/core", "unit/cli", "unit/verification", "unit/sdk", "integration"):
                p = os.path.join(repo_root, "tests", prefix, name) if prefix else os.path.join(repo_root, "tests", name)
                if os.path.isfile(p):
                    return p
        return None

    if aegis_package and norm.startswith("aegis_mcp/handlers/"):
        found = _find_in_tests("test_mcp_handlers.py")
        if found:
            return found
    if aegis_package and norm == "aegis_core/outcomes/telemetry.py":
        found = _find_in_tests("test_outcomes_telemetry.py")
        if found:
            return found
    if aegis_package and norm == "aegis_core/outcomes/engine.py":
        found = _find_in_tests("test_outcome_engine.py")
        if found:
            return found
    if aegis_package and norm == "aegis_core/skills/slots.py":
        found = _find_in_tests("test_slots.py")
        if found:
            return found
    if aegis_package and norm.startswith("aegis_core/skills/"):
        found = _find_in_tests("test_skills.py")
        if found:
            return found

    stem = posixpath.splitext(posixpath.basename(norm))[0]
    test_name = f"test_{stem}.py"
    parent = posixpath.basename(posixpath.dirname(norm))
    clean_parent = parent[6:] if aegis_package and parent.startswith("aegis_") else parent

    candidates = [
        test_name,
        f"test_{clean_parent}_{stem}.py",
        f"test_{parent}_{stem}.py",
        os.path.join(clean_parent, test_name),
        os.path.join(parent, test_name),
        os.path.join(f"test_{clean_parent}", test_name),
    ]

    # Domain specific mapping
    if aegis_package and stem == "runner" and clean_parent == "verification":
        found = _find_in_tests("test_layer1.py", "test_verification/test_layer1.py")
        if found:
            return found

    # A same-named test of another package (tests/unit/core/test_scan.py for
    # aegis_cli/scan.py) must not win over the source package's own tests.
    home = next((d for pkg, d in _TEST_HOMES if aegis_package and norm.startswith(pkg)), None)
    if home:
        for cand_name in candidates:
            p = os.path.join(repo_root, "tests", home, cand_name)
            if os.path.isfile(p):
                return p

    for cand_name in candidates:
        found = _find_in_tests(cand_name)
        if found:
            return found

    return None


def _module_names(filepath: str, repo_root: str) -> set[str]:
    """The dotted names a test can import ``filepath`` by: its package path and its path from the root."""
    full = os.path.abspath(os.path.join(repo_root, filepath))
    stem = os.path.splitext(os.path.basename(full))[0]
    parts = [stem]
    parent = os.path.dirname(full)
    while os.path.isfile(os.path.join(parent, "__init__.py")):
        parts.insert(0, os.path.basename(parent))
        parent = os.path.dirname(parent)
    names = {".".join(parts)}
    try:
        names.add(".".join(Path(os.path.relpath(os.path.splitext(full)[0], repo_root)).parts))
    except ValueError:  # another drive on Windows
        pass
    return names


def _imports_module(tree: ast.AST, names: set[str]) -> bool:
    """Whether a module imports one of ``names``: ``import a.b``, ``from a.b import x`` or ``from a import b``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name in names for alias in node.names):
                return True
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            if node.module in names or any(f"{node.module}.{alias.name}" in names for alias in node.names):
                return True
    return False


class _TestModules:
    """The test modules under ``tests/``, in path order, each read and parsed at most once per run."""

    def __init__(self, repo_root: str):
        base = os.path.join(repo_root, "tests")
        found: list[str] = []
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d != "__pycache__" and not d.startswith(".")]
            for name in filenames:
                stem, ext = os.path.splitext(name)
                if ext == ".py" and (stem.startswith("test_") or stem.endswith("_test")):
                    found.append(os.path.join(dirpath, name))
        self.paths = sorted(found, key=lambda path: Path(os.path.relpath(path, base)).as_posix())
        self._text: dict[str, str] = {}
        self._tree: dict[str, Optional[ast.AST]] = {}

    def text(self, path: str) -> str:
        if path not in self._text:
            try:
                self._text[path] = Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._text[path] = ""
        return self._text[path]

    def tree(self, path: str) -> Optional[ast.AST]:
        if path not in self._tree:
            try:
                self._tree[path] = ast.parse(self.text(path))
            except (SyntaxError, ValueError, RecursionError):
                self._tree[path] = None
        return self._tree[path]


def _find_mutation_test_files(filepath: str, repo_root: str, func_name: str, tests: _TestModules) -> list[str]:
    """The test files that face mutants of ``func_name`` in ``filepath``.

    The convention file (``_find_test_file``) first, then, in path order, every test
    module under ``tests/`` that imports the module and names the function (a method or
    nested function by its own name: ``Class.method`` is called as ``obj.method``). A
    mutant that survives them has met every test that could plausibly detect it, not just
    the one conventionally named file. mutation_tester caps how many run.
    """
    convention = _find_test_file(filepath, repo_root)
    names = _module_names(filepath, repo_root)
    tails = {name.rpartition(".")[2] for name in names}
    mentions = re.compile(rf"\b{re.escape(func_name.rpartition('.')[2])}\b")
    ordered = [convention] if convention else []
    convention_key = os.path.normcase(os.path.abspath(convention)) if convention else None
    for path in tests.paths:
        text = tests.text(path)
        if not mentions.search(text) or not any(tail in text for tail in tails):
            continue
        tree = tests.tree(path)
        if (tree is not None and os.path.normcase(os.path.abspath(path)) != convention_key
                and _imports_module(tree, names)):
            ordered.append(path)
    return ordered


def _discover_functions(filepath: str, target_lines: Optional[set[int]] = None) -> list[str]:
    """The public functions of a Python file, by the qualified name mutation_tester resolves.

    A method is ``Class.method`` and a nested function ``outer.inner``; each name is listed
    once, outer scopes first (breadth first), even when it is defined twice (a platform
    branch). Unqualified, every method was mutated as the first definition in the file with
    its name. With target_lines, only the functions intersecting them.
    """
    from aegis_core.ast.drivers.python import read_python_source

    try:
        tree = ast.parse(read_python_source(filepath))
    except (SyntaxError, OSError, UnicodeError, ValueError):
        return []
    found: dict[str, None] = {}
    todo: list[tuple[ast.AST, str]] = [(tree, "")]
    for node, scope in todo:  # grows while iterated: a breadth-first walk, as ast.walk
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = f"{scope}{child.name}."
                if (
                    isinstance(child, ast.FunctionDef)
                    and not child.name.startswith(("_", "test_"))
                    and (target_lines is None
                         or not target_lines.isdisjoint(range(child.lineno, (child.end_lineno or child.lineno) + 1)))
                ):
                    found.setdefault(inner[:-1], None)
            todo.append((child, inner))
    return list(found)


def _diff_base_candidates(repo_root: str, diff_base: Optional[str] = None) -> list[str]:
    """The commits a changed file is compared with, in order and each once: ``diff_base`` (``REF...HEAD``
    means its merge base with HEAD), HEAD, the merge base with the pull request's base branch, HEAD~1."""
    from aegis_core import gitsafe

    bases: list[Optional[str]] = []
    if diff_base:
        if diff_base.endswith("...HEAD"):
            bases.append(gitsafe.merge_base(repo_root, diff_base[: -len("...HEAD")]))
        else:
            bases.append(gitsafe.resolve_commit(repo_root, diff_base))
    bases.append(gitsafe.head_commit(repo_root))
    pr_base = gitsafe.resolve_base_ref(repo_root)
    if pr_base:
        bases.append(gitsafe.merge_base(repo_root, pr_base))
    bases.append(gitsafe.resolve_commit(repo_root, "HEAD~1"))
    return list(dict.fromkeys(base for base in bases if base))


def _get_modified_lines(filepath: str, repo_root: str, diff_base: Optional[str] = None) -> Optional[set[int]]:
    """1-based lines of ``filepath``'s working copy that are new or changed against a base.

    Bases, in order: ``diff_base`` (``REF...HEAD`` means its merge base with HEAD), HEAD,
    the merge base with the pull request's base branch, then HEAD~1. The first base the
    file differs from wins. Returns None when no base shows a change or git cannot answer.
    Old contents come from ``gitsafe.read_blob``; the comparison is done here, so no
    porcelain diff (and no repository fsmonitor or diff driver) is involved.
    """
    import difflib

    from aegis_core import gitsafe

    try:
        current = (Path(repo_root) / filepath).read_bytes().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    rel = Path(os.path.relpath(Path(repo_root) / filepath, repo_root)).as_posix()

    for base in _diff_base_candidates(repo_root, diff_base):
        try:
            old = gitsafe.read_blob(repo_root, base, rel)
        except gitsafe.GitError:
            return None
        before = old.decode("utf-8", "replace").splitlines() if old is not None else []
        lines: set[int] = set()
        matcher = difflib.SequenceMatcher(None, before, current, autojunk=False)
        for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
            if tag in ("replace", "insert"):
                lines.update(range(j1 + 1, j2 + 1))
        if lines:
            return lines
    return None


def _tool_failure(tool: str, target: str, exc: Exception) -> ToolEvidence:
    """A Layer 1 tool that raised fails the gate; it must never abort the run or pass silently."""
    return ToolEvidence(
        tool=tool,
        target=target,
        verdict=False,
        detail=f"{tool}: cannot verify {target}: {type(exc).__name__}: {exc}",
    )


def _forbid_evidence(root: str, rule_id: str, rel: str, findings: list[dict[str, Any]]) -> list[ToolEvidence]:
    """The evidence of one evaluation of ``rule_id`` on ``rel``: a failing row naming each violated
    pattern and its lines. Each allowed hit is recorded once as a contested override."""
    from aegis_core import credit
    from aegis_core.ast.policy import violation_messages

    for finding in findings:
        if not finding["unknown"] and finding["override"] is not None:
            try:
                credit.record_override(root, rule_id, rel, finding["line"], reason=finding["override"])
            except Exception:
                pass
    out: list[ToolEvidence] = []
    violations = violation_messages(findings)
    if violations:
        # The sites that produced the messages: an allowed site is a contested override, never a line.
        lines = sorted({f["line"] for f in findings if not f["unknown"] and f["override"] is None and f["line"] > 0})
        out.append(ToolEvidence(tool=f"forbid_ast:{rule_id}", target=rel, verdict=False, detail="; ".join(violations),
                                lines=lines))
    unknown = [f for f in findings if f["unknown"] and f["override"] is None]
    if unknown:
        out.append(_unverified_note(rule_id, rel, unknown))
    return out


def _unverified_note(rule_id: str, rel: str, unknown: list[dict[str, Any]]) -> ToolEvidence:
    """Passing evidence that names the sites a rule could not decide: advisory, never silent (spec T7)."""
    shown = "; ".join(f"line {f['line']}: {f['snippet']}" for f in unknown[:_UNVERIFIED_SHOWN])
    more = f"; and {len(unknown) - _UNVERIFIED_SHOWN} more" if len(unknown) > _UNVERIFIED_SHOWN else ""
    return ToolEvidence(
        tool=UNVERIFIED_NOTE_TOOL, target=rel, verdict=True, lines=sorted({f["line"] for f in unknown}),
        detail=(f"forbid_ast:{rule_id}: {len(unknown)} site(s) in {rel} could not be decided, so they are reported, "
                f"not failed (unknown: advisory): {shown}{more}"),
    )


def _forbid_or_failure(root: str, rule_id: str, rel: str, findings: list[dict[str, Any]]) -> list[ToolEvidence]:
    try:
        return _forbid_evidence(root, rule_id, rel, findings)
    except Exception as exc:
        return [_tool_failure(f"forbid_ast:{rule_id}", rel, exc)]


def _exempt_notes(forbid_rules: list[tuple[Any, dict]], paths: list[str]) -> list[ToolEvidence]:
    """One passing note per rule that skipped test files only because its target_paths do not
    name tests. Rule.applies_to tests the exemption first, so it is spelled out here."""
    notes = []
    for rule, _spec in forbid_rules:
        skipped = {p for p in paths if rule.skips_tests and is_test_path(p) and first_match(rule.target_paths, p) is not None}
        if skipped:
            notes.append(ToolEvidence(
                tool=EXEMPT_NOTE_TOOL, target=rule.path, verdict=True,
                detail=f"forbid_ast:{rule.id}: {len(skipped)} test file(s) not checked (target_paths do not name tests)",
            ))
    return notes


def run_layer1(
    changed_files: list[str],
    repo_root: str,
    persistence_targets: Optional[list[tuple[str, str]]] = None,
    mutation_targets: Optional[list[tuple[str, str, str]]] = None,
    max_mutations: int = 5,
    fast_mode: bool = False,
    diff_base: Optional[str] = None,
    reviewed: bool = True,
    git_root: Optional[str] = None,
) -> list[ToolEvidence]:
    """Run all Layer 1 verification tools. ``git_root`` is where the history lives when ``repo_root``
    is an export of a tree (``check --record``): the T7 delta reads its base text there.

    Args:
        changed_files: List of file paths that were modified
        repo_root: Root of the repository
        persistence_targets: List of (filepath, dict_name) tuples for
            persistence checking. If None, auto-detects from changed_files.
        mutation_targets: List of (source_file, func_name, test_file) tuples.
            If None, auto-discovers the changed functions of changed_files and,
            for each, the test files that exercise it (_find_mutation_test_files).
        max_mutations: Maximum mutations per function (default: 5).
        reviewed: Enforce the reviewed BASE gate rules (default); False enforces the
            working-tree rules of ``repo_root``, for a snapshot no base describes.

    Returns:
        List of ToolEvidence results for the Arbiter
    """
    results: list[ToolEvidence] = []
    repo_root_str = str(getattr(repo_root, "root", repo_root))

    def _is_test_or_support(fpath: str) -> bool:
        return is_test_path(fpath) or os.path.basename(fpath) == '__init__.py'

    # ── Persistence Completeness ──────────────────────────────────────
    if persistence_targets:
        for filepath, dict_name in persistence_targets:
            full_path = os.path.join(repo_root_str, filepath)
            if os.path.exists(full_path):
                results.append(persistence_checker.check(full_path, dict_name))

    # ── Call Graph Completeness ───────────────────────────────────────
    from aegis_core.ast.runner import ASTDriverRunner
    ast_runner = ASTDriverRunner()

    for filepath in changed_files:
        full_path = os.path.join(repo_root_str, filepath)
        if not os.path.exists(full_path):
            continue
        if _is_test_or_support(filepath):
            continue
        ext = os.path.splitext(filepath)[1].lower()
        try:
            if ext == ".py":
                results.append(call_graph.check(
                    full_path, repo_root_str,
                    exclude_names={'main', '_parse_args', 'parse_args'},
                    fast_mode=fast_mode,
                ))
            elif ast_runner.registry.resolve_driver(ext, workspace_root=repo_root_str):
                results.append(call_graph.check(
                    full_path, repo_root_str,
                    exclude_names={'main', '_parse_args', 'parse_args'},
                    fast_mode=fast_mode,
                    ast_runner=ast_runner,
                ))
        except Exception as exc:
            results.append(_tool_failure("call_graph", filepath, exc))

    # ── Import Guards ─────────────────────────────────────────────────
    for filepath in changed_files:
        full_path = os.path.join(repo_root_str, filepath)
        if os.path.exists(full_path) and filepath.endswith('.py'):
            if _is_test_or_support(filepath):
                continue
            try:
                results.append(import_guard.check(full_path, project_root=repo_root_str))
            except Exception as exc:
                results.append(_tool_failure("import_guard", filepath, exc))

    # ── Declarative Rule-Level forbid_ast ─────────────────────────────
    from aegis_core.ast.policy import ASTExtractionError, evaluate_forbid_ast_structured, extract_normalized_ast

    try:
        # The default keeps the one-argument call that stand-ins for the discovery replace.
        forbid_rules, broken_rules = _discover_forbid_ast_rules(*((repo_root_str,) if reviewed else (repo_root_str, False)))
    except Exception as exc:
        # The rules are gate rules: if they cannot be read, nothing may pass unchecked.
        forbid_rules = []
        broken_rules = []
        results.append(ToolEvidence(
            tool="forbid_ast",
            target=RULES_RELDIR,
            verdict=False,
            detail=f"forbid_ast: cannot load rules: {type(exc).__name__}: {exc}",
        ))
    for rule_path, reason in broken_rules:
        results.append(ToolEvidence(
            tool="forbid_ast",
            target=rule_path,
            verdict=False,
            detail=f"forbid_ast: cannot load rule {rule_path}: {reason}",
        ))
    owned: set[tuple[str, int, str]] = set()  # (file, line, pattern) a user forbid_ast rule judged
    if forbid_rules:
        ast_cache: dict[str, object] = {}
        checked_paths: list[str] = []
        for filepath in changed_files:
            full_path = filepath if os.path.isabs(filepath) else os.path.join(repo_root_str, filepath)
            if not os.path.isfile(full_path):
                continue
            try:
                rel_path = os.path.relpath(full_path, repo_root_str).replace("\\", "/")
            except ValueError:
                rel_path = filepath.replace("\\", "/")
            checked_paths.append(rel_path)
            for rule, forbid_spec in forbid_rules:
                rule_id = rule.id
                # Rule.applies_to: target_paths ("**" when a forbid_ast rule names none),
                # and test files only when the patterns name tests. Scan, telemetry and
                # coverage ask the same question.
                if not rule.applies_to(rel_path):
                    continue

                try:
                    if full_path not in ast_cache:
                        try:
                            ast_cache[full_path] = extract_normalized_ast(
                                full_path, workspace_root=repo_root_str, ast_runner=ast_runner
                            )
                        except ASTExtractionError as exc:
                            ast_cache[full_path] = exc
                    norm_ast = ast_cache[full_path]
                    if norm_ast is None:  # no AST driver for this file type: rule does not apply
                        continue
                    findings: list[dict[str, Any]] = []
                    if not isinstance(norm_ast, ASTExtractionError):
                        try:
                            findings = evaluate_forbid_ast_structured(norm_ast, forbid_spec, rule_id=rule_id)
                            owned.update((rel_path, f["line"], f["pattern"]) for f in findings if not f["unknown"])
                        except ASTExtractionError as exc:  # decorators had to be re-read from disk
                            norm_ast = exc
                except Exception as exc:
                    results.append(_tool_failure(f"forbid_ast:{rule_id}", rel_path, exc))
                    continue
                if isinstance(norm_ast, ASTExtractionError):
                    # Fail closed: a gate rule that cannot read the file must not pass it.
                    results.append(
                        VerificationResult(
                            tool=f"forbid_ast:{rule_id}",
                            target=rel_path,
                            verdict=False,
                            detail=f"forbid_ast: cannot verify {rel_path}: {norm_ast.reason}",
                        )
                    )
                    continue
                results.extend(_forbid_or_failure(repo_root_str, rule_id, rel_path, findings))
        try:
            results.extend(_exempt_notes(forbid_rules, checked_paths))
        except Exception as exc:
            results.append(_tool_failure("forbid_ast", RULES_RELDIR, exc))

    # ── T7: the security pack and the secret scan, on what the change introduces ──
    t7_rels = []
    for filepath in changed_files:
        full_path = filepath if os.path.isabs(filepath) else os.path.join(repo_root_str, filepath)
        if os.path.isfile(full_path):
            t7_rels.append(os.path.relpath(full_path, repo_root_str).replace("\\", "/"))
    if t7_rels:
        results.extend(_t7_evidence(git_root or repo_root_str, t7_rels, repo_root_str, diff_base, owned))

    # ── Mutation Testing ───────────────────────────────────────────────
    if not fast_mode:
        if mutation_targets:
            for source, func, test in mutation_targets:
                src_path = os.path.join(repo_root_str, source)
                tst_path = os.path.join(repo_root_str, test)
                if os.path.exists(src_path) and os.path.exists(tst_path):
                    results.append(mutation_tester.check(
                        src_path, func, tst_path, max_mutations=max_mutations,
                    ))
        else:
            # Auto-discover: for each changed .py file, its changed functions and the
            # test files that exercise each of them.
            test_modules: Optional[_TestModules] = None
            for filepath in changed_files:
                if not filepath.endswith('.py') or _is_test_or_support(filepath):
                    continue
                full_path = os.path.join(repo_root_str, filepath)
                if not os.path.exists(full_path):
                    continue
                mod_lines = _get_modified_lines(filepath, repo_root_str, diff_base=diff_base)
                funcs = _discover_functions(full_path, target_lines=mod_lines)
                for func_name in funcs[:3]:  # Limit auto-discovery to 3 functions
                    if test_modules is None:
                        test_modules = _TestModules(repo_root_str)
                    test_files = _find_mutation_test_files(filepath, repo_root_str, func_name, test_modules)
                    if not test_files:
                        continue
                    results.append(mutation_tester.check(
                        full_path, func_name, test_files,
                        max_mutations=max_mutations,
                        target_lines=mod_lines,
                    ))

    return results


def _blob_ids(data: bytes, oid_length: int) -> set[str]:
    """The ids ``data`` has as a blob, line endings aside: with core.autocrlf (Git for Windows'
    default) a checkout holds CRLF where the commit holds LF, and both scans read lines either way."""
    from aegis_core import gitsafe

    ids = {gitsafe.blob_id(data, oid_length)}
    if b"\r\n" in data:
        ids.add(gitsafe.blob_id(data.replace(b"\r\n", b"\n"), oid_length))
    return ids


def _renamed_from(data: bytes, base_tree: dict[str, tuple[str, str]], prefix: str, present: Any,
                  taken: set[str]) -> Optional[str]:
    """The blob id of ``data`` when ``base_tree`` holds it at a path the change removed and no other
    file was renamed from (``taken``, which gains it): an exact rename, judged against its old text.
    A path still ``present`` makes it a copy, and a copied hit is new (as is the second of two copies
    of one removed file)."""
    from aegis_core import gitsafe

    if not base_tree:
        return None
    ids = _blob_ids(data, len(next(iter(base_tree.values()))[1]))
    for path, (_mode, oid) in base_tree.items():
        if oid in ids and path not in taken:
            old = gitsafe.relative_to_prefix(prefix, path)
            if old is not None and not present(old):
                taken.add(path)
                return oid
    return None


def _base_sources(git_root: str, rels: list[str], work_root: str, diff_base: Optional[str],
                  contents: Optional[dict[str, bytes]] = None, present: Any = None) -> dict[str, bytes]:
    """What the T7 delta subtracts for each of ``rels`` (relative to ``work_root``, which holds
    ``git_root``'s workspace or an export of it; ``contents`` holds the bytes of those read already):
    walking the diff-base candidates in order, the bytes at the first one whose content differs from
    the work file. A file one of them does not hold is new against it and has no entry (judged
    whole) unless it is an exact rename of a path the change removed (``present``: whether a path
    relative to ``work_root`` is still in the checked tree; by default, on disk there). One equal at
    every candidate keeps those bytes. Object ids are compared, so only the blobs kept are read; a
    binary file (NUL in its first 4 KiB, which neither scan reads) needs none. Raises GitError."""
    from aegis_core import gitsafe

    bases = _diff_base_candidates(git_root, diff_base)
    if not bases:
        return {}
    prefix = gitsafe.show_prefix(git_root)
    current: dict[str, bytes] = {}
    for rel in rels:
        if contents is not None and rel in contents:
            data = contents[rel]
        else:
            try:
                data = (Path(work_root) / rel).read_bytes()
            except OSError:
                continue
        if b"\0" not in data[:4096]:
            current[rel] = data
    if present is None:
        present = lambda rel: os.path.lexists(os.path.join(work_root, *rel.split("/")))  # noqa: E731
    kept: dict[str, str] = {}
    pending = sorted(current)
    for base in bases:
        if not pending:
            break
        # A long path list would overflow a command line: past 64 files the whole tree is listed.
        whole = len(pending) > 64
        listed = gitsafe.tree_blobs(git_root, base, paths=() if whole else [prefix + r for r in pending])
        tree: Optional[dict[str, tuple[str, str]]] = listed if whole else None
        taken: set[str] = set()
        unchanged = []
        for rel in pending:
            entry = listed.get(prefix + rel)
            oid = entry[1] if entry is not None else None
            if oid is None:
                tree = gitsafe.tree_blobs(git_root, base) if tree is None else tree
                oid = _renamed_from(current[rel], tree, prefix, present, taken)
            if oid is None:
                kept.pop(rel, None)
                continue
            kept[rel] = oid
            if oid in _blob_ids(current[rel], len(oid)):
                unchanged.append(rel)  # the same here: what changed it, if anything, is further back
        pending = unchanged
    blobs = gitsafe.read_blobs(git_root, kept.values())
    return {rel: blobs[oid] for rel, oid in kept.items()}


def _t7_evidence(git_root: str, rels: list[str], work_root: str, diff_base: Optional[str],
                 owned: set[tuple[str, int, str]], contents: Optional[dict[str, bytes]] = None,
                 present: Any = None) -> list[ToolEvidence]:
    """T7 on ``rels``: the Python security pack and the Tier A secret scan, each against the file's
    text before the change, so only what it introduces fails (spec T7, D-delta: user forbid_ast rules
    keep whole-file judgment). Test-path hits and undecidable sites are reported on a passing row; an
    ``# aegis: allow`` hit passes unrecorded (no credit for pack rows); an unreadable file and any
    failure to run fail closed. A call a user forbid_ast rule judged at a site, failed or allowed (the
    seeded no-eval rule's eval), is that rule's: the pack neither reports it twice nor second-guesses
    its allow. Another call on the same line (``pickle.loads(eval(s))``) stays the pack's.
    ``contents`` holds the bytes of files not on disk under ``work_root`` (non-Python only), and
    ``present`` says which paths the checked tree holds (_base_sources)."""
    from aegis_core.verification import scanners, security_pack

    try:
        base_sources = _base_sources(git_root, rels, work_root, diff_base, contents, present)
        py = [rel for rel in rels if rel.endswith(".py")]
        pack = security_pack.evaluate_security_pack(work_root, py, base_sources) if py else {}
        secrets = scanners.scan_secrets_delta(work_root, rels, {p: b.decode("utf-8", "replace") for p, b in base_sources.items()}, contents)
    except Exception as exc:
        return [_tool_failure("security_pack", "changed files", exc)]
    hits: dict[tuple[str, str], list[dict[str, Any]]] = {}
    notes: dict[str, list[str]] = {}
    for hit in pack.get("violations", ()):
        if (hit["file"], hit["line"], hit["pattern"]) not in owned:
            hits.setdefault((f"security_pack:{hit['rule_id']}", hit["file"]), []).append(hit)
    for hit in pack.get("unverified_findings", ()):
        if hit["kind"] == "file":
            hits.setdefault(("security_pack", hit["file"]), []).append(hit)
        else:
            notes.setdefault(hit["file"], []).append(f"unverified (advisory): {hit['rule_id']} line {hit['line']}")
    for hit in pack.get("exempted_test_findings", ()):
        notes.setdefault(hit["file"], []).append(f"exempted in a test path: {hit['rule_id']} line {hit['line']}")
    for f in secrets:
        if is_test_path(f.path):
            notes.setdefault(f.path, []).append(f"exempted in a test path: {f.rule_id} line {f.line}")
        else:  # named by rule and line only: no repository text, masked or not, reaches the detail
            hits.setdefault((f"secret_scan:{f.rule_id}", f.path), []).append({"line": f.line, "pattern": f.rule_id})
    out = []
    for (tool, rel), found in hits.items():
        if tool == "security_pack":
            detail = f"security_pack: cannot verify {rel}: {found[0]['reason']}"
        else:
            # No line number: SARIF fingerprints hash the message, and the lines are in ``lines``.
            detail = "; ".join(dict.fromkeys(f"{h['pattern']} introduced by this change" for h in found))
        out.append(ToolEvidence(tool=tool, target=rel, verdict=False, detail=detail,
                                lines=sorted({h["line"] for h in found if h["line"] > 0})))
    out.extend(ToolEvidence(tool="security_pack", target=rel, verdict=True, detail="; ".join(items))
               for rel, items in sorted(notes.items()))
    return out


def gate_verdict(results: list[ToolEvidence]) -> bool:
    """Simple gate: PASS if all tools pass. Empty results (no changed files) is a clean pass."""
    if not results:
        return True
    return all(r.verdict for r in results)


def format_summary(results: list[ToolEvidence]) -> str:
    """One-line summary of Layer 1 results."""
    if not results:
        return "Layer 1: No changed files to verify (0 checks run, PASSED)"
    passed = sum(1 for r in results if r.verdict)
    failed = sum(1 for r in results if not r.verdict)
    total = len(results)
    unverified = sum(1 for r in results if r.tool == UNVERIFIED_NOTE_TOOL)
    notes = f" ({unverified} unverified, see notes)" if unverified else ""
    if failed:
        return f"Layer 1: {failed}/{total} FAILED — {', '.join(r.tool for r in results if not r.verdict)}{notes}"
    return f"Layer 1: {passed}/{total} PASSED{notes}"


# ── Layer 1 on the index (`aegis check --hook`) ────────────────────────────
# `git commit` records the index, which can differ from the working tree (a partial
# `git add`, an edit after it, a staged file since deleted). The hook therefore checks
# the staged blobs, written to a temporary tree at their repository paths; the rules,
# AST driver configuration and local-package context stay the workspace's own.

_INDEX_FILE_MODES = frozenset({"100644", "100755"})  # a symlink or submodule has no source to check
SNAPSHOT_PREFIX = "aegis-index-"
# The largest staged file the hook reads from git, and the most it reads per git call:
# memory stays bounded whatever is staged. A larger source file is not read (see
# _layer1_on_snapshot for what that means for its checks).
INDEX_BLOB_LIMIT_BYTES = 5 * 1024 * 1024
INDEX_NOTE_TOOL = "index"  # passing evidence that says what the hook did not check
UNVERIFIED_NOTE_TOOL = "forbid_ast_unverified"  # sites a forbid_ast where clause could not decide
EXEMPT_NOTE_TOOL = "forbid_ast_exempt"  # test files a forbid_ast rule skipped
NOTE_TOOLS = frozenset({INDEX_NOTE_TOOL, UNVERIFIED_NOTE_TOOL, EXEMPT_NOTE_TOOL})
_UNVERIFIED_SHOWN = 5


def _index_entries(repo_root: str) -> dict[str, tuple[str, str]]:
    """Path (relative to ``repo_root``, POSIX) -> (mode, object id) for each merged
    entry of the index under ``repo_root``: the one ``GIT_INDEX_FILE`` names in a hook."""
    from aegis_core import gitsafe

    res = gitsafe.run(["ls-files", "-s", "-z"], repo_root)
    if res.returncode != 0:
        raise gitsafe.GitError(f"git ls-files failed: {res.stderr.decode('utf-8', 'replace').strip()}")
    entries: dict[str, tuple[str, str]] = {}
    for record in res.stdout.split(b"\0"):
        meta, sep, raw_path = record.partition(b"\t")
        parts = meta.split()
        if not sep or len(parts) != 3 or parts[2] != b"0":
            continue  # an unmerged entry: git refuses the commit before any hook runs
        entries[os.fsdecode(raw_path)] = (parts[0].decode("ascii"), parts[1].decode("ascii"))
    return entries


def _snapshot_file(snapshot: str, rel: str) -> str:
    """Where ``rel`` (a repository path) lives in the snapshot; never outside it."""
    parts = safe_parts(rel)  # on Windows a ":" would name a drive or a stream
    full = os.path.normpath(os.path.join(snapshot, *parts)) if parts is not None else ""
    if parts is None or not is_within(full, snapshot, unresolvable=False):
        from aegis_core import gitsafe

        raise gitsafe.GitError(f"refusing the staged path {rel!r}: it leaves the snapshot")
    return full


def snapshot_index(repo_root: str, paths: list[str], snapshot: str,
                   entries: Optional[dict[str, tuple[str, str]]] = None) -> tuple[list[str], dict[str, int]]:
    """Write the staged content of ``paths`` (relative to ``repo_root``) under ``snapshot``
    at the same relative paths. Return the paths written (regular files only) and the
    size of each staged file larger than INDEX_BLOB_LIMIT_BYTES, whose content is not read.
    ``entries`` is the index listing (``_index_entries``) when the caller has read it.

    The other Python files the index holds next to each one are written empty: Layer 1
    reads only their names (import_guard counts a sibling module as local), so their
    content is never read from git. Raises GitError when git cannot list or read the index.
    """
    from aegis_core import gitsafe

    entries = _index_entries(repo_root) if entries is None else entries
    staged = [p for p in dict.fromkeys(paths) if entries.get(p, ("", ""))[0] in _INDEX_FILE_MODES]
    sizes = gitsafe.blob_sizes(repo_root, [entries[p][1] for p in staged], timeout=gitsafe.GIT_TIMEOUT_SECONDS)
    too_large = {p: sizes[entries[p][1]] for p in staged if sizes[entries[p][1]] > INDEX_BLOB_LIMIT_BYTES}
    written = [p for p in staged if p not in too_large]
    folders = {posixpath.dirname(p) for p in written if p.endswith(".py")}
    for rel, (mode, _oid) in entries.items():
        if rel.endswith(".py") and posixpath.dirname(rel) in folders and mode in _INDEX_FILE_MODES:
            target = _snapshot_file(snapshot, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            open(target, "wb").close()
    batch: list[str] = []
    batch_bytes = 0
    for rel in [*written, None]:
        size = sizes[entries[rel][1]] if rel is not None else 0
        if batch and (rel is None or batch_bytes + size > INDEX_BLOB_LIMIT_BYTES):
            blobs = gitsafe.read_blobs(repo_root, [entries[r][1] for r in batch], timeout=gitsafe.GIT_TIMEOUT_SECONDS)
            for done in batch:
                target = _snapshot_file(snapshot, done)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(blobs[entries[done][1]])
            batch = []
            batch_bytes = 0
        if rel is not None:
            batch.append(rel)
            batch_bytes += size
    return written, too_large


def _without_snapshot(results: list[ToolEvidence], snapshot: str) -> list[ToolEvidence]:
    """Evidence naming repository paths: a tool's message may quote the snapshot file."""
    prefixes = sorted({os.path.join(root, "") for root in (snapshot, os.path.realpath(snapshot))}, key=len, reverse=True)
    for result in results:
        for prefix in prefixes:
            result.detail = result.detail.replace(prefix, "")
            result.target = result.target.replace(prefix, "")
    return results


def _not_in_the_commit(rel: str, full_path: str, repo_root: str) -> list[str]:
    """The modules ``rel`` imports that are sibling files in the working tree but neither
    staged nor tracked: the hook (rightly) does not count them as local, so say why."""
    folder = posixpath.dirname(rel)
    try:
        here = os.listdir(os.path.join(repo_root, *folder.split("/")) if folder else repo_root)
        imported = {imp.module for imp in import_guard.extract_imports(full_path)}
    except Exception:
        return []
    return sorted(
        name for name in here
        if name.endswith(".py") and not name.startswith("_") and name[:-3] in imported
        and not os.path.exists(os.path.join(os.path.dirname(full_path), name))
    )


def _not_read(size: int) -> str:
    limit = f"{INDEX_BLOB_LIMIT_BYTES / (1024 * 1024):g} MiB"
    return f"its staged content is {size} bytes, over the {limit} the pre-commit hook reads from git"


def _identical_work_file(repo_root: str, rel: str, oid: str, size: int) -> Optional[bytes]:
    """The staged blob ``oid`` (``size`` bytes) read from the working tree when ``rel`` holds it byte
    for byte, or once its CRLF line endings are LF (a ``core.autocrlf`` checkout), else None. Opened
    without following a final symlink or waiting on a FIFO, typed by the open descriptor, and read
    once: the bytes returned are the bytes compared, and they are the blob's."""
    import stat

    from aegis_core import gitsafe

    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(os.path.join(repo_root, *parts), flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        on_disk = info.st_size
        if not stat.S_ISREG(info.st_mode) or not size <= on_disk <= 2 * size:
            return None
        chunks, left = [], on_disk + 1  # one byte more: a file that grew since fstat is not the blob
        while left > 0:
            chunk = os.read(fd, left)
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) != on_disk:
        return None
    for candidate in (data, data.replace(b"\r\n", b"\n")):
        if len(candidate) == size and gitsafe.blob_id(candidate, len(oid)) == oid:
            return candidate
    return None


def _t7_on_index(repo_root: str, rels: list[str], entries: dict[str, tuple[str, str]]) -> list[ToolEvidence]:
    """T7 on the staged content of ``rels``, files no other Layer 1 check parses (the secret scan
    reads any type): held in memory in batches of at most INDEX_BLOB_LIMIT_BYTES, never written to
    the snapshot. A working-tree file that is the staged blob byte for byte is read from disk, once,
    instead of through git (a large asset would cost about three times its size piped through
    ``cat-file`` and could meet git's timeout); any other is read from git. A file over the limit is
    not read, and passing INDEX_NOTE_TOOL evidence says so."""
    from aegis_core import gitsafe

    staged = [rel for rel in dict.fromkeys(rels) if entries.get(rel, ("", ""))[0] in _INDEX_FILE_MODES]
    sizes = gitsafe.blob_sizes(repo_root, [entries[rel][1] for rel in staged], timeout=gitsafe.GIT_TIMEOUT_SECONDS)
    results: list[ToolEvidence] = []
    held: dict[str, bytes] = {}
    from_git: list[str] = []
    batch_bytes = 0
    for rel in [*staged, None]:
        size = sizes[entries[rel][1]] if rel is not None else 0
        if rel is not None and size > INDEX_BLOB_LIMIT_BYTES:
            if not is_test_path(rel):
                results.append(ToolEvidence(tool=INDEX_NOTE_TOOL, target=rel, verdict=True,
                                            detail=f"{rel} not checked: {_not_read(size)}"))
            continue
        if (held or from_git) and (rel is None or batch_bytes + size > INDEX_BLOB_LIMIT_BYTES):
            blobs = gitsafe.read_blobs(repo_root, [entries[r][1] for r in from_git], timeout=gitsafe.GIT_TIMEOUT_SECONDS)
            held.update((r, blobs[entries[r][1]]) for r in from_git)
            results.extend(_t7_evidence(repo_root, sorted(held), repo_root, None, set(), contents=held,
                                        present=entries.__contains__))
            held, from_git, batch_bytes = {}, [], 0
        if rel is None:
            break
        data = _identical_work_file(repo_root, rel, entries[rel][1], size)
        if data is None:
            from_git.append(rel)
        else:
            held[rel] = data
        batch_bytes += size
    return results


def _layer1_on_snapshot(
    files: list[str], repo_root: str, snapshot: str, ast_runner: Any, too_large: dict[str, int],
    entries: dict[str, tuple[str, str]],
) -> list[ToolEvidence]:
    """run_layer1 in fast mode (call_graph, import_guard, forbid_ast) with each file read
    from ``snapshot`` and everything else (rules, drivers, local packages) from ``repo_root``.

    ``entries`` is the index listing: the snapshot holds only some of its files.

    A file in ``too_large`` was not read: a forbid_ast gate rule that covers it fails
    closed; otherwise the call_graph and import_guard checks it would get are skipped,
    and passing INDEX_NOTE_TOOL evidence says so."""
    from aegis_core.ast.policy import ASTExtractionError, evaluate_forbid_ast_structured, extract_normalized_ast

    results: list[ToolEvidence] = []
    checked = [
        (rel, _snapshot_file(snapshot, rel)) for rel in files
        if not (is_test_path(rel) or posixpath.basename(rel) == "__init__.py")
    ]
    entry_points = {"main", "_parse_args", "parse_args"}
    for rel, full_path in checked:
        ext = os.path.splitext(rel)[1].lower()
        try:
            if ext == ".py":
                results.append(call_graph.check(full_path, repo_root, exclude_names=entry_points, fast_mode=True))
            elif ast_runner.registry.resolve_driver(ext, workspace_root=repo_root):
                # The snapshot sits outside the repository: confine to it, resolve drivers from the repo.
                results.append(call_graph.check(
                    full_path, repo_root, exclude_names=entry_points, fast_mode=True, ast_runner=ast_runner,
                    confine_root=snapshot,
                ))
        except Exception as exc:
            results.append(_tool_failure("call_graph", rel, exc))
    for rel, full_path in checked:
        if rel.endswith(".py"):
            try:
                result = import_guard.check(full_path, project_root=repo_root)
            except Exception as exc:
                results.append(_tool_failure("import_guard", rel, exc))
                continue
            missing = _not_in_the_commit(rel, full_path, repo_root) if not result.verdict else []
            if missing:
                result.detail += (f"; {', '.join(missing)} {'is' if len(missing) == 1 else 'are'} not staged or "
                                  "tracked, so the commit would not include it")
            results.append(result)

    try:
        forbid_rules, broken_rules = _discover_forbid_ast_rules(repo_root)
    except Exception as exc:
        forbid_rules = []
        broken_rules = []
        results.append(ToolEvidence(
            tool="forbid_ast", target=RULES_RELDIR, verdict=False,
            detail=f"forbid_ast: cannot load rules: {type(exc).__name__}: {exc}",
        ))
    for rule_path, reason in broken_rules:
        results.append(ToolEvidence(
            tool="forbid_ast", target=rule_path, verdict=False,
            detail=f"forbid_ast: cannot load rule {rule_path}: {reason}",
        ))
    owned: set[tuple[str, int, str]] = set()  # (file, line, pattern) a user forbid_ast rule judged
    for rel, size in too_large.items():
        why = _not_read(size)
        covering = [rule for rule, _spec in forbid_rules if rule.applies_to(rel)]
        for rule in covering:  # a gate rule that cannot read the file must not pass it
            results.append(ToolEvidence(
                tool=f"forbid_ast:{rule.id}", target=rel, verdict=False, detail=f"forbid_ast: cannot verify {rel}: {why}",
            ))
        if not covering and not (is_test_path(rel) or posixpath.basename(rel) == "__init__.py"):
            results.append(ToolEvidence(tool=INDEX_NOTE_TOOL, target=rel, verdict=True, detail=f"{rel} not checked: {why}"))
    for rel in files:
        # Rule.applies_to: target_paths, and test files only when the patterns name tests.
        applicable = [(rule, spec) for rule, spec in forbid_rules if rule.applies_to(rel)]
        if not applicable:
            continue
        try:
            norm_ast = extract_normalized_ast(
                _snapshot_file(snapshot, rel), workspace_root=repo_root, ast_runner=ast_runner, confine_root=snapshot,
            )
        except ASTExtractionError as exc:
            norm_ast = exc
        except Exception as exc:
            results.extend(_tool_failure(f"forbid_ast:{rule.id}", rel, exc) for rule, _spec in applicable)
            continue
        if norm_ast is None:  # no AST driver for this file type: the rules do not apply
            continue
        for rule, forbid_spec in applicable:
            tool = f"forbid_ast:{rule.id}"
            failure = norm_ast if isinstance(norm_ast, ASTExtractionError) else None
            findings: list[dict[str, Any]] = []
            if failure is None:
                try:
                    findings = evaluate_forbid_ast_structured(norm_ast, forbid_spec, rule_id=rule.id)
                    owned.update((rel, f["line"], f["pattern"]) for f in findings if not f["unknown"])
                except ASTExtractionError as exc:  # decorators had to be re-read from the file
                    failure = exc
                except Exception as exc:
                    results.append(_tool_failure(tool, rel, exc))
                    continue
            if failure is not None:
                # Fail closed: a gate rule that cannot read the file must not pass it.
                results.append(ToolEvidence(
                    tool=tool, target=rel, verdict=False, detail=f"forbid_ast: cannot verify {rel}: {failure.reason}",
                ))
                continue
            results.extend(_forbid_or_failure(repo_root, rule.id, rel, findings))
    try:
        results.extend(_exempt_notes(forbid_rules, files))
    except Exception as exc:
        results.append(_tool_failure("forbid_ast", RULES_RELDIR, exc))
    t7_rels = [rel for rel in files if os.path.isfile(_snapshot_file(snapshot, rel))]
    if t7_rels:  # the staged text, against HEAD first
        results.extend(_t7_evidence(repo_root, t7_rels, snapshot, None, owned, present=entries.__contains__))
    return results


def run_layer1_on_index(changed_files: list[str], repo_root: str) -> list[ToolEvidence]:
    """Layer 1 in fast mode on the staged content of ``changed_files`` (paths relative to
    ``repo_root``): exactly what ``git commit`` records, whatever the working tree holds.

    Python and the types an AST driver handles are written to a snapshot for call_graph,
    import_guard, forbid_ast and T7; every other staged file goes to T7 alone (the secret
    scan reads any type, as plain ``aegis check`` does) and is never written (_t7_on_index).
    A path the index does not hold as a regular file (a deletion, a symlink, a submodule)
    has no content to check. Raises GitError when git cannot list or read the index, so
    the caller fails closed.
    """
    import tempfile

    from aegis_core.ast.runner import ASTDriverRunner

    repo_root_str = str(getattr(repo_root, "root", repo_root))
    ast_runner = ASTDriverRunner()
    driven: dict[str, bool] = {".py": True}

    def readable(rel: str) -> bool:
        ext = os.path.splitext(rel)[1].lower()
        if ext not in driven:
            try:
                driven[ext] = bool(ast_runner.registry.resolve_driver(ext, workspace_root=repo_root_str))
            except Exception:
                driven[ext] = True  # read it: call_graph meets the same error and fails closed on it
        return driven[ext]

    entries = _index_entries(repo_root_str)
    with tempfile.TemporaryDirectory(prefix=SNAPSHOT_PREFIX) as snapshot:
        typed = [rel for rel in changed_files if readable(rel)]
        staged, too_large = snapshot_index(repo_root_str, typed, snapshot, entries)
        results = _layer1_on_snapshot(staged, repo_root_str, snapshot, ast_runner, too_large, entries)
        results = _without_snapshot(results, snapshot)
    return results + _t7_on_index(repo_root_str, [rel for rel in changed_files if not readable(rel)], entries)
