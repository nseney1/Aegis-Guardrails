from __future__ import annotations

"""Call Graph Completeness Checker — Layer 1 Verification Tool.

Answers: "Is every defined function reachable from at least one call site?"

Uses Python AST traversal to extract function definitions, inspect module exports
(__all__), and resolve intra-module and inter-module call sites without false-positive
regex collisions.
Pure deterministic — no LLM judgment.
"""

import ast
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

from aegis_core.ast.drivers.python import read_python_source
from aegis_core.ast.schema import NormalizedAST
from aegis_core.match import is_test_path
from . import ToolEvidence

__all__ = ["check"]


@dataclass(frozen=True)
class FunctionDefInfo:
    """Metadata for a function or method definition in an AST."""
    name: str
    line_no: int
    is_exported: bool = False
    is_method: bool = False
    class_name: Optional[str] = None


class FunctionDefinitionVisitor(ast.NodeVisitor):
    """Extracts function/method definitions and module __all__ exports."""

    def __init__(self):
        self.definitions: dict[str, FunctionDefInfo] = {}
        self.dunder_all: set[str] = set()
        self.class_stack: list[str] = []

    def visit_Assign(self, node: ast.Assign):
        # Extract __all__ = ["func1", "ClassA"]
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "__all__":
                if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            self.dunder_all.add(elt.value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._record_func(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._record_func(node)
        self.generic_visit(node)

    def _record_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        # Skip standard dunder methods (__init__, __repr__, etc.)
        if node.name.startswith("__") and node.name.endswith("__"):
            return
        is_method = bool(self.class_stack)
        # Skip AST NodeVisitor dynamic dispatch handlers
        if is_method and node.name.startswith("visit_"):
            return
        class_name = self.class_stack[-1] if is_method else None
        is_exported = node.name in self.dunder_all or (class_name is not None and class_name in self.dunder_all)
        self.definitions[node.name] = FunctionDefInfo(
            name=node.name,
            line_no=node.lineno,
            is_exported=is_exported,
            is_method=is_method,
            class_name=class_name,
        )


class InternalCallCollector(ast.NodeVisitor):
    """Collects direct and method calls within a module, tracking enclosing scope."""

    def __init__(self):
        self.direct_calls: set[str] = set()
        self.attribute_calls: set[str] = set()
        self.current_func: Optional[str] = None
        self.non_recursive_calls: set[str] = set()
        self.non_recursive_attrs: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev = self.current_func
        self.current_func = node.name
        self.generic_visit(node)
        self.current_func = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        prev = self.current_func
        self.current_func = node.name
        self.generic_visit(node)
        self.current_func = prev

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            callee = node.func.id
            self.direct_calls.add(callee)
            if self.current_func != callee:
                self.non_recursive_calls.add(callee)
        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            self.attribute_calls.add(attr)
            if self.current_func != attr:
                self.non_recursive_attrs.add(attr)
        # Check arguments passed to calls (e.g. callbacks or dispatch handlers)
        for arg in node.args:
            if isinstance(arg, ast.Name):
                self.direct_calls.add(arg.id)
                self.non_recursive_calls.add(arg.id)
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name):
                self.direct_calls.add(kw.value.id)
                self.non_recursive_calls.add(kw.value.id)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        for val in node.values:
            if isinstance(val, ast.Name):
                self.direct_calls.add(val.id)
                self.non_recursive_calls.add(val.id)
        self.generic_visit(node)

    def visit_List(self, node: ast.List):
        for elt in node.elts:
            if isinstance(elt, ast.Name):
                self.direct_calls.add(elt.id)
                self.non_recursive_calls.add(elt.id)
        self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple):
        for elt in node.elts:
            if isinstance(elt, ast.Name):
                self.direct_calls.add(elt.id)
                self.non_recursive_calls.add(elt.id)
        self.generic_visit(node)

    def visit_Set(self, node: ast.Set):
        for elt in node.elts:
            if isinstance(elt, ast.Name):
                self.direct_calls.add(elt.id)
                self.non_recursive_calls.add(elt.id)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if isinstance(node.value, ast.Name):
            self.direct_calls.add(node.value.id)
            self.non_recursive_calls.add(node.value.id)
        self.generic_visit(node)


class ExternalModuleInspector(ast.NodeVisitor):
    """Analyzes an external file to check if it calls target functions from target module."""

    def __init__(self, target_stems: set[str], target_func_names: set[str]):
        self.target_stems = target_stems
        self.target_func_names = target_func_names
        # Local name in this external file -> the target function it is bound to
        self.bound_direct_names: dict[str, str] = {}
        # Aliases/module identifiers that refer to our target module
        self.bound_module_aliases: set[str] = set()
        # Confirmed called functions
        self.matched_calls: set[str] = set()
        self.has_wildcard_import: bool = False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            parts = alias.name.split('.')
            if any(p in self.target_stems for p in parts):
                alias_name = alias.asname or parts[-1]
                self.bound_module_aliases.add(alias_name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod_name = node.module or ""
        parts = mod_name.split('.')
        is_target_mod = any(p in self.target_stems for p in parts)

        if is_target_mod:
            for alias in node.names:
                if alias.name == "*":
                    self.has_wildcard_import = True
                elif alias.name in self.target_func_names:
                    self.bound_direct_names[alias.asname or alias.name] = alias.name
                else:
                    # Could be an imported class whose methods are called
                    self.bound_module_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _match_reference(self, node: ast.AST) -> None:
        """Record the target function ``node`` names: ``f`` bound by an import from the
        target module, or ``alias.f`` through an alias of the module or of a class in it."""
        if isinstance(node, ast.Name):
            if node.id in self.bound_direct_names:
                self.matched_calls.add(self.bound_direct_names[node.id])
            elif self.has_wildcard_import and node.id in self.target_func_names:
                self.matched_calls.add(node.id)
        elif isinstance(node, ast.Attribute) and node.attr in self.target_func_names:
            if isinstance(node.value, ast.Name):
                if node.value.id in self.bound_module_aliases or node.value.id in self.target_stems:
                    self.matched_calls.add(node.attr)
            elif self.has_wildcard_import:
                self.matched_calls.add(node.attr)

    def visit_Call(self, node: ast.Call):
        self._match_reference(node.func)
        # A function passed as a value (map(f, ...), key=f) is used, as InternalCallCollector
        # counts it within the module.
        for arg in node.args:
            self._match_reference(arg.value if isinstance(arg, ast.Starred) else arg)
        for kw in node.keywords:
            self._match_reference(kw.value)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict):
        for val in node.values:
            self._match_reference(val)
        self.generic_visit(node)

    def _visit_elements(self, node: ast.List | ast.Tuple | ast.Set):
        for elt in node.elts:
            self._match_reference(elt)
        self.generic_visit(node)

    visit_List = visit_Tuple = visit_Set = _visit_elements

    def visit_Assign(self, node: ast.Assign):
        self._match_reference(node.value)
        self.generic_visit(node)


def _get_target_module_stems(filepath: str, repo_root: str) -> set[str]:
    """Compute module name variations (stem and dotted path) for import resolution."""
    stem = os.path.splitext(os.path.basename(filepath))[0]
    stems = {stem}
    try:
        rel_path = os.path.relpath(filepath, repo_root)
        if not rel_path.startswith(".."):
            no_ext = os.path.splitext(rel_path)[0]
            dotted = no_ext.replace(os.sep, '.')
            stems.add(dotted)
            parts = dotted.split('.')
            stems.update(parts)
    except ValueError:
        pass
    return stems


def _resolve_searchable_extensions(
    repo_root: str,
    norm_ast: Optional[NormalizedAST] = None,
    ast_runner: Optional[Any] = None,
) -> set[str]:
    """Dynamically determine allowed source extensions for the workspace.

    Discovers extensions from the configured AST drivers (aegis_core.config),
    active AST runner registry, the target file extension, and its language definition.
    Zero hardcoded extension lists.
    """
    exts: set[str] = {".py"}

    # 1. Active AST driver registry and configured workspace slots
    if ast_runner is not None and hasattr(ast_runner, "registry"):
        try:
            exts.update(ast_runner.registry.get_configured_extensions(workspace_root=repo_root))
        except Exception:
            pass
    else:
        try:
            from aegis_core.skills.slots import SlotRegistry
            slot_reg = SlotRegistry.load(repo_root)
            exts.update(slot_reg.get_configured_extensions())
        except Exception:
            pass

    # 2. Extensions derived from norm_ast (file extension + language definition)
    if norm_ast is not None:
        if norm_ast.file_path:
            file_ext = os.path.splitext(norm_ast.file_path)[1].lower()
            if file_ext:
                exts.add(file_ext)
        if norm_ast.language:
            try:
                from aegis_core.ast.detect import LANGUAGE_DEFINITIONS
                lang_info = LANGUAGE_DEFINITIONS.get(norm_ast.language.lower())
                if lang_info and "extensions" in lang_info:
                    exts.update(lang_info["extensions"])
            except Exception:
                pass

    return exts

_COMMON_IGNORE_DIRS: frozenset[str] = frozenset({
    "__pycache__", "node_modules", ".venv", "venv", "dist", "build",
    "target", ".cargo", "bin", "obj", ".git", ".soma", ".tox",
    "tests", "test",
})


def _is_safe_source_file(filepath: str, max_size_bytes: int = 1_000_000) -> bool:
    """Ensure file is under size threshold and does not contain null bytes."""
    try:
        st = os.stat(filepath)
        if st.st_size > max_size_bytes or st.st_size == 0:
            return False
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" not in chunk
    except OSError:
        return False


def _get_searchable_source_files(
    repo_root: str,
    allowed_extensions: set[str],
) -> list[str]:
    """Resolve source code files within repo_root matching allowed_extensions.

    Uses Git to respect .gitignore automatically. Falls back to os.walk for non-git trees.
    """
    from aegis_core import gitsafe

    clean_exts = {e if e.startswith(".") else f".{e}" for e in allowed_extensions}

    listed = gitsafe.list_files(repo_root)  # tracked and untracked, .gitignore respected
    if listed is not None:
        files = []
        for f in listed:
            if os.path.splitext(f)[1].lower() in clean_exts:
                full_p = os.path.join(repo_root, f)
                if _is_safe_source_file(full_p):
                    files.append(full_p)
        return files

    # Fallback for non-git directories
    matched = []
    for root, dirs, fnames in os.walk(repo_root):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in _COMMON_IGNORE_DIRS
        ]
        for fname in fnames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in clean_exts:
                full_p = os.path.join(root, fname)
                if _is_safe_source_file(full_p):
                    matched.append(full_p)
    return matched


_COMMENTS_STRINGS_RE = re.compile(
    r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|/\*[\s\S]*?\*/|//[^\n]*|#[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)'
)


def _strip_comments_and_strings(code: str) -> str:
    """Strip comments and string literals from source to prevent false positive call sites."""
    return _COMMENTS_STRINGS_RE.sub(" ", code)


def check_normalized(
    norm_ast: NormalizedAST,
    repo_root: str,
    exclude_names: set[str] | None = None,
    *,
    fast_mode: bool = False,
    ast_runner: Optional[Any] = None,
) -> ToolEvidence:
    """Run call graph reachability check using NormalizedAST representation."""
    exclude_names = exclude_names or set()

    definitions = {
        d.name: FunctionDefInfo(
            name=d.name,
            line_no=d.line,
            is_exported=d.is_exported,
            is_method=d.is_method,
            class_name=d.class_name,
        )
        for d in norm_ast.definitions
        if d.kind in ("function", "method")
    }

    if not definitions:
        return ToolEvidence(
            tool="call_graph",
            target=os.path.basename(norm_ast.file_path),
            verdict=True,
            detail="No function definitions found to verify",
        )

    # 2. Extract internal calls
    internal_called = {c.target for c in norm_ast.call_sites} | {
        c.target.split(".")[-1] for c in norm_ast.call_sites
    }

    # 3. Identify candidate orphan functions
    candidate_orphans: dict[str, FunctionDefInfo] = {}
    for name, info in definitions.items():
        if name in exclude_names:
            continue
        if info.is_exported:
            continue
        if name in internal_called:
            continue
        candidate_orphans[name] = info

    # 4. Inspect external repository files if needed
    orphans: dict[str, int] = {}
    if candidate_orphans:
        if fast_mode:
            return ToolEvidence(
                tool="call_graph",
                target=os.path.basename(norm_ast.file_path),
                verdict=True,
                detail=f"fast_mode: intra-module checks passed ({len(definitions)} functions verified, {len(candidate_orphans)} external candidates skipped)",
            )
        candidate_names = set(candidate_orphans.keys())
        externally_matched: set[str] = set()

        allowed_exts = _resolve_searchable_extensions(repo_root, norm_ast=norm_ast, ast_runner=ast_runner)
        norm_file_abs = os.path.abspath(norm_ast.file_path)

        for fpath in _get_searchable_source_files(repo_root, allowed_exts):
            if is_test_path(os.path.relpath(fpath, repo_root)):
                continue
            if os.path.abspath(fpath) == norm_file_abs:
                continue

            remaining = candidate_names - externally_matched
            if not remaining:
                break

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            stripped = _strip_comments_and_strings(content)

            for name in remaining:
                if re.search(rf"\b{re.escape(name)}\s*\(", stripped):
                    externally_matched.add(name)

        for name, info in candidate_orphans.items():
            if name not in externally_matched:
                orphans[name] = info.line_no

    if orphans:
        orphan_details = [f"{name} (L{line})" for name, line in sorted(orphans.items())]
        return ToolEvidence(
            tool="call_graph",
            target=os.path.basename(norm_ast.file_path),
            verdict=False,
            detail=f"ORPHAN FUNCTIONS: {'; '.join(orphan_details)} — defined but never called",
            lines=list(orphans.values()),
        )

    return ToolEvidence(
        tool="call_graph",
        target=os.path.basename(norm_ast.file_path),
        verdict=True,
        detail=f"All {len(definitions)} functions have call sites",
    )


def check(
    filepath: str,
    repo_root: str,
    exclude_names: set[str] | None = None,
    *,
    fast_mode: bool = False,
    ast_runner: Any = None,
    confine_root: Optional[str] = None,
) -> ToolEvidence:
    """Run AST-based call graph completeness check.

    Args:
        filepath: Path to the source file to analyze
        repo_root: Root of the repository to search for call sites
        exclude_names: Function names to skip (e.g., CLI entry points)
        fast_mode: If True, performs file-isolated checks and skips external repo walks
        ast_runner: Optional ASTDriverRunner instance for non-Python sources

    Returns:
        ToolEvidence with verdict=True if all functions have call sites or are exported
    """
    exclude_names = exclude_names or set()

    ext = os.path.splitext(filepath)[1].lower()
    if ext != ".py":
        from aegis_core.ast.runner import ASTDriverRunner
        runner = ast_runner or ASTDriverRunner()
        try:
            extra = {"confine_root": confine_root} if confine_root is not None else {}
            norm_ast = runner.parse_file(filepath, workspace_root=repo_root, **extra)
            return check_normalized(norm_ast, repo_root, exclude_names, fast_mode=fast_mode, ast_runner=runner)
        except Exception as e:
            return ToolEvidence(
                tool="call_graph",
                target=os.path.basename(filepath),
                verdict=False,
                detail=f"Failed to parse AST via driver: {e}",
            )

    try:
        tree = ast.parse(read_python_source(filepath), filename=filepath)
    except (OSError, SyntaxError, UnicodeError) as e:
        return ToolEvidence(
            tool="call_graph",
            target=os.path.basename(filepath),
            verdict=False,
            detail=f"Failed to parse AST: {e}",
        )

    # 1. Extract definitions and __all__ exports
    def_visitor = FunctionDefinitionVisitor()
    def_visitor.visit(tree)
    # Re-evaluate is_exported post-traversal so trailing __all__ definitions are honored
    for name, info in list(def_visitor.definitions.items()):
        is_exp = name in def_visitor.dunder_all or (info.class_name is not None and info.class_name in def_visitor.dunder_all)
        if is_exp and not info.is_exported:
            def_visitor.definitions[name] = FunctionDefInfo(
                name=info.name,
                line_no=info.line_no,
                is_exported=True,
                is_method=info.is_method,
                class_name=info.class_name,
            )
    definitions = def_visitor.definitions

    if not definitions:
        return ToolEvidence(
            tool="call_graph",
            target=os.path.basename(filepath),
            verdict=True,
            detail="No function definitions found to verify",
        )

    # 2. Extract internal calls within the target file itself
    int_collector = InternalCallCollector()
    int_collector.visit(tree)
    internal_called = int_collector.non_recursive_calls | int_collector.non_recursive_attrs

    # 3. Identify candidate orphan functions
    candidate_orphans: dict[str, FunctionDefInfo] = {}
    for name, info in definitions.items():
        if name in exclude_names:
            continue
        # Exported via __all__ (e.g. public library/SDK API)
        if info.is_exported:
            continue
        # Called internally
        if name in internal_called:
            continue
        candidate_orphans[name] = info

    # 4. If candidates remain, inspect external repository files
    orphans: dict[str, int] = {}
    if candidate_orphans:
        if fast_mode:
            # Fast mode (e.g. pre-commit): skip repo-wide os.walk to preserve <300ms budget
            return ToolEvidence(
                tool="call_graph",
                target=os.path.basename(filepath),
                verdict=True,
                detail=f"fast_mode: intra-module checks passed ({len(definitions)} functions verified, {len(candidate_orphans)} external candidates skipped)",
            )
        target_stems = _get_target_module_stems(filepath, repo_root)
        candidate_names = set(candidate_orphans.keys())
        externally_matched: set[str] = set()
        file_abs = os.path.abspath(filepath)

        for fpath in _get_searchable_source_files(repo_root, {".py"}):
            if os.path.abspath(fpath) == file_abs:
                continue

            remaining = candidate_names - externally_matched
            if not remaining:
                break

            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            # Fast filter: skip AST parsing if none of the candidate names appear
            if not any(name in content for name in remaining):
                continue

            try:
                ext_tree = ast.parse(content, filename=fpath)
            except SyntaxError:
                continue

            inspector = ExternalModuleInspector(target_stems, remaining)
            inspector.visit(ext_tree)
            externally_matched.update(inspector.matched_calls)

        for name, info in candidate_orphans.items():
            if name not in externally_matched:
                orphans[name] = info.line_no

    if orphans:
        orphan_details = [f"{name} (L{line})" for name, line in sorted(orphans.items())]
        return ToolEvidence(
            tool="call_graph",
            target=os.path.basename(filepath),
            verdict=False,
            detail=f"ORPHAN FUNCTIONS: {'; '.join(orphan_details)} — defined but never called",
            lines=list(orphans.values()),
        )

    return ToolEvidence(
        tool="call_graph",
        target=os.path.basename(filepath),
        verdict=True,
        detail=f"All {len(definitions)} functions have call sites",
    )
