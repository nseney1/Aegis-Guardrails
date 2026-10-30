"""Behavioral test suite verifying Call Graph reachability on language-agnostic NormalizedAST."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from aegis_core.ast.schema import (
    CallSiteNode,
    DefinitionNode,
    ImportNode,
    NormalizedAST,
)
from aegis_core.verification import call_graph


def test_call_graph_all_functions_called_internally():
    norm_ast = NormalizedAST(
        file_path="src/service.ts",
        language="typescript",
        definitions=(
            DefinitionNode(name="publicMethod", kind="function", line=10, is_exported=True),
            DefinitionNode(name="internalHelper", kind="function", line=20, is_exported=False),
        ),
        call_sites=(
            CallSiteNode(target="internalHelper", line=12, caller_scope="publicMethod"),
        ),
        imports=(),
    )

    evidence = call_graph.check_normalized(norm_ast, repo_root=".")
    assert evidence.verdict is True
    assert "All 2 functions have call sites" in evidence.detail or "verified" in evidence.detail.lower()


def test_call_graph_detects_orphan_function():
    norm_ast = NormalizedAST(
        file_path="src/calc.go",
        language="go",
        definitions=(
            DefinitionNode(name="ExportedApi", kind="function", line=5, is_exported=True),
            DefinitionNode(name="uncalledDeadwood", kind="function", line=15, is_exported=False),
            DefinitionNode(name="calledHelper", kind="function", line=25, is_exported=False),
        ),
        call_sites=(
            CallSiteNode(target="calledHelper", line=8, caller_scope="ExportedApi"),
        ),
        imports=(),
    )

    evidence = call_graph.check_normalized(norm_ast, repo_root=".")
    assert evidence.verdict is False
    assert "ORPHAN FUNCTIONS" in evidence.detail
    assert "uncalledDeadwood" in evidence.detail
    assert 15 in evidence.lines


def test_call_graph_exported_functions_not_flagged_as_orphans():
    norm_ast = NormalizedAST(
        file_path="lib/export_only.ts",
        language="typescript",
        definitions=(
            DefinitionNode(name="PublicApiA", kind="function", line=1, is_exported=True),
            DefinitionNode(name="PublicApiB", kind="function", line=10, is_exported=True),
        ),
        call_sites=(),
        imports=(),
    )

    evidence = call_graph.check_normalized(norm_ast, repo_root=".")
    assert evidence.verdict is True


def test_call_graph_external_file_matches_polyglot_orphan(tmp_path):
    # Target file has an uncalled function
    target_ts = tmp_path / "utils.ts"
    target_ts.write_text("// utils", encoding="utf-8")

    norm_ast = NormalizedAST(
        file_path=str(target_ts),
        language="typescript",
        definitions=(
            DefinitionNode(name="sharedHelper", kind="function", line=10, is_exported=False),
        ),
        call_sites=(),
        imports=(),
    )

    # Calling file in repo calls sharedHelper
    consumer_file = tmp_path / "caller.ts"
    consumer_file.write_text("import { sharedHelper } from './utils'; sharedHelper();", encoding="utf-8")

    evidence = call_graph.check_normalized(norm_ast, repo_root=str(tmp_path), fast_mode=False)
    assert evidence.verdict is True


def test_call_graph_comment_and_string_in_external_file_does_not_satisfy_call(tmp_path):
    target_go = tmp_path / "calc.go"
    target_go.write_text("// calc", encoding="utf-8")

    norm_ast = NormalizedAST(
        file_path=str(target_go),
        language="go",
        definitions=(
            DefinitionNode(name="uncalledCalc", kind="function", line=10, is_exported=False),
        ),
        call_sites=(),
        imports=(),
    )

    # Calling file only mentions uncalledCalc in a comment and string literal
    consumer_file = tmp_path / "main.go"
    consumer_file.write_text(
        '// Note: uncalledCalc() should be used\nconst msg = "call uncalledCalc()";\n',
        encoding="utf-8",
    )

    evidence = call_graph.check_normalized(norm_ast, repo_root=str(tmp_path), fast_mode=False)
    assert evidence.verdict is False
    assert "ORPHAN FUNCTIONS" in evidence.detail
    assert "uncalledCalc" in evidence.detail


def test_call_graph_respects_gitignore_in_git_repository(tmp_path):
    import subprocess
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True, capture_output=True)

    (tmp_path / ".gitignore").write_text("target/\n*.bin\n", encoding="utf-8")
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    target_rs = src_dir / "lib.rs"
    target_rs.write_text("// rust source", encoding="utf-8")

    ignored_dir = tmp_path / "target" / "debug"
    ignored_dir.mkdir(parents=True)
    ignored_file = ignored_dir / "dummy.rs"
    ignored_file.write_text("fn test() { orphanFunc(); }", encoding="utf-8")

    subprocess.run(["git", "add", ".gitignore", "src"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True, capture_output=True)

    norm_ast = NormalizedAST(
        file_path=str(target_rs),
        language="rust",
        definitions=(
            DefinitionNode(name="orphanFunc", kind="function", line=5, is_exported=False),
        ),
        call_sites=(),
        imports=(),
    )

    evidence = call_graph.check_normalized(norm_ast, repo_root=str(tmp_path), fast_mode=False)
    # The dummy call in target/ MUST be ignored because target/ is in .gitignore
    assert evidence.verdict is False
    assert "ORPHAN FUNCTIONS" in evidence.detail
    assert "orphanFunc" in evidence.detail


def test_call_graph_ignores_non_source_extensions(tmp_path):
    target_py = tmp_path / "mod.py"
    target_py.write_text("# py", encoding="utf-8")

    (tmp_path / "asset.png").write_bytes(b"\x89PNG\r\n\x1a\nunusedHelper()")
    (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02unusedHelper()\x00")
    (tmp_path / "notes.txt").write_text("unusedHelper()", encoding="utf-8")

    norm_ast = NormalizedAST(
        file_path=str(target_py),
        language="python",
        definitions=(
            DefinitionNode(name="unusedHelper", kind="function", line=10, is_exported=False),
        ),
        call_sites=(),
        imports=(),
    )

    evidence = call_graph.check_normalized(norm_ast, repo_root=str(tmp_path), fast_mode=False)
    assert evidence.verdict is False
    assert "unusedHelper" in evidence.detail


def test_resolve_searchable_extensions_dynamic(tmp_path):
    from aegis_core.ast.runner import NATIVE_JS_EXTENSIONS

    # 1. Default without slots or norm_ast is the in-process languages: .py and native JS/TS
    exts = call_graph._resolve_searchable_extensions(str(tmp_path))
    assert exts == {".py"} | NATIVE_JS_EXTENSIONS
    assert ".rs" not in exts and ".ts" in exts

    # 2. A packaged driver enabled in .aegis/config.json dynamically adds .rs
    aegis_dir = tmp_path / ".aegis"
    aegis_dir.mkdir()
    (aegis_dir / "config.json").write_text('{"v": 1, "ast": {"packaged_drivers": ["rs"]}}', encoding="utf-8")

    exts_with_slot = call_graph._resolve_searchable_extensions(str(tmp_path))
    assert exts_with_slot == {".py", ".rs"} | NATIVE_JS_EXTENSIONS

    # 3. Providing norm_ast for typescript adds .ts and .tsx dynamically
    target_ts = tmp_path / "index.ts"
    norm_ast = NormalizedAST(
        file_path=str(target_ts),
        language="typescript",
        definitions=(),
        call_sites=(),
        imports=(),
    )
    exts_with_norm = call_graph._resolve_searchable_extensions(str(tmp_path), norm_ast=norm_ast)
    assert {".py", ".rs", ".ts", ".tsx"}.issubset(exts_with_norm)
