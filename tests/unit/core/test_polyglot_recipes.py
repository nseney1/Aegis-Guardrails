"""Unit tests for polyglot AST recipe drivers and mutation testing adaptations."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
import pytest

from aegis_core.ast.runner import ASTDriverRegistry, ASTDriverRunner
from aegis_core.ast.schema import (
    CallSiteNode,
    DefinitionNode,
    ImportNode,
    MutationPoint,
    NormalizedAST,
)
from aegis_core.verification import mutation_tester



# A hang ceiling, not a budget: real node and go start-ups on a loaded Windows runner can take
# minutes, and these tests check what the drivers produce, not how fast.
_HANG_CEILING = 600.0

class TestMutationPointApplication:
    """Test applying MutationPoint replacements to source code."""

    def test_apply_mutation_point_byte_offset(self):
        source = "function check(x) {\n  return x === 10;\n}"
        idx = source.index("===")
        point = MutationPoint(
            line=2,
            col=11,
            original_op="===",
            replacement_op="!==",
            mutation_type="cmpop",
        )
        # Verify with byte_offset attached
        object.__setattr__(point, "byte_offset", idx)

        mutated = mutation_tester.apply_mutation_point(source, point)
        assert mutated == "function check(x) {\n  return x !== 10;\n}"

    def test_apply_mutation_point_line_and_column(self):
        source = "const a = b && c;\n"
        point = MutationPoint(
            line=1,
            col=12,
            original_op="&&",
            replacement_op="||",
            mutation_type="boolop",
        )

        mutated = mutation_tester.apply_mutation_point(source, point)
        assert mutated == "const a = b || c;\n"

    def test_apply_mutation_point_line_search_fallback(self):
        source = "let flag = foo <= bar;\n"
        point = MutationPoint(
            line=1,
            col=0,  # Deliberately zero/mismatched column to trigger line search fallback
            original_op="<=",
            replacement_op=">=",
            mutation_type="cmpop",
        )

        mutated = mutation_tester.apply_mutation_point(source, point)
        assert mutated == "let flag = foo >= bar;\n"

    def test_collect_mutations_from_ast_filtering(self):
        p1 = MutationPoint(line=2, col=5, original_op="&&", replacement_op="||", mutation_type="boolop")
        p2 = MutationPoint(line=6, col=5, original_op="==", replacement_op="!=", mutation_type="cmpop")
        p3 = MutationPoint(line=10, col=5, original_op="+", replacement_op="-", mutation_type="binop")

        object.__setattr__(p1, "function_scope", "fnA")
        object.__setattr__(p2, "function_scope", "fnB")

        ast = NormalizedAST(
            file_path="service.ts",
            language="typescript",
            mutation_points=(p1, p2, p3),
        )

        all_muts = mutation_tester.collect_mutations_from_ast(ast, target_function=None)
        assert len(all_muts) == 3

        fna_muts = mutation_tester.collect_mutations_from_ast(ast, target_function="fnA")
        assert fna_muts == [p1, p3]

        fnb_muts = mutation_tester.collect_mutations_from_ast(ast, target_function="fnB")
        assert fnb_muts == [p2, p3]


class TestPolyglotRecipes:
    """Test Node.js/TypeScript and Go driver recipes."""

    def test_ts_ast_recipe_execution(self, tmp_path):
        node_bin = shutil.which("node")
        if not node_bin:
            pytest.skip("node is not available on PATH")

        ts_code = (
            "import { helper } from './utils';\n"
            "export function calculate(a: number, b: number): number {\n"
            "  if (a === b) {\n"
            "    return helper(a);\n"
            "  }\n"
            "  return a + b;\n"
            "}\n"
        )
        sample_ts = tmp_path / "calc.ts"
        sample_ts.write_text(ts_code, encoding="utf-8")

        recipe_path = Path(__file__).parents[3] / "aegis_core" / "ast" / "drivers" / "templates" / "ts_ast.js"
        assert recipe_path.is_file(), f"Recipe file missing at {recipe_path}"

        proc = subprocess.run(
            [node_bin, str(recipe_path), str(sample_ts)],
            capture_output=True,
            text=True,
            timeout=_HANG_CEILING,
            stdin=subprocess.DEVNULL,
        )
        assert proc.returncode == 0, f"Driver failed with stderr: {proc.stderr}"

        data = json.loads(proc.stdout)
        norm_ast = NormalizedAST.from_dict(data)

        assert norm_ast.language == "typescript"
        assert any(d.name == "calculate" and d.is_exported for d in norm_ast.definitions)
        assert any(c.target == "helper" for c in norm_ast.call_sites)
        assert any(imp.source == "./utils" for imp in norm_ast.imports)
        assert any(m.original_op == "===" and m.replacement_op == "!==" for m in norm_ast.mutation_points)

    def test_ast_driver_runner_with_ts_recipe(self, tmp_path):
        node_bin = shutil.which("node")
        if not node_bin:
            pytest.skip("node is not available on PATH")

        ts_code = "export function run(): void { console.log('hello'); }"
        sample_ts = tmp_path / "app.ts"
        sample_ts.write_text(ts_code, encoding="utf-8")

        recipe_path = Path(__file__).parents[3] / "aegis_core" / "ast" / "drivers" / "templates" / "ts_ast.js"
        driver_cmd = f'"{node_bin}" "{recipe_path}"'

        registry = ASTDriverRegistry(drivers={".ts": driver_cmd})
        runner = ASTDriverRunner(registry=registry)
        norm_ast = runner.parse_file(str(sample_ts), workspace_root=str(tmp_path), timeout=_HANG_CEILING)

        assert norm_ast.file_path == str(sample_ts)
        assert any(d.name == "run" for d in norm_ast.definitions)

    def test_go_recipe_source_structure(self):
        recipe_path = Path(__file__).parents[3] / "aegis_core" / "ast" / "drivers" / "templates" / "go_ast.go"
        assert recipe_path.is_file()
        content = recipe_path.read_text(encoding="utf-8")
        assert "go/parser" in content
        assert "go/token" in content
        assert "NormalizedAST" in content
        assert "encoding/json" in content


