"""Public test classification and warning-only checkpoint pairing across languages."""
from __future__ import annotations

from pathlib import Path

import pytest

from aegis_core.ast.runner import ASTDriverRunner
from aegis_core.match import is_test_path
from aegis_core.verification.checkpoint_checks import (
    check_test_coverage,
    find_python_files,
)
from tests.conftest import symlink_or_skip

JS_EXTENSIONS = ("ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs")


def write(root: Path, relative: str, source: str = "") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


@pytest.mark.parametrize("extension", JS_EXTENSIONS)
@pytest.mark.parametrize("kind", ("test", "spec"))
def test_every_js_test_suffix_is_classified(extension, kind):
    assert is_test_path(f"web/widget.{kind}.{extension}")


@pytest.mark.parametrize("path", [
    "src/__tests__/widget.ts", "src\\__tests__\\widget.tsx", "__tests__/nested/helper.js",
    "cmd/main_test.go", "tests/regress.rs", "crates/example/tests/nested/regress.rs",
    "test_unit.py", "package/module_test.py", "tests/unit/helper.py", "conftest.py", "src/test_module.rs",
])
def test_test_directories_and_existing_python_names_are_classified(path):
    assert is_test_path(path)


@pytest.mark.parametrize("path", [
    "src/widget.ts", "src/widget.test.ts.map", "src/widget.testish.ts", "src/lib.rs",
    "src/contest.rs", "src/testing_module.rs", "src/__tests__like/widget.ts", "main.go",
    "src/app.py", "src/testing.py", "test/helpers.py",
])
def test_source_files_do_not_become_tests(path):
    assert not is_test_path(path)


@pytest.mark.parametrize("extension", JS_EXTENSIONS)
@pytest.mark.parametrize("kind", ("test", "spec"))
def test_js_colocated_tests_pair_sources(tmp_path, extension, kind):
    write(tmp_path, f"src/widget.{extension}")
    write(tmp_path, f"src/widget.{kind}.{extension}")
    assert check_test_coverage(tmp_path) == []


@pytest.mark.parametrize("test", [
    "src/widget.test.js", "src/__tests__/widget.ts", "src/__tests__/widget.test.ts",
    "src/__tests__/widget.spec.tsx", "tests/widget.test.ts", "tests/unit/widget.spec.mts",
    "test/integration/nested/widget.test.cjs",
])
def test_js_supported_layouts_pair_sources(tmp_path, test):
    write(tmp_path, "src/widget.ts")
    write(tmp_path, test)
    assert check_test_coverage(tmp_path) == []


@pytest.mark.parametrize("source,hint", [
    ("src/widget.ts", "widget.test.*"), ("widget.mjs", "widget.test.*"),
    ("src/main.go", "main_test.go"), ("src/lib.rs", "#[cfg(test)]"),
])
def test_unpaired_polyglot_sources_warn(tmp_path, source, hint):
    write(tmp_path, source)
    issues = check_test_coverage(tmp_path)
    assert len(issues) == 1
    assert issues[0]["check"] == "test_coverage"
    assert issues[0]["file"] == source
    assert "Missing test file" in issues[0]["message"]
    assert hint in issues[0]["message"]


@pytest.mark.parametrize("source,test", [
    ("src/main.go", "src/main_test.go"), ("src/main.go", "src/other_test.go"),
    ("main.go", "main_test.go"),
])
def test_go_pairs_by_file_or_package(tmp_path, source, test):
    write(tmp_path, source)
    write(tmp_path, test)
    assert check_test_coverage(tmp_path) == []


def test_go_tests_in_another_package_do_not_pair(tmp_path):
    write(tmp_path, "cmd/main.go")
    write(tmp_path, "other/main_test.go")
    assert [issue["file"] for issue in check_test_coverage(tmp_path)] == ["cmd/main.go"]


def test_rust_integration_file_pairs_without_parsing_source(tmp_path):
    write(tmp_path, "src/widget.rs", "pub fn widget() {}")
    write(tmp_path, "tests/widget.rs", "#[test] fn widget() {}")
    assert check_test_coverage(tmp_path) == []


@pytest.mark.parametrize("source", [
    "#[cfg(test)] mod tests { #[test] fn works() {} }",
    "#[cfg(test)] mod tests {}",
])
def test_rust_inline_pairing_uses_normalized_parser_metadata(tmp_path, source):
    root = tmp_path / "project"
    target = write(root, "src/lib.rs", source)
    runner = ASTDriverRunner(allow_build=False)
    assert runner.parse_file(target, workspace_root=root).metadata["test_module"] is True
    assert check_test_coverage(root, ast_runner=runner) == []
    assert not is_test_path("src/lib.rs")


@pytest.mark.parametrize("source", [
    '// #[cfg(test)] mod tests {}\nconst S: &str = "#[cfg(test)]";',
    "macro_rules! ignored { () => { #[cfg(test)] mod tests {} } }",
    "#[cfg(test)] mod tests;",
    '#[path = "missing.rs"] #[cfg(test)] mod tests;',
])
def test_rust_inline_text_does_not_replace_confirmed_metadata(tmp_path, source):
    root = tmp_path / "project"
    target = write(root, "src/lib.rs", source)
    runner = ASTDriverRunner(allow_build=False)
    assert runner.parse_file(target, workspace_root=root).metadata["test_module"] is False
    issues = check_test_coverage(root, ast_runner=runner)
    assert [issue["file"] for issue in issues] == ["src/lib.rs"]
    assert "Missing test file" in issues[0]["message"]


def test_rust_parser_failure_remains_a_visible_warning(tmp_path):
    root = tmp_path / "project"
    target = write(root, "src/lib.rs", "fn broken(")
    runner = ASTDriverRunner(allow_build=False)
    issues = check_test_coverage(root, ast_runner=runner)
    assert issues == [{
        "check": "test_coverage", "file": "src/lib.rs",
        "message": (f"src/lib.rs: parse inline test module failed: cannot verify {target}: "
                    "ASTDriverError: unclosed delimiter at line 1"),
    }]


@pytest.mark.parametrize("source,test", [
    ("src/main.go", "src/main_test.go"), ("src/widget.ts", "src/widget.test.ts"),
    ("src/widget.rs", "tests/widget.rs"),
])
def test_symlinked_pairing_files_do_not_satisfy_coverage(tmp_path, source, test):
    root = tmp_path / "project"
    write(root, source)
    target = write(tmp_path, "outside-test", "fixture")
    link = root / test
    link.parent.mkdir(parents=True, exist_ok=True)
    symlink_or_skip(target, link)
    issues = check_test_coverage(root)
    assert any(issue["file"] == test and "symlinked" in issue["message"] for issue in issues)


def test_symlinked_test_directory_is_not_followed(tmp_path):
    root = tmp_path / "project"
    write(root, "src/widget.ts")
    outside = tmp_path / "outside"
    write(outside, "widget.test.ts")
    symlink_or_skip(outside, root / "src/__tests__", target_is_directory=True)
    issues = check_test_coverage(root)
    assert issues and all(issue["check"] == "test_coverage" for issue in issues)


def test_test_files_and_build_trees_are_not_unpaired_sources(tmp_path):
    for path in ["src/__tests__/helper.ts", "src/widget.test.tsx", "cmd/main_test.go",
                 "tests/regress.rs", "node_modules/library/index.js", "target/generated/build.rs"]:
        write(tmp_path, path)
    assert check_test_coverage(tmp_path) == []


def test_python_discovery_and_warning_contract_remain_unchanged(tmp_path):
    write(tmp_path, "pkg/module.py", "VALUE = 1")
    write(tmp_path, "pkg/widget.ts")
    write(tmp_path, "pkg/__init__.py")
    assert [path.name for path in find_python_files(tmp_path, "pkg")] == ["module.py"]
    issues = check_test_coverage(tmp_path)
    python = next(issue for issue in issues if issue["file"] == "pkg/module.py")
    assert python["message"] == "Missing test file for module.py: expected tests/test_module.py"


def test_checkpoint_pairing_does_not_modify_repository_files(tmp_path):
    write(tmp_path, "src/widget.ts")
    write(tmp_path, "src/widget.test.ts")
    before = {str(path.relative_to(tmp_path)): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert check_test_coverage(tmp_path) == []
    after = {str(path.relative_to(tmp_path)): path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert after == before


def test_unpaired_source_remains_warning_only_in_the_cli(tmp_path, capsys):
    from aegis_cli.cli import main

    write(tmp_path, "src/widget.ts")
    assert main(["check", "--workspace", str(tmp_path)]) == 0
    output = capsys.readouterr()
    assert "[WARN]" in output.out and "Missing test file for widget.ts" in output.out
    assert output.err == ""


def test_aegis_go_template_pairs_with_its_actual_python_protocol_harness(tmp_path):
    write(tmp_path, "aegis_core/ast/drivers/templates/go_ast.go", "package main")
    write(tmp_path, "tests/unit/core/test_go_ast_driver.py", "def test_protocol():\n    assert True\n")
    assert check_test_coverage(tmp_path) == []


@pytest.mark.parametrize("source,harness", [
    ("aegis_core/ast/drivers/templates/go_ast.go", None),
    ("aegis_core/ast/drivers/templates/unrelated.go", "tests/unit/core/test_go_ast_driver.py"),
    ("another/ast/drivers/templates/go_ast.go", "tests/unit/core/test_go_ast_driver.py"),
    ("aegis_core/ast/drivers/templates/go_ast.go", "tests/unit/core/test_unrelated.py"),
])
def test_go_harness_mapping_never_exempts_unpaired_sources(tmp_path, source, harness):
    write(tmp_path, source, "package main")
    if harness:
        write(tmp_path, harness, "def test_protocol():\n    assert True\n")
    assert [issue["file"] for issue in check_test_coverage(tmp_path)] == [source]


def test_symlinked_go_python_harness_is_not_a_pair(tmp_path):
    source = "aegis_core/ast/drivers/templates/go_ast.go"
    write(tmp_path, source, "package main")
    harness = tmp_path / "tests/unit/core/test_go_ast_driver.py"
    harness.parent.mkdir(parents=True)
    target = write(tmp_path, "outside.py", "def test_protocol():\n    assert True\n")
    symlink_or_skip(target, harness)
    issues = check_test_coverage(tmp_path)
    assert any(row["file"] == "tests/unit/core/test_go_ast_driver.py" and "symlinked" in row["message"]
               for row in issues)
