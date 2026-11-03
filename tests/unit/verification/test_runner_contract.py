"""Layer 1 runner contracts: which changed files the structural checks read, and the
staged snapshot `aegis check --hook` checks (runner.snapshot_index, runner.run_layer1_on_index)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from aegis_core import gitsafe
from aegis_core.verification import ToolEvidence
from aegis_core.verification import runner


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=str(repo), check=True, capture_output=True, text=True,
    )
    return out.stdout.strip()


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    return root


def _stage(repo: Path, rel: str, data: bytes) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    _git(repo, "add", rel)


def _tree(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture
def batch_reads(monkeypatch) -> list:
    """The object ids of each `git cat-file --batch` call, one list per call."""
    real_run, calls = gitsafe.run, []

    def spy(args, cwd, *rest, **kwargs):
        if list(args[:2]) == ["cat-file", "--batch"]:
            calls.append((kwargs.get("stdin") or b"").decode("ascii").split())
        return real_run(args, cwd, *rest, **kwargs)

    monkeypatch.setattr(gitsafe, "run", spy)
    return calls


def test_tests_and_package_markers_get_no_structural_checks(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("import requests\n", encoding="utf-8")
    (tmp_path / "tests" / "test_mod.py").write_text("import requests\n", encoding="utf-8")
    (tmp_path / "pkg" / "mod.py").write_text("def double(x):\n    return x + x\n", encoding="utf-8")

    results = runner.run_layer1(["pkg/__init__.py", "tests/test_mod.py", "pkg/mod.py"], str(tmp_path), fast_mode=True)

    assert sorted((r.tool, r.target) for r in results) == [("call_graph", "mod.py"), ("import_guard", "mod.py")]


class TestSnapshotIndex:
    def test_writes_the_staged_bytes_and_empty_python_siblings_of_their_folders(self, repo: Path, tmp_path: Path):
        _stage(repo, "pkg/a.py", b"STAGED = 1\n")
        _stage(repo, "pkg/b.py", b"SIBLING = 2\n")
        _stage(repo, "pkg/data.json", b"{}\n")
        _stage(repo, "other/c.py", b"OTHER = 3\n")
        (repo / "pkg" / "a.py").write_bytes(b"WORKING_COPY = 1\n")  # not what the commit records
        snapshot = tmp_path / "snap"
        snapshot.mkdir()

        written, too_large = runner.snapshot_index(str(repo), ["pkg/a.py"], str(snapshot))

        assert (written, too_large) == (["pkg/a.py"], {})
        assert _tree(snapshot) == {"pkg/a.py": b"STAGED = 1\n", "pkg/b.py": b""}

    def test_paths_the_index_does_not_hold_as_files_are_not_written(self, repo: Path, tmp_path: Path):
        _stage(repo, "kept.py", b"x = 1\n")
        snapshot = tmp_path / "snap"
        snapshot.mkdir()

        written, _ = runner.snapshot_index(str(repo), ["kept.py", "never_staged.py", "kept.py"], str(snapshot))

        assert written == ["kept.py"]
        assert _tree(snapshot) == {"kept.py": b"x = 1\n"}

    def test_a_file_over_the_limit_is_reported_by_size_and_never_read(self, repo, tmp_path, monkeypatch, batch_reads):
        monkeypatch.setattr(runner, "INDEX_BLOB_LIMIT_BYTES", 64)
        _stage(repo, "big.py", b"#" * 65 + b"\n")
        _stage(repo, "small.py", b"y = 2\n")
        snapshot = tmp_path / "snap"
        snapshot.mkdir()

        written, too_large = runner.snapshot_index(str(repo), ["big.py", "small.py"], str(snapshot))

        assert (written, too_large) == (["small.py"], {"big.py": 66})
        assert _tree(snapshot) == {"big.py": b"", "small.py": b"y = 2\n"}  # big.py: an empty sibling only
        assert _git(repo, "rev-parse", ":big.py") not in sum(batch_reads, [])

    def test_staged_files_are_read_in_batches_of_at_most_the_limit(self, repo, tmp_path, monkeypatch, batch_reads):
        monkeypatch.setattr(runner, "INDEX_BLOB_LIMIT_BYTES", 100)
        for name, size in (("a.py", 30), ("b.py", 30), ("c.py", 60), ("d.py", 10)):
            _stage(repo, name, name.encode() + b"#" * (size - len(name) - 1) + b"\n")
        oid = {name: _git(repo, "rev-parse", f":{name}") for name in ("a.py", "b.py", "c.py", "d.py")}
        snapshot = tmp_path / "snap"
        snapshot.mkdir()

        written, _ = runner.snapshot_index(str(repo), ["a.py", "b.py", "c.py", "d.py"], str(snapshot))

        assert written == ["a.py", "b.py", "c.py", "d.py"]
        assert batch_reads == [[oid["a.py"], oid["b.py"]], [oid["c.py"], oid["d.py"]]]
        assert {rel: len(data) for rel, data in _tree(snapshot).items()} == {"a.py": 30, "b.py": 30, "c.py": 60, "d.py": 10}


class TestLayer1OnIndex:
    def test_the_staged_python_content_is_what_is_checked(self, repo: Path):
        _stage(repo, "app.py", b"import requests\n\ndef main():\n    return requests\n")
        (repo / "app.py").write_text("def main():\n    return 1\n", encoding="utf-8")

        results = runner.run_layer1_on_index(["app.py"], str(repo))

        blocked = [(r.tool, r.target) for r in results if not r.verdict]
        assert blocked == [("import_guard", "app.py")]
        assert "requests" in next(r.detail for r in results if r.tool == "import_guard")

    def test_a_file_whose_driver_lookup_fails_is_still_read_and_fails_closed(self, repo: Path):
        (repo / ".aegis").mkdir()
        (repo / ".aegis" / "config.json").write_text("{not json", encoding="utf-8")
        _stage(repo, "app.go", b"package main\n\nfunc run() {}\n")

        results = runner.run_layer1_on_index(["app.go"], str(repo))

        assert [(r.tool, r.target, r.verdict) for r in results] == [
            ("call_graph", "app.go", False), ("security_pack", "app.go", False)]
        assert results[0].detail.startswith("call_graph: cannot verify app.go: ")
        assert results[1].detail.startswith("security_pack: cannot verify app.go: ")
        assert results[1].language == "go"

    def test_native_ts_needs_no_driver_lookup_so_a_malformed_config_does_not_block_it(self, repo: Path):
        (repo / ".aegis").mkdir()
        (repo / ".aegis" / "config.json").write_text("{not json", encoding="utf-8")
        _stage(repo, "app.ts", b"export function run() {}\n")

        results = runner.run_layer1_on_index(["app.ts"], str(repo))

        assert [(r.tool, r.target, r.verdict) for r in results] == [("call_graph", "app.ts", True)]


def test_working_tree_and_index_preserve_identical_forbid_ast_evidence(repo: Path):
    _stage(repo, ".aegis/rules/invariants/no-danger.md", (
        b"---\nid: no-danger\ntype: invariant\nenforcement: gate\n"
        b"forbid_ast:\n  imports: [pickle]\n  calls: [eval]\n---\nNo dangerous operations.\n"
    ))
    _git(repo, "commit", "-q", "-m", "reviewed rule")
    _git(repo, "update-ref", "refs/remotes/origin/main", _git(repo, "rev-parse", "HEAD"))
    _git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    _stage(repo, "app.py", b'\n\neval("1")\n\nimport pickle\n\n\n\neval("2")\n')

    working = runner.run_layer1(["app.py"], str(repo), fast_mode=True)
    staged = runner.run_layer1_on_index(["app.py"], str(repo))

    assert working == staged == [
        ToolEvidence("call_graph", "app.py", True, "No function definitions found to verify"),
        ToolEvidence("import_guard", "app.py", True, "All imports are stdlib, allowed, or guarded"),
        ToolEvidence("forbid_ast:no-danger", "app.py", False,
                     "Forbidden import 'pickle' matched rule forbid_ast.imports; "
                     "Forbidden call 'eval' matched rule forbid_ast.calls", [3, 5, 9]),
    ]


def _local_python_env() -> dict:
    root = Path(__file__).resolve().parents[3]
    return {**os.environ, "PYTHONPATH": str(root) + os.pathsep + os.environ.get("PYTHONPATH", "")}


@pytest.mark.parametrize("package", ["aegis_mcp", "mylib"])
def test_hook_schema_coverage_mapping_is_scoped_to_aegis(repo: Path, package: str):
    _stage(repo, f"{package}/schemas.py", b"TOOL_DEFINITIONS = []\n")
    _stage(repo, "tests/unit/mcp/test_mcp_registry.py", b"def test_wire_bytes():\n    assert 1 == 1\n")

    result = subprocess.run([sys.executable, "-m", "aegis_cli", "check", "--hook", "--json"],
                            cwd=repo, env=_local_python_env(), capture_output=True, timeout=30)

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    payload = json.loads(result.stdout)
    assert payload["summary"] == "Layer 1: 2/2 PASSED"
    assert payload["checkpoint_issues"] == ([] if package == "aegis_mcp" else [{
        "check": "test_coverage", "file": "mylib/schemas.py",
        "message": "Missing test file for schemas.py: expected tests/test_schemas.py",
    }])


def _mutation_project(root: Path, source: str, suite: str, test_code: bytes) -> Path:
    root.mkdir()
    path = root / source
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"def main(x):\n    return x + x\n")
    test = root / suite
    test.parent.mkdir(parents=True, exist_ok=True)
    test.write_bytes(test_code)
    (root / "pyproject.toml").write_bytes(b'[tool.pytest.ini_options]\npythonpath = ["."]\n')
    return root


@pytest.mark.parametrize(("source", "suite"), [
    ("verification/runner.py", "tests/unit/verification/test_layer1.py"),
    ("mylib/verification/runner.py", "tests/unit/verification/test_layer1.py"),
    ("nested/aegis_core/verification/runner.py", "tests/unit/verification/test_layer1.py"),
    ("aegis_core_extra/verification/runner.py", "tests/unit/verification/test_layer1.py"),
    ("soma_core/verification/runner.py", "tests/unit/verification/test_layer1.py"),
    ("nested/aegis_mcp/handlers/governance.py", "tests/unit/mcp/test_mcp_handlers.py"),
    ("prefixaegis_mcp/handlers/governance.py", "tests/unit/mcp/test_mcp_handlers.py"),
    ("soma_mcp/handlers/governance.py", "tests/unit/mcp/test_mcp_handlers.py"),
    ("nested/aegis_core/skills/catalog.py", "tests/unit/core/test_skills.py"),
])
def test_foreign_paths_do_not_select_aegis_mutation_suites(tmp_path: Path, source: str, suite: str):
    root = _mutation_project(tmp_path / "project", source, suite, b"def test_unrelated():\n    assert 2 + 2 == 4\n")

    results = runner.run_layer1([source], str(root), max_mutations=1)

    assert [result for result in results if result.tool == "mutation_tester"] == []


@pytest.mark.parametrize(("source", "suite"), [
    ("aegis_core/verification/runner.py", "tests/unit/verification/test_layer1.py"),
    ("aegis_mcp/handlers/governance.py", "tests/unit/mcp/test_mcp_handlers.py"),
    ("aegis_core/outcomes/telemetry.py", "tests/unit/core/test_outcomes_telemetry.py"),
    ("aegis_core/outcomes/engine.py", "tests/unit/core/test_outcome_engine.py"),
    ("aegis_core/skills/slots.py", "tests/unit/core/test_slots.py"),
    ("aegis_core/skills/catalog.py", "tests/unit/core/test_skills.py"),
])
@pytest.mark.parametrize("absolute", [False, True])
def test_aegis_package_roots_keep_their_mutation_suites(tmp_path: Path, source: str, suite: str, absolute: bool):
    root = _mutation_project(tmp_path / "project", source, suite, b"def test_unrelated():\n    assert 2 + 2 == 4\n")

    results = runner.run_layer1([str(root / source) if absolute else source], str(root), max_mutations=1)

    assert [(result.verdict, result.detail) for result in results if result.tool == "mutation_tester"] == [
        (False, f"1/1 survived: no test that ran imported {Path(source).name} (1 test file ran)"),
    ]


@pytest.mark.parametrize("source", ["widget.py", "mylib/widget.py", "nested/aegis_core/skills/slots.py"])
def test_generic_sources_still_select_their_matching_tests(tmp_path: Path, source: str):
    module = source[:-3].replace("/", ".")
    test = f"from {module} import main\ndef test_double():\n    assert main(2) == 4\n".encode("utf-8")
    root = _mutation_project(tmp_path / "project", source, f"tests/test_{Path(source).stem}.py", test)

    results = runner.run_layer1([source], str(root), max_mutations=1)

    assert [(result.verdict, result.detail) for result in results if result.tool == "mutation_tester"] == [
        (True, "0/1 survived (1 test file ran)"),
    ]


@pytest.mark.parametrize("source", ["nested/aegis_cli/scan.py", "soma_cli/scan.py"])
def test_foreign_package_names_do_not_prioritize_aegis_test_homes(tmp_path: Path, source: str):
    module = source[:-3].replace("/", ".")
    test = f"from {module} import main\ndef test_double():\n    assert main(2) == 4\n".encode("utf-8")
    root = _mutation_project(tmp_path / "project", source, "tests/test_scan.py", test)
    wrong = root / "tests/unit/cli/test_cli_scan.py"
    wrong.parent.mkdir(parents=True)
    wrong.write_bytes(b'def test_wrong_package():\n    assert False, "wrong package suite selected"\n')

    results = runner.run_layer1([source], str(root), max_mutations=1)

    assert [(result.verdict, result.detail) for result in results if result.tool == "mutation_tester"] == [
        (True, "0/1 survived (1 test file ran)"),
    ]


@pytest.mark.parametrize("module", ["runner", "call_graph", "persistence_checker"])
def test_verification_library_modules_have_no_script_ui(tmp_path: Path, module: str):
    result = subprocess.run([sys.executable, "-m", f"aegis_core.verification.{module}"],
                            cwd=tmp_path, env=_local_python_env(), capture_output=True, timeout=30)

    assert (result.returncode, result.stdout) == (0, b"")
