"""Declarative forbid_ast rules: evaluate_forbid_ast and the Layer 1 gate built on it.

The pre-edit planned_symbols scan input was cut in v4 (plan of record: JIT
ast_triggers/planned_symbols, 0 uses); forbid_ast stays as the gate tier's
deterministic mechanism.
"""
from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from aegis_core.ast.policy import evaluate_forbid_ast
from aegis_core.ast.schema import CallSiteNode, ImportNode, NormalizedAST
from aegis_core.verification.pipeline import DeterministicVerifier
from aegis_core.verification.runner import gate_verdict, run_layer1_on_index


class TestEvaluateForbidAST:
    """Behavioral tests for evaluate_forbid_ast across imports, calls, and decorators."""

    def test_forbid_ast_imports_matches_module_prefix_and_symbol(self):
        norm_ast = NormalizedAST(
            file_path="src/loader.py",
            language="python",
            imports=(
                ImportNode(source="pickle", imported_symbols=("loads",)),
                ImportNode(source="urllib.request", imported_symbols=("urlopen",)),
            ),
        )
        violations = evaluate_forbid_ast(
            norm_ast,
            {"imports": ["pickle", "urllib", "subprocess"]},
        )
        assert len(violations) == 2
        assert "Forbidden import 'pickle' matched rule forbid_ast.imports" in violations
        assert "Forbidden import 'urllib' matched rule forbid_ast.imports" in violations

    def test_forbid_ast_calls_matches_direct_and_dotted_calls(self):
        norm_ast = NormalizedAST(
            file_path="src/runner.py",
            language="python",
            call_sites=(
                CallSiteNode(target="eval", line=5),
                CallSiteNode(target="os.system", line=8),
                CallSiteNode(target="safe_evaluate", line=10),
            ),
        )
        violations = evaluate_forbid_ast(
            norm_ast,
            {"calls": ["eval", "os.system", "exec"]},
        )
        assert len(violations) == 2
        assert "Forbidden call 'eval' matched rule forbid_ast.calls" in violations
        assert "Forbidden call 'os.system' matched rule forbid_ast.calls" in violations

    def test_forbid_ast_decorators_matches_normalized_ast_decorators(self):
        norm_ast = NormalizedAST(
            file_path="tests/test_sample.py",
            language="python",
            decorators=["@pytest.mark.xfail", "dataclass"],
        )
        violations = evaluate_forbid_ast(
            norm_ast,
            {"decorators": ["pytest.mark.xfail", "flaky"]},
        )
        assert violations == [
            "Forbidden decorator 'pytest.mark.xfail' matched rule forbid_ast.decorators"
        ]

    def test_forbid_ast_clean_returns_empty_list(self):
        norm_ast = NormalizedAST(
            file_path="src/clean.py",
            language="python",
            imports=(ImportNode(source="json", imported_symbols=("loads",)),),
            call_sites=(CallSiteNode(target="json.loads", line=3),),
            decorators=["dataclass"],
        )
        violations = evaluate_forbid_ast(
            norm_ast,
            {
                "imports": ["pickle", "subprocess"],
                "calls": ["eval", "exec"],
                "decorators": ["pytest.mark.xfail"],
            },
        )
        assert violations == []


_SUBPROCESS_AST = NormalizedAST(
    file_path="src/runner.py",
    language="python",
    imports=(ImportNode(source="subprocess", imported_symbols=("run",)),),
    call_sites=(CallSiteNode(target="subprocess.run", line=3), CallSiteNode(target="eval", line=4)),
)


class TestSpecsThatForbidNothing:
    """What evaluate_forbid_ast cannot use forbids nothing here; Layer 1 reports such a
    rule itself (runner._forbid_ast_spec_error), so a gate is never silently empty."""

    @pytest.mark.parametrize("spec", [["subprocess"], "subprocess", None, {}])
    def test_a_spec_that_is_not_a_mapping_is_ignored(self, spec):
        assert evaluate_forbid_ast(_SUBPROCESS_AST, spec) == []

    def test_no_ast_means_no_violation(self):
        assert evaluate_forbid_ast(None, {"imports": ["subprocess"], "calls": ["eval"]}) == []

    @pytest.mark.parametrize("key, value", [("imports", "subprocess"), ("calls", "eval"), ("decorators", "x")])
    def test_patterns_given_as_one_string_are_ignored(self, key, value):
        norm_ast = NormalizedAST(
            file_path="src/runner.py",
            imports=(ImportNode(source="subprocess"),),
            call_sites=(CallSiteNode(target="eval"),),
            decorators=["x"],
        )
        assert evaluate_forbid_ast(norm_ast, {key: value}) == []

    def test_an_empty_decorator_list_never_reads_the_file(self, tmp_path):
        broken = tmp_path / "broken.py"
        broken.write_text("def (:\n", encoding="utf-8")
        norm_ast = NormalizedAST(file_path=str(broken), call_sites=(CallSiteNode(target="eval"),))

        assert evaluate_forbid_ast(norm_ast, {"calls": ["eval"], "decorators": []}) == [
            "Forbidden call 'eval' matched rule forbid_ast.calls"
        ]


class TestLayer1DeterministicVerifierForbidAST:
    """Layer 1 DeterministicVerifier tests with workspace rules declaring forbid_ast."""

    def _setup_workspace_with_rule(self, tmp_path: Path) -> Path:
        rules_dir = tmp_path / ".aegis" / "rules" / "invariants"
        rules_dir.mkdir(parents=True, exist_ok=True)
        rule_md = (
            "---\n"
            "id: no-unsafe-exec-or-pickle\n"
            "type: invariant\n"
            "enforcement: gate\n"
            "hypothesis: Never use eval() or pickle in production code.\n"
            "target_paths:\n"
            "  - src/*.py\n"
            "forbid_ast:\n"
            "  calls:\n"
            "    - eval\n"
            "  imports:\n"
            "    - pickle\n"
            "  decorators:\n"
            "    - pytest.mark.xfail\n"
            "---\n"
            "# No Unsafe Exec or Pickle\n"
        )
        (rules_dir / "no-unsafe-exec-or-pickle.md").write_text(rule_md, encoding="utf-8")
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        return tmp_path

    def test_deterministic_verifier_fails_on_forbidden_eval_and_pickle(self, tmp_path: Path):
        ws = self._setup_workspace_with_rule(tmp_path)
        bad_file = ws / "src" / "unsafe.py"
        bad_file.write_text(
            "import pickle\n\n"
            "def main(payload: str):\n"
            "    return eval(payload)\n",
            encoding="utf-8",
        )

        verifier = DeterministicVerifier(fast_mode=True)
        evidence = verifier.verify(changed_files=["src/unsafe.py"], workspace=ws)

        assert not gate_verdict(evidence)
        forbid_results = [e for e in evidence if e.tool == "forbid_ast:no-unsafe-exec-or-pickle"]
        assert len(forbid_results) == 1
        assert forbid_results[0].verdict is False
        assert forbid_results[0].target == "src/unsafe.py"
        assert "Forbidden import 'pickle'" in forbid_results[0].detail
        assert "Forbidden call 'eval'" in forbid_results[0].detail

    def test_deterministic_verifier_passes_when_clean_and_skips_tests_dir(self, tmp_path: Path):
        ws = self._setup_workspace_with_rule(tmp_path)
        clean_file = ws / "src" / "safe.py"
        clean_file.write_text(
            "import json\n\n"
            "def main(payload: str):\n"
            "    return json.loads(payload)\n",
            encoding="utf-8",
        )
        test_dir = ws / "tests"
        test_dir.mkdir(parents=True, exist_ok=True)
        test_file = test_dir / "test_unsafe_allowed.py"
        test_file.write_text(
            "import pickle\n"
            "def test_something():\n"
            "    eval('1 + 1')\n",
            encoding="utf-8",
        )

        verifier = DeterministicVerifier(fast_mode=True)
        evidence = verifier.verify(
            changed_files=["src/safe.py", "tests/test_unsafe_allowed.py"],
            workspace=ws,
        )
        assert gate_verdict(evidence) is True
        forbid_results = [e for e in evidence if e.tool.startswith("forbid_ast:")]
        assert forbid_results == []


# (flow-style where, the argument the reason names). The ReDoS literal below would backtrack for
# hours if a rule-supplied regex ever reached ``re``.
_MALFORMED_WHERE_YAML = [
    ("{shell: {equal: true}}", "shell"),
    ("{'#0': {in: SafeLoader}}", "#0"),
    ("{shell: {matches: '^(a+)+$'}}", "shell"),
    ("{shell: {not_equals: false}}", "shell"),
    ("{shell: {in: []}}", "shell"),
    ("{shell: {in: [1], not: 2}}", "shell"),
    ("{shell: {absent: 'yes'}}", "shell"),
    ("{shell: {}}", "shell"),
]
_REDOS_SOURCE = "import subprocess\n\ndef main(c):\n    return subprocess.run(c, shell='" + "a" * 40 + "!')\n"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=str(repo), check=True, capture_output=True)


class TestMalformedWhereFailsClosedInLayer1:
    """R-checks-8: a forbid_ast rule whose where would enforce nothing is refused at load by
    every Layer 1 path, so the gate fails instead of passing (or hanging on) the file."""

    def _workspace(self, tmp_path: Path, where: str) -> Path:
        rules = tmp_path / ".aegis" / "rules" / "invariants"
        rules.mkdir(parents=True)
        (rules / "r1.md").write_text(
            "---\nid: r1\ntype: invariant\nenforcement: gate\ntarget_paths:\n  - 'src/*.py'\n"
            f"forbid_ast:\n  calls:\n    - {{name: subprocess.run, where: {where}}}\n---\n# R1\n",
            encoding="utf-8")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text(_REDOS_SOURCE, encoding="utf-8")
        return tmp_path

    @staticmethod
    def _assert_refused(evidence, arg: str) -> None:
        assert gate_verdict(evidence) is False
        refused = [e for e in evidence if e.tool == "forbid_ast"]
        assert [(e.target, e.verdict) for e in refused] == [(".aegis/rules/invariants/r1.md", False)]
        assert refused[0].detail.startswith(
            f"forbid_ast: cannot load rule .aegis/rules/invariants/r1.md: forbid_ast.calls[0].where.{arg}: ")
        assert not [e for e in evidence if e.tool == "forbid_ast:r1"]

    @pytest.mark.parametrize("where,arg", _MALFORMED_WHERE_YAML, ids=[w for w, _ in _MALFORMED_WHERE_YAML])
    def test_the_working_tree_path_refuses_the_rule(self, tmp_path, where, arg):
        ws = self._workspace(tmp_path, where)
        evidence = DeterministicVerifier(fast_mode=True).verify(changed_files=["src/app.py"], workspace=ws)
        self._assert_refused(evidence, arg)

    @pytest.mark.parametrize("where,arg", _MALFORMED_WHERE_YAML, ids=[w for w, _ in _MALFORMED_WHERE_YAML])
    def test_the_staged_snapshot_path_refuses_the_rule(self, tmp_path, monkeypatch, where, arg):
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        ws = self._workspace(tmp_path, where)
        _git(ws, "init", "-q", "-b", "main")
        _git(ws, "add", "src/app.py")
        self._assert_refused(run_layer1_on_index(["src/app.py"], str(ws)), arg)

    @pytest.mark.parametrize("where,src,blocked", [
        ("{shell: true}", "import subprocess\nsubprocess.run(c, shell=True)\n", True),
        ("{shell: true}", "import subprocess\nsubprocess.run(c)\n", False),
        ("{shell: {absent: true}}", "import subprocess\nsubprocess.run(c)\n", True),
        ("{check: {not: true}}", "import subprocess\nsubprocess.run(c, check=False)\n", True),
        ("{check: {not: true}}", "import subprocess\nsubprocess.run(c, check=True)\n", False),
        ("{'args|#0': {in: [ls, rm]}}", "import subprocess\nsubprocess.run('rm')\n", True),
    ], ids=["literal-hit", "literal-miss", "absent", "not-hit", "not-miss", "in-alternation"])
    def test_a_well_formed_where_loads_and_evaluates(self, tmp_path, where, src, blocked):
        ws = self._workspace(tmp_path, where)
        (ws / "src" / "app.py").write_text(src, encoding="utf-8")
        evidence = DeterministicVerifier(fast_mode=True).verify(changed_files=["src/app.py"], workspace=ws)
        assert not [e for e in evidence if e.tool == "forbid_ast"]
        assert [e.verdict for e in evidence if e.tool == "forbid_ast:r1"] == ([False] if blocked else [])
