"""Test suite for soma_core/verification/pipeline.py conforming to strict checkpoint conventions."""
from __future__ import annotations

import json

import pytest

from aegis_core.verification import ToolEvidence, Verdict
from aegis_core.verification.pipeline import VerificationPipeline


class FakeUnparseableBackend:
    """Backend returning malformed or error string instead of JSON list."""

    def __init__(self, response: str):
        self.response = response

    def generate(self, prompt: str) -> str:
        return self.response


_PASSING = [ToolEvidence("call_graph", "module.py", True, "ok")]
_CRITICAL = json.dumps([{"category": "code_injection", "severity": "critical", "risk": "eval",
                         "mechanism": "exec", "affected_function": "run"}])


def _layer2(tmp_path, backend, evidence=_PASSING):
    (tmp_path / "module.py").write_text("def run():\n    return 42\n", encoding="utf-8")
    return VerificationPipeline().run(
        changed_files=["module.py"], workspace=tmp_path, task_plan="Implement run", backend=backend,
        test_names=[], test_results="", layer1_evidence=list(evidence),
    )


class TestLayer2IsAdvisory:
    """T6 is log-only: `passed` is Layer 1's; the arbiter verdict is reported, never gating (R-checks-43)."""

    @pytest.mark.parametrize("reply", ["Internal Server Error: 500", '{"error": "rate limit"}'], ids=["text", "dict"])
    def test_an_unreadable_spec_reply_is_unverified_not_block(self, tmp_path, reply):
        res = _layer2(tmp_path, FakeUnparseableBackend(reply))
        assert res.verdict != Verdict.BLOCK
        assert res.arbitration_result.infra_status == "unverified"
        assert res.passed is True
        assert "Layer 2 (advisory): UNVERIFIED" in res.summary

    def test_a_critical_prediction_blocks_but_passes(self, tmp_path):
        res = _layer2(tmp_path, lambda prompt: _CRITICAL if "Spec Agent" in prompt else "[]")
        assert res.verdict == Verdict.BLOCK
        assert res.passed is True
        assert res.layer1_passed is True
        assert "Layer 2 (advisory): BLOCK" in res.summary

    def test_a_failing_layer1_row_fails_with_a_clean_layer2(self, tmp_path):
        failing = [ToolEvidence("call_graph", "module.py", False, "run() is never called")]
        res = _layer2(tmp_path, lambda prompt: "[]", evidence=failing)
        assert res.passed is False
        assert res.layer1_passed is False


class TestPipelineFailClosed:
    """Verifies the pipeline writes no evidence, calls the backend only when needed and fails closed."""

    def test_no_changed_files_never_calls_the_backend(self, tmp_path):
        calls = []
        res = VerificationPipeline().run(
            changed_files=[],
            workspace=tmp_path,
            task_plan="Clean run",
            backend=lambda prompt: calls.append(prompt) or "[]",
        )
        assert res.verdict == Verdict.SHIP
        assert res.arbitration_result is None
        assert calls == []

    def test_layer1_only_never_calls_the_backend_or_writes_evidence(self, tmp_path):
        (tmp_path / "mod.py").write_text("def main():\n    return 1\n", encoding="utf-8")
        calls = []
        res = VerificationPipeline().run(
            changed_files=["mod.py"],
            workspace=tmp_path,
            task_plan="None",
            layer1_only=True,
            backend=lambda prompt: calls.append(prompt) or "[]",
        )
        assert res.arbitration_result is None
        assert calls == []
        assert not (tmp_path / ".aegis").exists()

    def test_garbage_reply_with_an_unwired_function_blocks_on_layer1(self, tmp_path):
        """The BLOCK and the failure come from Layer 1 (call_graph: run() is never called), not the reply."""
        f = tmp_path / "module.py"
        f.write_text("def run():\n    return 42\n", encoding="utf-8")

        pipeline = VerificationPipeline()
        bad_backend = FakeUnparseableBackend("Internal Server Error: 500 API Gateway Timeout")

        res = pipeline.run(
            changed_files=["module.py"],
            workspace=tmp_path,
            task_plan="Implement run",
            backend=bad_backend,
        )

        assert res.verdict == Verdict.BLOCK
        assert res.layer1_passed is False
        assert not res.passed

    def test_dict_reply_with_an_unwired_function_blocks_on_layer1(self, tmp_path):
        """The BLOCK and the failure come from Layer 1 (call_graph), not the dict reply."""
        f = tmp_path / "module.py"
        f.write_text("def run():\n    return 42\n", encoding="utf-8")

        pipeline = VerificationPipeline()
        dict_backend = FakeUnparseableBackend('{"error": "rate limit exceeded", "retry_after": 60}')

        res = pipeline.run(
            changed_files=["module.py"],
            workspace=tmp_path,
            task_plan="Implement run",
            backend=dict_backend,
        )

        assert res.verdict == Verdict.BLOCK
        assert res.layer1_passed is False
        assert not res.passed

    def test_pipeline_reusable_layer1_evidence_and_discovery(self, tmp_path):
        from aegis_core.verification import ToolEvidence
        f = tmp_path / "module.py"
        f.write_text("def run():\n    return 42\n", encoding="utf-8")
        test_f = tmp_path / "test_module.py"
        test_f.write_text("def test_run():\n    assert True\n", encoding="utf-8")

        pipeline = VerificationPipeline()
        backend = lambda p: "[]"
        l1_ev = [ToolEvidence("call_graph", "module.py", True, "ok")]

        res = pipeline.run(
            changed_files=["module.py"],
            workspace=tmp_path,
            task_plan="Implement run",
            backend=backend,
            layer1_evidence=l1_ev,
        )
        assert res.verdict == Verdict.SHIP
        assert res.passed is True
        assert res.layer1_evidence == l1_ev

    def test_pipeline_explicit_test_evidence_skips_discovery(self, tmp_path, monkeypatch):
        from aegis_core.verification import ToolEvidence
        f = tmp_path / "module.py"
        f.write_text("def run():\n    return 42\n", encoding="utf-8")

        discovered = []
        def _mock_disc(*a, **kw):
            discovered.append(True)
            return ([], "")
        monkeypatch.setattr("aegis_core.verification.test_runner.discover_test_evidence", _mock_disc)

        pipeline = VerificationPipeline()
        backend = lambda p: "[]"
        res = pipeline.run(
            changed_files=["module.py"],
            workspace=tmp_path,
            task_plan="Implement run",
            backend=backend,
            test_names=["test_custom"],
            test_results="1 passed in 0.01s",
            layer1_evidence=[ToolEvidence("call_graph", "module.py", True, "ok")],
        )
        assert res.verdict == Verdict.SHIP
        assert len(discovered) == 0, "Explicit test_names/test_results must skip discover_test_evidence"

    def test_pipeline_test_evidence_discovery_exception_handled_gracefully(self, tmp_path, monkeypatch):
        from aegis_core.verification import ToolEvidence
        f = tmp_path / "module.py"
        f.write_text("def run():\n    return 42\n", encoding="utf-8")

        def _raise_err(*a, **kw):
            raise RuntimeError("test discovery failure simulation")
        monkeypatch.setattr("aegis_core.verification.test_runner.discover_test_evidence", _raise_err)

        pipeline = VerificationPipeline()
        backend = lambda p: "[]"
        res = pipeline.run(
            changed_files=["module.py"],
            workspace=tmp_path,
            task_plan="Implement run",
            backend=backend,
            layer1_evidence=[ToolEvidence("call_graph", "module.py", True, "ok")],
        )
        assert res.verdict == Verdict.SHIP

    def test_pipeline_partial_test_evidence_triggers_discovery_for_missing(self, tmp_path, monkeypatch):
        from aegis_core.verification import ToolEvidence
        f = tmp_path / "module.py"
        f.write_text("def run():\n    return 42\n", encoding="utf-8")

        discovered = []
        def _mock_disc(*a, **kw):
            discovered.append(True)
            return (["disc_test"], "discovered test output")
        monkeypatch.setattr("aegis_core.verification.test_runner.discover_test_evidence", _mock_disc)

        captured_kwargs = {}
        def mock_verify(**kwargs):
            captured_kwargs.update(kwargs)
            return ([], [], False)

        pipeline = VerificationPipeline()
        monkeypatch.setattr(pipeline.adversarial_verifier, "verify", mock_verify)

        # Pass test_names but leave test_results None
        pipeline.run(
            changed_files=["module.py"],
            workspace=tmp_path,
            task_plan="Plan",
            backend=lambda p: "[]",
            test_names=["provided_test"],
            test_results=None,
            layer1_evidence=[ToolEvidence("call_graph", "module.py", True, "ok")],
        )
        assert len(discovered) == 1, "Partial test evidence (test_results=None) must trigger discovery for missing results"
        assert captured_kwargs["test_names"] == ["provided_test"]
        assert captured_kwargs["test_results"] == "discovered test output"


def test_layer2_reads_only_the_changed_source_modules(tmp_path):
    """Tests and package markers are not the implementation under review; neither are
    deleted files or non-Python ones."""
    from aegis_core.verification.pipeline import AdversarialVerifier

    (tmp_path / "pkg").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("def exported():\n    return 0\n", encoding="utf-8")
    (tmp_path / "pkg" / "mod.py").write_text("def transfer(amount: int) -> int:\n    return amount\n", encoding="utf-8")
    (tmp_path / "tests" / "test_mod.py").write_text("def test_transfer():\n    assert True\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("def nothing(): pass\n", encoding="utf-8")

    signatures, implementation = AdversarialVerifier().extract_target_data(
        ["pkg/__init__.py", "tests/test_mod.py", "pkg/mod.py", "notes.md", "pkg/deleted.py"], tmp_path,
    )

    assert implementation == "def transfer(amount: int) -> int:\n    return amount\n"
    assert len(signatures) == 1 and "def transfer(" in signatures[0]


class TestChangedFilesFromGit:
    """Without changed_files the library asks git; 'git cannot answer' is an error, never a clean pass (R-checks-45)."""

    @staticmethod
    def _git(root, *args):
        import subprocess

        subprocess.run(["git", *args], cwd=str(root), check=True, capture_output=True)

    def test_the_pipeline_outside_a_git_work_tree_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
        (tmp_path / "a.py").write_text("import os\n", encoding="utf-8")
        with pytest.raises(ValueError, match="cannot list the changed files"):
            VerificationPipeline().run(workspace=tmp_path)

    def test_the_layer1_verifier_outside_a_git_work_tree_raises(self, tmp_path, monkeypatch):
        from aegis_core.verification.pipeline import DeterministicVerifier

        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
        (tmp_path / "a.py").write_text("import os\n", encoding="utf-8")
        with pytest.raises(ValueError, match="cannot list the changed files"):
            DeterministicVerifier().verify(workspace=tmp_path)

    def test_a_clean_git_tree_is_a_clean_pass(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        self._git(tmp_path, "init", "-q")
        self._git(tmp_path, "config", "user.email", "t@example.com")
        self._git(tmp_path, "config", "user.name", "T")
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        self._git(tmp_path, "add", "a.py")
        self._git(tmp_path, "commit", "-q", "-m", "init")
        res = VerificationPipeline().run(workspace=tmp_path)
        assert res.passed is True
        assert res.verdict == Verdict.SHIP
        assert res.layer1_passed is True
        assert res.target_files == []

    def test_an_explicit_empty_list_is_a_clean_pass_outside_git(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
        res = VerificationPipeline().run(changed_files=[], workspace=tmp_path)
        assert res.passed is True
        assert res.verdict == Verdict.SHIP
