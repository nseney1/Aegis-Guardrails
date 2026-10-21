"""Tests for Verifier OOP Architecture and Pipeline (Phase 20).

Verifies:
- DeterministicVerifier Layer 1 orchestration and git change discovery (gitsafe)
- AdversarialVerifier backend contract: a callable or an object with .generate()
  (the CLI passes aegis_core.inference_provider.CommandBackend), and no backend
  is an error rather than a silent skip (D14)
- VerificationPipeline layer1_only and full arbitration modes
"""
from __future__ import annotations

import json

import pytest

from aegis_core.inference_provider import MISSING_BACKEND
from aegis_core.verification.pipeline import AdversarialVerifier, DeterministicVerifier, VerificationPipeline
from aegis_core.verification import RiskCategory, ToolEvidence, Verdict
from aegis_core.workspace.base import Workspace


class TestDeterministicVerifier:
    """Verifies DeterministicVerifier execution and git change auto-discovery."""

    def test_verify_explicit_files(self, tmp_path):
        src = tmp_path / "calc.py"
        src.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        test = tmp_path / "test_calc.py"
        test.write_text("from calc import add\ndef test_add():\n    assert add(1, 2) == 3\n", encoding="utf-8")

        verifier = DeterministicVerifier()
        ws = Workspace(root=tmp_path)
        evidence = verifier.verify(changed_files=["calc.py"], workspace=ws)
        assert isinstance(evidence, list)
        assert all(isinstance(e, ToolEvidence) for e in evidence)

    @staticmethod
    def _repo(tmp_path):
        import subprocess

        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=str(repo), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo), check=True)
        subprocess.run(["git", "config", "user.name", "Tester"], cwd=str(repo), check=True)
        (repo / "module.py").write_text("def fn():\n    return 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
        subprocess.run(["git", "commit", "-m", "Init"], cwd=str(repo), check=True, capture_output=True)
        return repo

    def test_verify_auto_discovers_unstaged_changes(self, tmp_path, monkeypatch):
        from aegis_core.verification import runner

        repo = self._repo(tmp_path)
        (repo / "module.py").write_text("def fn():\n    return 2\n", encoding="utf-8")
        seen = {}
        real = runner.run_layer1
        monkeypatch.setattr(runner, "run_layer1", lambda changed_files, **kw: seen.setdefault("files", changed_files) and real(changed_files, **kw))

        evidence = DeterministicVerifier().verify(changed_files=None, workspace=Workspace(root=repo))
        assert isinstance(evidence, list)
        assert seen["files"] == ["module.py"]

    def test_verify_auto_discovers_staged_only_changes(self, tmp_path, monkeypatch):
        """#27: v3 asked `git diff` (unstaged only), so a staged-only change was never checked."""
        import subprocess
        from aegis_core.verification import runner

        repo = self._repo(tmp_path)
        (repo / "staged.py").write_text("def g():\n    return 3\n", encoding="utf-8")
        subprocess.run(["git", "add", "staged.py"], cwd=str(repo), check=True)
        seen = {}
        monkeypatch.setattr(runner, "run_layer1", lambda changed_files, **kw: seen.setdefault("files", changed_files) and [])

        DeterministicVerifier().verify(changed_files=None, workspace=Workspace(root=repo))
        assert seen["files"] == ["staged.py"]


class TestAdversarialVerifierBackend:
    """The Layer 2 backend is a callable or an object with .generate(); nothing else."""

    def _verify(self, tmp_path, backend):
        (tmp_path / "api.py").write_text("def execute_transaction(amount: float):\n    return amount\n", encoding="utf-8")
        return AdversarialVerifier(backend).verify(
            changed_files=["api.py"],
            workspace=Workspace(root=tmp_path),
            task_plan="Implement banking transaction",
            layer1_evidence=[],
        )

    def test_plain_callable_backend(self, tmp_path):
        prompts = []
        preds, claims, spec_failed, gaps = self._verify(tmp_path, lambda prompt: prompts.append(prompt) or "[]")
        assert (preds, claims, spec_failed) == ([], [], False)
        assert (gaps.reviewed_files, gaps.skipped_files, gaps.dropped_entries, gaps.code_agent_failed) == (
            ("api.py",), (), 0, False)
        assert len(prompts) == 2

    def test_object_with_generate_backend(self, tmp_path):
        class Charging:
            def generate(self, prompt: str) -> str:
                if "Spec Agent" not in prompt:
                    return "[]"
                return json.dumps([{
                    "category": "missing_coverage", "severity": "high", "risk": "no failure-path test",
                    "mechanism": "negative amounts unexercised", "affected_function": "execute_transaction",
                }])

        preds, claims, _, _ = self._verify(tmp_path, Charging())
        assert [(p.category, p.affected_function) for p in preds] == [
            (RiskCategory.MISSING_COVERAGE, "execute_transaction")
        ]
        assert claims == []

    def test_missing_backend_is_an_error_not_a_skip(self, tmp_path):
        with pytest.raises(ValueError, match=MISSING_BACKEND):
            self._verify(tmp_path, None)

    def test_unusable_backend_raises_type_error(self, tmp_path):
        with pytest.raises(TypeError, match="must be callable or provide .generate"):
            self._verify(tmp_path, 12345)

    def test_call_time_backend_overrides_the_constructor_backend(self, tmp_path):
        (tmp_path / "api.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        used = []
        verifier = AdversarialVerifier(lambda p: used.append("ctor") or "[]")
        verifier.verify(
            changed_files=["api.py"], workspace=Workspace(root=tmp_path), task_plan="p",
            layer1_evidence=[], backend=lambda p: used.append("call") or "[]",
        )
        assert used == ["call", "call"]


class TestVerificationPipeline:
    """Verifies VerificationPipeline in layer1_only and full arbitration modes."""

    def test_pipeline_layer1_only(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("def hello():\n    return 'world'\n\ndef main():\n    hello()\n", encoding="utf-8")

        pipeline = VerificationPipeline()
        res = pipeline.run(
            changed_files=["clean.py"],
            workspace=tmp_path,
            layer1_only=True,
        )

        assert res.layer1_passed
        assert res.passed
        assert res.verdict == Verdict.SHIP
        assert res.arbitration_result is None

    def test_pipeline_full_run_arbitrates_with_the_backend(self, tmp_path):
        f = tmp_path / "auth.py"
        f.write_text("def login(user, pw):\n    return True\n\ndef main():\n    login('a', 'b')\n", encoding="utf-8")

        res = VerificationPipeline().run(
            changed_files=["auth.py"],
            workspace=tmp_path,
            task_plan="Add login logic",
            backend=lambda prompt: "[]",
        )

        assert res.arbitration_result is not None
        assert res.verdict == Verdict.SHIP
        assert res.passed

    def test_pipeline_full_run_without_a_plan_raises(self, tmp_path):
        (tmp_path / "auth.py").write_text("def login():\n    return True\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Layer 2 needs a task plan"):
            VerificationPipeline().run(changed_files=["auth.py"], workspace=tmp_path, backend=lambda p: "[]")

    def test_pipeline_rejects_a_missing_backend_before_running_layer1(self, tmp_path, monkeypatch):
        from aegis_core.verification import runner

        ran = []
        monkeypatch.setattr(runner, "run_layer1", lambda **kw: ran.append(kw) or [])
        (tmp_path / "auth.py").write_text("def login():\n    return True\n", encoding="utf-8")
        with pytest.raises(ValueError, match=MISSING_BACKEND):
            VerificationPipeline().run(changed_files=["auth.py"], workspace=tmp_path, task_plan="p")
        assert ran == []
