"""Verification pipeline: Layer 1 tools, the Layer 2 adversarial pair, the Arbiter.

- DeterministicVerifier: Layer 1 (call graph, import guards, forbid_ast, mutation tests)
- AdversarialVerifier: Layer 2 Spec Agent (plan + signatures) and Code Agent
  (implementation + Layer 1 output), information-partitioned (AEGIS-V01)
- Arbiter: pure deterministic set-logic judge
- VerificationPipeline: composes Layer 1 -> Layer 2 -> Arbiter

The Layer 2 backend is any callable ``prompt -> reply`` or an object with
``generate(prompt)``, such as ``aegis_core.inference_provider.CommandBackend``.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from aegis_core import gitsafe
from aegis_core.inference_provider import MISSING_BACKEND
from aegis_core.match import is_test_path
from aegis_core.workspace.base import Workspace
from aegis_core.workspace import as_workspace

from . import (
    ArbitrationResult,
    Claim,
    Prediction,
    ToolEvidence,
    Verdict,
)
from . import adversarial_verify
from . import arbiter as arbiter_module
from . import runner

# A callable ``prompt -> reply`` or an object with ``generate(prompt) -> reply``.
Backend = Any


def _working_changes(root: Path) -> list[str]:
    """What git reports as changed against HEAD, staged or not. None from git means it
    could not answer, which must not read as "nothing changed" (fail closed)."""
    found = gitsafe.changed_files(root, "working")
    if found is None:
        raise ValueError("cannot list the changed files (not a git work tree, or git failed); pass changed_files")
    return found


# ── Base Verifier ─────────────────────────────────────────────────────────


class BaseVerifier(ABC):
    """Abstract base class for verification components."""

    @abstractmethod
    def verify(self, *args: Any, **kwargs: Any) -> Any:
        """Run verification and emit results."""
        pass


# ── Deterministic Verifier (Layer 1) ──────────────────────────────────────


class DeterministicVerifier(BaseVerifier):
    """Layer 1 deterministic verification engine.

    Orchestrates the call graph, import guards, forbid_ast rules and (outside
    fast mode) mutation testing against modified files.
    """

    def __init__(self, max_mutations: int = 5, fast_mode: bool = False):
        self.max_mutations = max_mutations
        self.fast_mode = fast_mode

    def verify(
        self,
        changed_files: list[str] | None = None,
        workspace: str | Path | Workspace | None = None,
        persistence_targets: list[tuple[str, str]] | None = None,
        mutation_targets: list[tuple[str, str, str]] | None = None,
        fast_mode: bool | None = None,
    ) -> list[ToolEvidence]:
        """Run Layer 1 checks.

        Without ``changed_files``, checks what git reports as changed against HEAD,
        staged or not (``gitsafe.changed_files(..., "working")``); outside a git work
        tree, or when git fails, raises ValueError.
        """
        ws = as_workspace(workspace)
        repo_root = str(ws.root)

        files = changed_files
        if files is None:
            files = _working_changes(ws.root)

        is_fast = self.fast_mode if fast_mode is None else fast_mode
        return runner.run_layer1(
            changed_files=files,
            repo_root=repo_root,
            persistence_targets=persistence_targets,
            mutation_targets=mutation_targets,
            max_mutations=self.max_mutations,
            fast_mode=is_fast,
        )


# ── Layer 2 backend ───────────────────────────────────────────────────────


def _strip_code_fence(text: str) -> str:
    """Strip markdown code fences (```json ... ```) from LLM output."""
    match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def _generate_fn(backend: Backend) -> Callable[[str], str]:
    if backend is None:
        raise ValueError(MISSING_BACKEND)
    generate = getattr(backend, "generate", None)
    if callable(generate):
        return generate
    if callable(backend):
        return backend
    raise TypeError(f"Layer 2 backend must be callable or provide .generate(), got {type(backend).__name__}")


# ── Adversarial Verifier (Layer 2) ────────────────────────────────────────


class AdversarialVerifier(BaseVerifier):
    """Layer 2 adversarial verification engine."""

    def __init__(self, backend: Backend = None):
        self.backend = backend

    def extract_target_data(
        self,
        changed_files: list[str],
        workspace: Workspace | str | Path,
    ) -> tuple[list[str], str]:
        """Extract signatures and implementation text from changed Python files."""
        ws = as_workspace(workspace)
        repo_root = str(ws.root)

        all_signatures: list[str] = []
        all_implementation: list[str] = []

        for filepath in changed_files:
            full_path = Path(repo_root) / filepath
            if not full_path.exists() or not filepath.endswith(".py"):
                continue
            if is_test_path(filepath) or full_path.name == "__init__.py":
                continue
            try:
                sigs = adversarial_verify.extract_signatures(str(full_path))
                all_signatures.extend(sigs)
                all_implementation.append(full_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue

        return all_signatures, "\n\n".join(all_implementation)

    def verify(
        self,
        changed_files: list[str],
        workspace: Workspace | str | Path,
        task_plan: str,
        layer1_evidence: list[ToolEvidence],
        backend: Backend = None,
        test_names: list[str] | None = None,
        test_results: str | None = None,
    ) -> tuple[list[Prediction], list[Claim], bool]:
        """Run the Spec Agent (prosecution) then the Code Agent (defense).

        Returns (predictions, claims, spec_agent_failed).
        """
        generate = _generate_fn(backend if backend is not None else self.backend)
        signatures, implementation_text = self.extract_target_data(changed_files, workspace)

        # Phase 1: Prosecution
        spec_prompt = adversarial_verify.build_spec_prompt(
            plan=task_plan,
            signatures=signatures,
            test_names=test_names or [],
        )
        spec_response = generate(spec_prompt)
        spec_agent_failed = False
        try:
            raw_predictions = self._parse_json(spec_response)
        except Exception:
            raw_predictions = []
            spec_agent_failed = True

        predictions = adversarial_verify.parse_predictions(raw_predictions)

        # Phase 2: Defense
        layer1_output: dict[str, list] = {}
        for e in layer1_evidence:
            layer1_output.setdefault(e.tool, []).append(
                {"target": e.target, "verdict": e.verdict, "detail": e.detail}
            )

        code_prompt = adversarial_verify.build_code_prompt(
            implementation=implementation_text,
            test_results=test_results or "",
            layer1_output=layer1_output,
            spec_predictions=raw_predictions,
        )
        code_response = generate(code_prompt)
        try:
            raw_claims = self._parse_json(code_response)
        except Exception:
            raw_claims = []
        claims = adversarial_verify.parse_claims(raw_claims)

        return predictions, claims, spec_agent_failed

    @staticmethod
    def _parse_json(text: str) -> list[dict[str, Any]]:
        raw = _strip_code_fence(text)
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"Expected JSON list from LLM response, got {type(data).__name__}")
        return data


# ── Arbiter OOP Wrapper ───────────────────────────────────────────────────


class Arbiter:
    """Pure deterministic set-logic judge comparing predictions, claims, and tool evidence."""

    def arbitrate(
        self,
        predictions: list[Prediction],
        claims: list[Claim],
        layer1_evidence: list[ToolEvidence],
        *,
        spec_agent_failed: bool = False,
    ) -> ArbitrationResult:
        return arbiter_module.arbitrate(
            predictions=predictions,
            claims=claims,
            layer1_evidence=layer1_evidence,
            spec_agent_failed=spec_agent_failed,
        )


# ── Verification Pipeline ─────────────────────────────────────────────────


@dataclass
class VerificationPipelineResult:
    target_files: list[str]
    layer1_evidence: list[ToolEvidence]
    layer1_passed: bool
    verdict: Verdict
    passed: bool
    summary: str
    arbitration_result: ArbitrationResult | None = None


class VerificationPipeline:
    """End-to-end verification pipeline composing Layer 1, Layer 2, and Arbiter."""

    def __init__(
        self,
        deterministic_verifier: DeterministicVerifier | None = None,
        adversarial_verifier: AdversarialVerifier | None = None,
        arbiter: Arbiter | None = None,
    ):
        self.deterministic_verifier = deterministic_verifier or DeterministicVerifier()
        self.adversarial_verifier = adversarial_verifier or AdversarialVerifier()
        self.arbiter = arbiter or Arbiter()

    def run(
        self,
        changed_files: list[str] | None = None,
        workspace: str | Path | Workspace | None = None,
        task_plan: str | None = None,
        backend: Backend = None,
        layer1_only: bool = False,
        test_names: list[str] | None = None,
        test_results: str | None = None,
        layer1_evidence: list[ToolEvidence] | None = None,
    ) -> VerificationPipelineResult:
        ws = as_workspace(workspace)
        files = changed_files
        if files is None:
            files = _working_changes(ws.root)

        wants_layer2 = bool(files) and not layer1_only
        if wants_layer2:
            # Validate Layer 2's inputs before spending any Layer 1 work on them.
            if not task_plan:
                raise ValueError("Layer 2 needs a task plan")
            _generate_fn(backend if backend is not None else self.adversarial_verifier.backend)

        # 1. Deterministic Layer 1
        if layer1_evidence is not None:
            l1_evidence = layer1_evidence
        else:
            l1_evidence = self.deterministic_verifier.verify(
                changed_files=files,
                workspace=ws,
            )
        l1_passed = runner.gate_verdict(l1_evidence)
        l1_summary = runner.format_summary(l1_evidence)

        if not wants_layer2:
            verdict = Verdict.SHIP if l1_passed else Verdict.BLOCK
            return VerificationPipelineResult(
                target_files=list(files),
                layer1_evidence=l1_evidence,
                layer1_passed=l1_passed,
                verdict=verdict,
                passed=bool(l1_passed),
                summary=l1_summary,
            )

        # 2. Layer 2 Adversarial Verification
        if (test_names is None or test_results is None) and files:
            try:
                from aegis_core.verification.test_runner import discover_test_evidence
                disc_names, disc_results = discover_test_evidence(
                    files, str(ws.root if hasattr(ws, "root") else ws)
                )
                if test_names is None:
                    test_names = disc_names
                if test_results is None:
                    test_results = disc_results
            except Exception:
                pass

        predictions, claims, spec_failed = self.adversarial_verifier.verify(
            changed_files=files,
            workspace=ws,
            task_plan=task_plan,
            layer1_evidence=l1_evidence,
            backend=backend,
            test_names=test_names,
            test_results=test_results,
        )

        arb_result = self.arbiter.arbitrate(
            predictions=predictions,
            claims=claims,
            layer1_evidence=l1_evidence,
            spec_agent_failed=spec_failed,
        )

        # T6 is log-only: the arbiter's verdict is reported, never gating.
        overall_passed = bool(l1_passed)
        layer2_label = arb_result.verdict.name if arb_result.infra_status == "ok" else "UNVERIFIED"
        summary = (
            f"{l1_summary} | Layer 2 (advisory): {layer2_label} "
            f"({len(arb_result.divergences)} divergences, {len(arb_result.convergences)} convergences)"
        )

        return VerificationPipelineResult(
            target_files=list(files),
            layer1_evidence=l1_evidence,
            layer1_passed=l1_passed,
            verdict=arb_result.verdict,
            passed=overall_passed,
            summary=summary,
            arbitration_result=arb_result,
        )


__all__ = [
    "AdversarialVerifier",
    "Arbiter",
    "Backend",
    "BaseVerifier",
    "DeterministicVerifier",
    "VerificationPipeline",
    "VerificationPipelineResult",
]
