"""One head/base execution pair per native language, with namespaced judgments."""
from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
import tempfile
import time
from typing import Callable, Mapping, Sequence

from aegis_core import gitsafe
from aegis_core.testplans import language_settings
from aegis_core.verification.language_tests import run_language_snapshot
from aegis_core.verification.regression_identity import NativeSelection, prepare_native_selection
from aegis_core.verification.test_outcomes import RunOutcome, TestId

UNVERIFIED_CODES = frozenset({"tests_runner_not_configured", "tests_runner_unsupported", "tests_inline_with_source",
    "deps_unavailable", "test_ids_unmapped", "incomplete_test_output", "conflicting_test_results", "no_driver"})


@dataclass(frozen=True)
class NativeRuns:
    selection: NativeSelection
    head: RunOutcome | None = None
    base: RunOutcome | None = None


def _errors(*outcomes: RunOutcome) -> str | None:
    for field, reason in (("mapping_errors", "test_ids_unmapped"), ("conflict_errors", "conflicting_test_results"),
                          ("build_errors", "deps_unavailable"), ("incomplete_errors", "incomplete_test_output")):
        if any(getattr(outcome, field) for outcome in outcomes):
            return reason
    return None


def judge_native(selection: NativeSelection, files: Sequence[str], head: RunOutcome | None,
                 base: RunOutcome | None) -> tuple[str, tuple[TestId, ...]]:
    """Only identical owned base-failed/head-passed identities prove a transition."""
    if not selection.plan.available:
        return selection.plan.reason, ()
    if head is None or base is None:
        return "no_tests_collected", ()
    if head.timed_out or base.timed_out:
        return "timeout", ()
    error = _errors(head, base)
    if error:
        return error, ()
    if head.failed_ids or head.collection_errors or head.exit_code:
        return "failed_on_head", ()
    passed = {identity for identity in head.passed_ids if any(selection.belongs(identity, file) for file in files)}
    transitioned = tuple(sorted(passed & base.failed_ids))
    if transitioned and head.evidence:
        return "ok", transitioned
    if base.collection_errors:
        return "deps_unavailable", ()
    return ("passed_on_base" if passed else "no_tests_collected"), ()


def outcome_dict(outcome: RunOutcome | None):
    """Retain every structured result field; tuple identities remain JSON arrays."""
    if outcome is None:
        return None
    result = {}
    for field in fields(outcome):
        value = getattr(outcome, field.name)
        result[field.name] = [list(v) if isinstance(v, tuple) else v for v in sorted(value)] if isinstance(value, frozenset) else value
    return result


def language_evidence(runs: NativeRuns, files: Sequence[str]) -> dict:
    reason, transitions = judge_native(runs.selection, files, runs.head, runs.base)
    language = runs.selection.plan.language
    return {"language": language, "witness": "repo-runner" if language == "ts" else "aegis", "reason": reason,
            "files": list(files), "fail_to_pass_tests": [list(identity) for identity in transitions],
            "detail": runs.selection.plan.detail, "head": outcome_dict(runs.head), "base": outcome_dict(runs.base)}


def run_native_regressions(root: str, workspace: Path, merge_commit: str, head_commit: str,
                           groups: Mapping[str, Sequence[str]], progress: Callable[[str], None],
                           *, timeout: float | None = None) -> dict[str, NativeRuns]:
    """Prepare each language once, then run its head and base with head tests overlaid."""
    budgets = {}
    for language in groups:
        try:
            budgets[language] = language_settings(workspace, language).timeout_s
        except ValueError:
            budgets[language] = 300.0 if language != "rust" else 900.0
    deadline = time.monotonic() + 2 * sum(min(value, timeout) if timeout is not None else value for value in budgets.values())
    result = {}
    entries = gitsafe.tree_blobs(root, head_commit)
    for language, tests in groups.items():
        present = sorted({file for file in tests if file in entries})
        with tempfile.TemporaryDirectory(prefix="aegis-regression-" + language + "-") as directory:
            scratch = Path(directory)
            head_snapshot = scratch / "head"
            gitsafe.export_tree(root, head_commit, head_snapshot)
            selection = prepare_native_selection(workspace, head_snapshot, language, present,
                                                 scratch=scratch / "selection", deadline=deadline)
            if not selection.plan.available:
                result[language] = NativeRuns(selection)
                continue
            blobs = gitsafe.read_blobs(root, (entries[file][1] for file in selection.plan.files))
            overlay = {file: blobs[entries[file][1]] for file in selection.plan.files}
            outcomes = []
            for name, commit, layer in (("head", head_commit, None), ("base", merge_commit, overlay)):
                snapshot = scratch / name
                if name == "base":
                    gitsafe.export_tree(root, commit, snapshot, overlay=layer)
                progress(f"Regression tests: {language} on {name} {commit[:10]} ({len(selection.plan.files)} test file(s))")
                outcomes.append(run_language_snapshot(selection.plan, snapshot, workspace, scratch / (name + "-run"), deadline=deadline))
            result[language] = NativeRuns(selection, *outcomes)
    return result
