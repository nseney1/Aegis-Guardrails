"""The workspace checkpoint inside `aegis check`: repo-wide deterministic checks.

The checks live in aegis_core.verification.checkpoint_checks: a test file per
source file, hardcoded absolute paths, per-test assertions (AST), rule fitness
from the ledger, rule conventions, and gate/invariant rules that do not use
`gate` enforcement ("paper gates").

Issues are warnings unless --strict. Two always block: a paper gate (a rule that
claims to be a gate but enforces nothing) and a rule file that cannot be loaded
(aegis scan refuses to serve the rule set while it exists).
"""
from __future__ import annotations

from pathlib import Path

from aegis_core.verification.checkpoint_checks import run_all_checks

__all__ = ["GATE_CHECKS", "is_blocking", "run_checkpoint"]

GATE_CHECKS = frozenset({"paper_gates", "rule_load"})


def is_blocking(issue: dict, strict: bool) -> bool:
    return strict or issue.get("check") in GATE_CHECKS


def run_checkpoint(root: Path, *, strict: bool, pairing_info: list[dict] | None = None) -> tuple[list[dict], bool]:
    """Return (issues, blocking); successful pairing information never affects either."""
    issues = run_all_checks(root, pairing_info=pairing_info)
    return issues, any(is_blocking(issue, strict) for issue in issues)
