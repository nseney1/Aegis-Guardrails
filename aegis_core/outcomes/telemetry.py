"""Ambient verification telemetry: `aegis check` records rule triggers in the ledger, never verdicts (spec T1)."""
from __future__ import annotations

import secrets
import sys
from typing import Any, Optional

from aegis_core.workspace import literal_workspace

__all__ = ["record_verification_telemetry"]


def record_verification_telemetry(
    workspace: str,
    target_files: list[str],
    passed: bool,
    verdict: Any = None,
    layer1_evidence: Any = None,
    source: str = "session",
    run_id: Optional[str] = None,
) -> bool:
    """Append one trigger row per matched rule to the ledger. An unwitnessed local run is not a verdict:
    whether it passed is kept in ``meta`` and moves no tp/fp."""
    if not workspace or not target_files:
        return False

    ws = literal_workspace(workspace)
    if not ws.rules_dir.is_dir():
        return False

    from aegis_core.match import split_credit
    from aegis_core.outcomes.engine import matched_rules

    matched = matched_rules(ws, target_files)
    if not matched:
        return False

    from aegis_core.telemetry_engine import ledger

    if run_id is None:
        run_id = secrets.token_hex(16)

    # Each file's credit is shared by the rules that apply to it (Rule.applies_to).
    weights = split_credit({rule.id: files for rule, files in matched})
    verdict_text = str(verdict) if verdict is not None else ("PASS" if passed else "FAIL")
    events = []
    for rule, _files in matched:
        rule_id = rule.id
        weight = max(0.0, min(1.0, float(weights.get(rule_id, 0.0))))
        events.append({
            "rule": rule_id,
            "outcome": "trigger",
            "source": source,
            "key": run_id,
            "weight": weight,
            "meta": {
                "verdict": verdict_text,
                "passed": passed,
                "evidence_checks": len(layer1_evidence) if layer1_evidence else 0,
                "target_files": target_files[:20],
            },
        })

    # Ledger only: rule files are never rewritten at runtime (ADR 0005 AD-1/H6). Bumping
    # frontmatter here dirtied tracked .aegis/rules on every `aegis check --hook` and
    # broke the committed manifest.
    try:
        ledger.append(ws.root, events)
        return True
    except Exception as exc:
        print(f"    ! failed to record ambient verification telemetry: {exc}", file=sys.stderr)
        return False
