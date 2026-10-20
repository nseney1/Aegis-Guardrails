"""Adjudication labels: git content at the reviewed BASE (v4.3 spec T4; decision D-adjudicate).

``aegis rule adjudicate`` appends a label to ``.aegis/adjudications/<rule-id>.jsonl`` in the
working tree. The file is in the governance set, so it reaches the base branch only through an
approved merge, and a label counts only when read there: at the T3 BASE of ``rule_integrity``,
and only when that anchor is review-witnessed. The working tree, a feature branch, a local HEAD
and ledger ``adjudication`` rows (any writer can append one) count nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from aegis_core import gitsafe, rule_integrity
from aegis_core.rules import workspace_root
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = ["ADJUDICATIONS_DIR", "Adjudications", "RULE_ID", "read_adjudications"]

ADJUDICATIONS_DIR = f"{AEGIS_DIRNAME}/adjudications"
RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
MAX_ROW_BYTES, MAX_ROWS = 64 * 1024, 2000
_TEXT_FIELDS = ("session", "repo", "ts", "file", "summary", "ref")
_MEMO: Dict[Tuple[str, str], "Adjudications"] = {}
_MEMO_CAP = 64


@dataclass(frozen=True)
class Adjudications:
    """Labels per rule id read at ``base``; ``reason`` says why none could be read."""

    by_rule: Mapping[str, Tuple[Dict[str, Any], ...]] = field(default_factory=dict)
    base: Optional[str] = None
    reason: Optional[str] = None
    unusable: int = 0


def _labels(data: bytes) -> Tuple[List[Dict[str, Any]], int]:
    lines = [line for line in data.split(b"\n") if line.strip()]
    if len(lines) > MAX_ROWS:
        return [], len(lines)
    latest: Dict[str, Dict[str, Any]] = {}
    unusable = 0
    for line in lines:
        try:
            row = json.loads(line.decode("utf-8-sig")) if len(line) <= MAX_ROW_BYTES else None
        except (UnicodeDecodeError, ValueError, RecursionError):
            row = None
        example = row.get("example_id") if isinstance(row, dict) else None
        if not isinstance(example, str) or not example or row.get("verdict") not in ("tp", "fp"):
            unusable += 1
            continue
        label = {"example_id": example, "verdict": row["verdict"]}
        label.update({k: row[k] for k in _TEXT_FIELDS if isinstance(row.get(k), str)})
        if type(row.get("line")) is int:
            label["line"] = row["line"]
        # The last row per example wins: a later merged row corrects a label.
        latest.pop(example, None)
        latest[example] = label
    return list(latest.values()), unusable


def _read_at(ws: str, commit: str) -> Adjudications:
    prefix = gitsafe.show_prefix(ws)
    entries = gitsafe.tree_blobs(ws, commit, paths=(prefix + ADJUDICATIONS_DIR,))
    wanted: Dict[str, str] = {}
    unusable = 0
    for path, (mode, oid) in entries.items():
        rel = gitsafe.relative_to_prefix(prefix, path) or ""
        name = rel[len(ADJUDICATIONS_DIR) + 1:] if rel.startswith(ADJUDICATIONS_DIR + "/") else ""
        rule_id = name[:-len(".jsonl")] if name.endswith(".jsonl") else ""
        if mode in ("100644", "100755") and RULE_ID.fullmatch(rule_id):
            wanted[rule_id] = oid
        else:
            unusable += 1
    blobs = gitsafe.read_blobs(ws, wanted.values()) if wanted else {}
    by_rule: Dict[str, Tuple[Dict[str, Any], ...]] = {}
    for rule_id, oid in sorted(wanted.items()):
        labels, bad = _labels(blobs.get(oid, b""))
        unusable += bad
        if labels:
            by_rule[rule_id] = tuple(labels)
    return Adjudications(by_rule, commit, None, unusable)


def read_adjudications(root: Any, *, anchor: Optional[rule_integrity.BaseAnchor] = None) -> Adjudications:
    """The labels merged at the reviewed BASE of ``root`` (``anchor``, default
    ``rule_integrity.resolve_base``). Fails closed: no base, an unwitnessed one or a git error
    gives no labels and a reason. Memoized per (workspace, base commit)."""
    ws = workspace_root(root)
    try:
        base = anchor if anchor is not None else rule_integrity.resolve_base(ws)
        if base is None:
            return Adjudications(reason="no reviewed base: labels count only once merged to the base branch")
        if not base.witnessed:
            return Adjudications(base=base.commit, reason=f"the base is {base.label}: labels count only at a reviewed base")
        key = (os.path.realpath(ws), base.commit)
        if key not in _MEMO:
            if len(_MEMO) >= _MEMO_CAP:
                _MEMO.pop(next(iter(_MEMO)))
            _MEMO[key] = _read_at(ws, base.commit)
        return _MEMO[key]
    except (gitsafe.GitError, rule_integrity.IntegrityError, OSError) as exc:
        return Adjudications(reason=f"labels unreadable at the base: {str(exc)[:200]}")
