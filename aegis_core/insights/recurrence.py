"""Insight recurrence: how many alive sessions saw a correction a rule should prevent, after its
current revision, with a 95% upper bound and the episodes the alarm counts."""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from aegis_core.insights.keys import COUNTABLE_LEVELS, read_insight_rows
from aegis_core.insights.review import (
    _confirmed,
    _cosine,
    _effective_level,
    _paths_overlap_rule,
    _superseded,
    _tfidf_vectors,
    _tokenize,
)
from aegis_core.primitives import parse_utc
from aegis_core.workspace.layout import WorkspaceLayout

if TYPE_CHECKING:
    # For annotations only: the rule parser is imported where recurrence needs it, never at load.
    from aegis_core.rules import Rule

__all__ = [
    "RECURRENCE_DENOMINATOR",
    "RECURRENCE_SIM",
    "insight_born_rules",
    "insight_status",
    "insight_status_lines",
    "measure_recurrence",
]

RECURRENCE_ALARM_COUNT = 3
# In-scope filtering needs the MCP and hook sessions to join (v4.5); until then the rate's
# denominator is every alive session, and every recurrence line says so.
RECURRENCE_DENOMINATOR = "sessions = all heartbeat-alive sessions in this workspace (not scope-filtered)"
BURST_WINDOW_SECONDS = 300
# The TF-IDF cosine at which a counted insight recurs for a rule: hand-set in 4.3 with review's
# RULE_MATCH_SIM thresholds, not measured.
RECURRENCE_SIM = 0.12


def _wilson_ucb95(k: int, n: int) -> float:
    if n <= 0:
        return 1.0
    z = 1.6448536269514722
    phat = min(1.0, max(0.0, k / n))
    z2 = 2.705543454095404
    num = (phat + z2 / (2.0 * n)) + z * math.sqrt((phat * (1.0 - phat) + z2 / (4.0 * n)) / n)
    return min(1.0, round(num / (1.0 + z2 / n), 6))


def _count_recurrence_episodes(matching: Sequence[Mapping[str, Any]]) -> int:
    """Insights closer than BURST_WINDOW_SECONDS to the one before are one episode."""
    stamps = sorted(ts for ts in (parse_utc(r.get("ts")) for r in matching) if ts is not None)
    gaps = sum(1 for a, b in zip(stamps, stamps[1:]) if (b - a).total_seconds() > BURST_WINDOW_SECONDS)
    return len(matching) - len(stamps) + (gaps + 1 if stamps else 0)


def _session_rates(alive: Set[str], matching: Sequence[Mapping[str, Any]]) -> Tuple[int, int]:
    """(alive sessions with a recurrence, episodes inside alive sessions)."""
    by_session: Dict[str, List[Mapping[str, Any]]] = {}
    for ins in matching:
        if ins.get("hs") in alive:
            by_session.setdefault(str(ins["hs"]), []).append(ins)
    return len(by_session), sum(_count_recurrence_episodes(rows) for rows in by_session.values())


def _measure(rule: Rule, rows: Sequence[Mapping[str, Any]], confirmed: Set[str]) -> Dict[str, Any]:
    cur_rev = rule.digest[:16]
    rule_tokens = _tokenize(f"{rule.id} {rule.meta.get('hypothesis', '')} {rule.body}")
    burst = {str(i) for i in rule.meta.get("insight_ids") or [] if isinstance(i, (str, int))}
    inv_revs = {
        r["inv"]: r["revs"] for r in rows
        if r.get("event") == "inventory" and isinstance(r.get("inv"), str) and isinstance(r.get("revs"), Mapping)
    }
    # The window opens at the first row that names the rule's current rev (its first inventory
    # row); the baseline is the same measurement over the sessions before it.
    window_open = False
    superseded = _superseded(rows)
    # One TF-IDF corpus: every counted insight and the rule, as review weighs them.
    counted = [r for r in rows if r.get("event") == "insight" and id(r) not in superseded
               and _effective_level(r, confirmed) in COUNTABLE_LEVELS]
    vecs = _tfidf_vectors([_tokenize(str(r.get("text") or "")) for r in counted] + [rule_tokens])
    similarity = {id(r): _cosine(v, vecs[-1]) for r, v in zip(counted, vecs)}
    alive: Set[str] = set()
    before: Set[str] = set()
    unidentified_heartbeats = 0
    matching: List[Mapping[str, Any]] = []
    earlier: List[Mapping[str, Any]] = []
    for row in rows:
        # A new heartbeat names its rule set by `inv`; an old one carries its own revs.
        revs = row.get("revs")
        if not isinstance(revs, Mapping):
            revs = inv_revs.get(row["inv"], {}) if isinstance(row.get("inv"), str) else {}
        in_rev = revs.get(rule.id) == cur_rev
        window_open = window_open or in_rev
        if window_open and not in_rev:
            continue
        ev, hs_val = row.get("event"), row.get("hs")
        if ev == "heartbeat":
            if isinstance(hs_val, str) and hs_val.strip():
                (alive if window_open else before).add(hs_val)
            elif window_open:
                unidentified_heartbeats += 1
        elif similarity.get(id(row), 0.0) >= RECURRENCE_SIM and _paths_overlap_rule(row.get("paths") or [], rule):
            if window_open:
                matching.append(row)
            elif str(row.get("id") or "") not in burst:
                earlier.append(row)
    recurrent, episodes = _session_rates(alive, matching)
    unattributed = _count_recurrence_episodes([r for r in matching if not r.get("hs")])
    base_recurrent, _ = _session_rates(before, earlier)
    n_sess = len(alive)
    if n_sess:
        status = "not_working" if episodes >= RECURRENCE_ALARM_COUNT else "ok"
    elif unidentified_heartbeats or matching:
        status = "insufficient_session_identity"
    else:
        status = "no_prompt_traffic"
    return {
        "rule": rule.id, "rev": cur_rev, "sessions": n_sess, "unidentified_heartbeats": unidentified_heartbeats,
        "recurrences": episodes, "recurrent_sessions": recurrent, "unattributed_recurrences": unattributed,
        "rate": round(recurrent / n_sess, 6) if n_sess else 0.0, "rate_ucb95": _wilson_ucb95(recurrent, n_sess),
        "alarm": bool(n_sess) and episodes >= RECURRENCE_ALARM_COUNT, "status": status,
        "baseline_rate": round(base_recurrent / len(before), 6) if before else None,
        "baseline_sessions": len(before), "denominator": RECURRENCE_DENOMINATOR,
    }


def measure_recurrence(
    workspace: Any,
    rule_id: str,
    *,
    home: Optional[Path] = None,
) -> Dict[str, Any]:
    """Alive sessions with a matching human insight over all alive sessions (at most 1), its 95%
    upper bound, and the episodes the alarm counts."""
    from aegis_core.rules import load_rules

    root = Path(os.fspath(workspace)).resolve()
    rule = load_rules(root).get(rule_id)
    if rule is None:
        raise ValueError(f"unknown rule {rule_id!r}")
    rows = read_insight_rows(root, home=home)
    return _measure(rule, rows, set(_confirmed(rows)))


def insight_born_rules(workspace: Any) -> List[Rule]:
    """The served rules whose frontmatter names the insights they came from."""
    from aegis_core.rules import load_rules

    root = Path(os.fspath(workspace)).resolve()
    try:
        served = load_rules(root).served if WorkspaceLayout(root).rules_dir.is_dir() else ()
    except Exception:  # a display surface: an unloadable rule set has no insight-born rules to show
        return []
    return [r for r in served if isinstance(r.meta.get("insight_ids"), list) and r.meta["insight_ids"]]


def insight_status(workspace: Any, *, home: Optional[Path] = None) -> Dict[str, Any]:
    """What ``aegis status`` and ``aegis sync`` say about insights; {} without an insights log."""
    rows = read_insight_rows(workspace, home=home)
    if not rows:
        return {}
    confirmed = set(_confirmed(rows))
    return {
        "rules": [_measure(rule, rows, confirmed) for rule in insight_born_rules(workspace)],
        "unconfirmed_suggestions": sum(1 for r in rows if r.get("event") == "insight"
                                       and _effective_level(r, confirmed) == "suggestion"),
        "denominator": RECURRENCE_DENOMINATOR,
    }


def insight_status_lines(summary: Mapping[str, Any]) -> List[str]:
    lines = [
        f"recurrence {r['rule']}: {r['status']}, rate {r['rate']:.2f} ({r['recurrent_sessions']}/{r['sessions']} "
        f"sessions), 95% bound {r['rate_ucb95']:.2f}; {summary['denominator']}"
        for r in summary.get("rules") or ()
    ]
    if summary.get("unconfirmed_suggestions"):
        lines.append(f"{summary['unconfirmed_suggestions']} unconfirmed agent suggestions (not counted)")
    return lines
