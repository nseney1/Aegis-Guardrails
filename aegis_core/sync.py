"""``aegis sync``: the one writer of derived state (ADR 0005 AD-1, D1, D3)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

from aegis_core.fitness import for_rules
from aegis_core.rules import RuleSet, load_rules
from aegis_core.storage import atomic_write_text, locked, read_json_dict, state_dir
from aegis_core.telemetry_engine import ledger
from aegis_core.workspace import literal_workspace
from aegis_core.workspace.layout import WorkspaceLayout

__all__ = ["DERIVED_VERSION", "SyncResult", "build", "format_pr_body", "read_derived", "stale_rules", "sync"]
DERIVED_VERSION = 1


def _now_iso(now: Optional[datetime]) -> str:
    cur = now or datetime.now(timezone.utc)
    return (cur if cur.tzinfo else cur.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(workspace: Any, ruleset: Optional[RuleSet] = None, now: Optional[datetime] = None, view: Any = None) -> Dict[str, Any]:
    """The derived document for ``workspace`` (written by ``sync``)."""
    from aegis_core.lifecycle.promotion import suggest
    rules = ruleset if ruleset is not None else load_rules(workspace)
    view = view if view is not None else ledger.read(workspace)
    loaded = [r for r in rules.rules if r.ok]
    fits = for_rules(workspace, loaded, now, view=view)
    entries: Dict[str, Any] = {}
    for rule in loaded:
        fit = fits[rule.id]
        entry: Dict[str, Any] = {
            "path": rule.path, "sha256": rule.digest, "type": rule.type, "fitness": fit.score,
            "triggers": fit.triggers, "tp": fit.tp, "fp": fit.fp, "last_ts": fit.last_ts,
            "suggestion": None if not fit.evidence_available else suggest(rule, fit, now), "state": fit.state,
            "evidence_available": fit.evidence_available,
            "effective_weight": fit.effective_weight, "decay_factor": fit.decay_factor,
            "eligible_sessions": fit.eligible_sessions, "contested": fit.contested,
            "override_rate": fit.override_rate, "flagged_for_review": fit.flagged_for_review,
            "archive_candidate": fit.archive_candidate, "caught": fit.caught, "leaked": fit.leaked,
            "adjudicated_n": fit.adjudicated_n, "precision_lo": fit.precision_lo,
            "precision_hi": fit.precision_hi, "sessions_count": fit.sessions_count,
            "repos_count": fit.repos_count, "samples": list(fit.samples),
        }
        if fit.evidence_error:
            entry["evidence_error"] = fit.evidence_error
        if fit.prior_disclosure:
            entry["prior_disclosure"] = fit.prior_disclosure
        if rule.expired:
            entry["expired"] = True
        entries[rule.id] = entry
    return {
        "v": DERIVED_VERSION, "norm": "lf", "synced_at": _now_iso(now), "rules": entries,
        "errors": [{"path": r.path, "error": r.error} for r in rules.errors],
        "ignored": [{"path": i.path, "reason": i.reason} for i in rules.ignored],
        "untargeted": [{"id": r.id, "path": r.path} for r in sorted(rules.served, key=lambda r: r.id) if not r.target_paths],
        "ledger": view.health(),
    }


def read_derived(workspace: Any) -> Optional[Dict[str, Any]]:
    """The last derived document, or None when there is none or it cannot be used."""
    path = WorkspaceLayout(Path(literal_workspace(workspace).root)).derived_file
    doc = read_json_dict(path)
    if isinstance(doc, dict) and doc.get("v") == DERIVED_VERSION and isinstance(doc.get("rules"), dict):
        return doc
    return None


def stale_rules(ruleset: RuleSet, derived: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rules edited, added or removed since the last sync: ``[{id, path, change}]``."""
    if derived is None:
        return []
    recorded = derived.get("rules") or {}
    out, current, broken = [], set(), {}
    for rule in ruleset.rules:
        if not rule.ok:
            broken.setdefault(rule.id, rule)
            continue
        current.add(rule.id)
        entry = recorded.get(rule.id)
        if not isinstance(entry, dict):
            out.append({"id": rule.id, "path": rule.path, "change": "new"})
        elif entry.get("path") != rule.path or entry.get("sha256") != rule.digest:
            out.append({"id": rule.id, "path": rule.path, "change": "edited"})
    for rule_id in sorted(set(recorded) - current):
        if rule_id in broken:
            out.append({"id": rule_id, "path": broken[rule_id].path, "change": "unloadable", "error": broken[rule_id].error})
        else:
            entry = recorded[rule_id]
            out.append({"id": rule_id, "path": entry.get("path") if isinstance(entry, dict) else None, "change": "removed"})
    return out


@dataclass
class SyncResult:
    derived: Dict[str, Any]
    path: Path
    applied: List[Dict[str, Any]] = field(default_factory=list)
    refused: Optional[str] = None
    pr: Optional[Dict[str, Any]] = None


def _apply(workspace: Any, derived: Dict[str, Any]) -> List[Dict[str, Any]]:
    from aegis_core.lifecycle.promotion import demote_rule, promote_rule
    from aegis_core.lifecycle.selection import archive_rule
    actions = {
        "promote": lambda rid: promote_rule(workspace, rid, force=True),
        "demote": lambda rid: demote_rule(workspace, rid),
        "archive": lambda rid: archive_rule(workspace, rid),
    }
    applied = []
    for rule_id, entry in sorted(derived["rules"].items()):
        action = entry.get("suggestion")
        if action in actions:
            res = actions[action](rule_id)
            rec = {"rule": rule_id, "action": action, "status": res.get("status")}
            rec.update({k: res[k] for k in ("from_type", "to_type", "target_path", "message") if res.get(k) is not None})
            applied.append(rec)
    return applied


def format_pr_body(pre_rules: Dict[str, Dict[str, Any]], applied: List[Dict[str, Any]]) -> str:
    """Format the evidence-backed PR body for decided lifecycle transitions."""
    lines = [
        "## Aegis Rule Lifecycle Transitions", "",
        "Evidence-backed rule transitions generated by `aegis sync --pr` (human review required; never auto-merged).", "",
    ]
    for item in applied:
        rid, action = str(item.get("rule", "")), str(item.get("action", ""))
        from_t, to_t = item.get("from_type"), item.get("to_type")
        tier_str = f" (`{from_t}` -> `{to_t}`)" if from_t and to_t else (f" (from `{from_t}`)" if from_t else "")
        e = pre_rules.get(rid, {})
        tp, fp = e.get("tp", 0), e.get("fp", 0)
        lines.extend([
            f"### `{rid}` — **{action}**{tier_str}",
            f"- **Sample size ($n$)**: {tp + fp:g} (TP={tp:g}, FP={fp:g})",
            f"- **Precision 90% CI**: [{e.get('precision_lo', 0.0):.2f}, {e.get('precision_hi', 1.0):.2f}] (Wilson lower bound: {e.get('fitness', 0.0):.2f})",
            f"- **Breadth**: {e.get('sessions_count', 0)} session(s), {e.get('repos_count', 0)} repo(s)",
            f"- **Contested overrides**: {e.get('contested', 0)} (override rate: {e.get('override_rate', 0.0):.1%})",
        ])
        if e.get("prior_disclosure"):
            lines.append(f"- **Prior disclosure**: {e['prior_disclosure']}")
        samples = list(e.get("samples") or [])[:3]
        if samples:
            lines.append("- **Sampled examples (up to 3)**:")
            for idx, s in enumerate(samples, start=1):
                ref = s.get("ref") or s.get("rev") or f"sample-{idx}"
                loc = s.get("file") or ""
                if s.get("line"):
                    loc = f"{loc}:{s['line']}" if loc else f"line {s['line']}"
                summary = s.get("summary") or s.get("pattern") or s.get("verdict") or ""
                lines.append(f"  {idx}. [{ref}]{f' (`{loc}`)' if loc else ''}: {summary}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _default_gh_runner(argv: List[str], cwd: Optional[str] = None) -> Any:
    from aegis_core.human_gate import default_gh_runner
    res = default_gh_runner(argv, None, cwd)
    return res if res is not None else SimpleNamespace(returncode=127, stdout="", stderr="gh is not installed")


def sync(
    workspace: Any, apply: bool = False, now: Optional[datetime] = None, *,
    pr: bool = False, gh_runner: Optional[Callable[..., Any]] = None,
    ci_client: Any = None, workflow: str = "validate.yml",
) -> SyncResult:
    """Rebuild derived state under the workspace lock; optionally apply transitions or open a PR."""
    from aegis_core import credit
    from aegis_core.fitness import replay_detector_history
    ws = literal_workspace(workspace)
    path = WorkspaceLayout(ws.root).derived_file
    should_apply = bool(apply or pr)
    pr_info: Optional[Dict[str, Any]] = None
    with locked(ws.root):
        ruleset = load_rules(ws)
        loaded_ok = [r for r in ruleset.rules if r.ok]
        try:
            replay_detector_history(ws.root, loaded_ok)
        except (OSError, ValueError):
            pass
        if ci_client is not None or any(r.get("event") == "report" for r in credit.read_rows(ws.root)):
            credit.confirm(
                ws.root,
                client=ci_client if ci_client is not None else credit.GhRestClient(cwd=str(ws.root)),
                workflow=workflow,
            )
        derived = build(ws, ruleset, now, ledger.read(ws))
        missing = ledger.incomplete(derived["ledger"])
        applied, refused = [], None
        pre_rules = {rid: dict(entry) for rid, entry in derived["rules"].items()}
        if should_apply and ruleset.errors:
            refused = "not applied: rule files cannot be loaded: " + ", ".join(r.path for r in ruleset.errors)
        elif should_apply and missing:
            refused = f"not applied: the ledger is incomplete ({missing}); fitness and suggestions are computed over partial evidence"
        elif should_apply:
            applied = _apply(ws, derived)
            if applied:
                derived = build(ws, load_rules(ws), now)
        state_dir(ws.root)
        atomic_write_text(path, json.dumps(derived, indent=2, sort_keys=True) + "\n")
    if pr:
        if refused:
            pr_info = {"status": "refused", "url": None, "reason": refused, "transitions": []}
        elif not applied:
            pr_info = {"status": "no_transitions", "url": None, "body": "", "transitions": []}
        else:
            title_rules = ", ".join(a["rule"] for a in applied[:3]) + (f" (+{len(applied) - 3} more)" if len(applied) > 3 else "")
            title, body = f"chore(aegis): lifecycle transitions for {title_rules}", format_pr_body(pre_rules, applied)
            res = (gh_runner or _default_gh_runner)(["pr", "create", "--title", title, "--body", body], cwd=str(ws.root))
            rc = getattr(res, "returncode", 0)
            raw_out, raw_err = getattr(res, "stdout", ""), getattr(res, "stderr", "")
            out_s = (raw_out.decode("utf-8", "replace") if isinstance(raw_out, bytes) else str(raw_out or "")).strip()
            err_s = (raw_err.decode("utf-8", "replace") if isinstance(raw_err, bytes) else str(raw_err or "")).strip()
            if rc == 0:
                pr_info = {"status": "opened", "url": out_s or None, "title": title, "body": body, "transitions": applied}
            else:
                pr_info = {"status": "failed", "url": None, "title": title, "body": body, "error": err_s or f"gh exited with status {rc}", "transitions": applied}
    return SyncResult(derived=derived, path=path, applied=applied, refused=refused, pr=pr_info)

