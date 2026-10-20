"""Rule fitness, computed at read time from the outcome ledger (ADR 0005 H6, AD-1; v4.3 T4)."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import math
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import stats as _stats
from aegis_core.stats import (
    _betacf,
    _num,
    beta_cdf,
    beta_ppf,
    clopper_pearson_interval,
    clopper_pearson_lower,
    clopper_pearson_upper,
    regularized_incomplete_beta,
)
from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL, WILSON_CONFIDENCE_Z_SCORES

__all__ = [
    "DEFAULT_ARCHIVE_EPSILON",
    "DEFAULT_HALF_LIFE_SESSIONS",
    "DEFAULT_MIN_N",
    "Fitness",
    "MAX_PRIOR_MASS",
    "MDE_UNTESTABLE_THRESHOLD",
    "MIN_N",
    "beta_cdf",
    "beta_ppf",
    "cap_prior",
    "clopper_pearson_interval",
    "clopper_pearson_lower",
    "clopper_pearson_upper",
    "compute",
    "compute_mde_180d",
    "compute_silence_credit",
    "decay_factor",
    "for_rules",
    "regularized_incomplete_beta",
    "replay_detector_history",
    "session_decay_factor",
    "wilson_interval",
    "wilson_lower_bound",
]

Z = WILSON_CONFIDENCE_Z_SCORES[DEFAULT_CONFIDENCE_LEVEL]
MAX_PRIOR_MASS = 10.0
# One minimum-sample gate (spec T4, section 9): below it no number is shown and no transition is suggested.
MIN_N = 25
DEFAULT_MIN_N = MIN_N
DEFAULT_HALF_LIFE_SESSIONS = 20
DEFAULT_ARCHIVE_EPSILON = 0.15
DEFAULT_MDE_HORIZON_DAYS = 180.0
MDE_UNTESTABLE_THRESHOLD = 0.6
_VIOLATION_PATTERN_RE = re.compile(r"Forbidden (?:call|import|decorator) '([^']+)'")
_MERGE_BRANCH_RE = re.compile(r"Merge branch '([^']+)'")


def wilson_interval(successes: float, n: float, z: float = Z) -> Tuple[float, float]:
    return _stats.wilson_interval(successes, n, z)


def wilson_lower_bound(successes: float, n: float, z: float = Z) -> float:
    return _stats.wilson_lower_bound(successes, n, z)


def cap_prior(alpha0: float, beta0: float, max_mass: float = MAX_PRIOR_MASS) -> Tuple[float, float]:
    a = max(0.0, float(alpha0))
    b = max(0.0, float(beta0))
    mass = a + b
    if mass > max_mass and mass > 0.0:
        scale = max_mass / mass
        return (a * scale, b * scale)
    return (a, b)


def compute_mde_180d(trigger_rate_per_day: float, horizon_days: float = DEFAULT_MDE_HORIZON_DAYS) -> float:
    expected_n = _num(trigger_rate_per_day) * _num(horizon_days)
    if expected_n <= 0.0:
        return 1.0
    return min(1.0, 1.24324 / math.sqrt(expected_n))


def compute_silence_credit(
    rrr: float,
    *,
    c: float = 0.1,
    heartbeat_alive: bool = True,
    scope_basis: Optional[str] = None,
    clean_sessions: int = 1,
) -> float:
    if not heartbeat_alive or scope_basis == "fallback_unscoped":
        return 1.0
    r = _num(rrr)
    k = max(0, int(clean_sessions))
    if r <= 0.0 or k == 0:
        return 1.0
    return math.exp(float(c) * r * k)


def _parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def decay_factor(last_ts: Optional[str], half_life_days: Optional[float], now: Optional[datetime] = None) -> float:
    last = _parse_ts(last_ts) if half_life_days and half_life_days > 0 else None
    if last is None:
        return 1.0
    current = now or datetime.now(timezone.utc)
    days = ((current if current.tzinfo is not None else current.replace(tzinfo=timezone.utc)) - last).total_seconds() / 86400.0
    return 1.0 if days <= 0 else 0.5 ** (days / float(half_life_days))


def session_decay_factor(eligible_sessions: int, half_life_sessions: Optional[float] = DEFAULT_HALF_LIFE_SESSIONS) -> float:
    return 1.0 if (eligible_sessions <= 0 or not half_life_sessions or half_life_sessions <= 0) else float(2.0 ** (-float(eligible_sessions) / float(half_life_sessions)))


@dataclass(frozen=True)
class Fitness:
    rule: str = ""
    triggers: int = 0
    tp: float = 0
    fp: float = 0
    last_ts: Optional[str] = None
    score: float = 0.0
    misfire: float = 0.0
    state: str = "insufficient"
    adjudicated_n: int = 0
    adjudicated_tp: int = 0
    adjudicated_fp: int = 0
    caught: int = 0
    leaked: int = 0
    contested: int = 0
    override_rate: float = 0.0
    flagged_for_review: bool = False
    precision_lo: float = 0.0
    precision_hi: float = 1.0
    p_below_demote: float = 0.0
    prior_mass: float = 0.0
    prior_share: float = 0.0
    prior_disclosure: Optional[str] = None
    mde: Optional[float] = None
    eligible_sessions: int = 0
    decay_factor: float = 1.0
    effective_weight: float = 1.0
    archive_candidate: bool = False
    silence_lr: float = 1.0
    sessions_count: int = 0
    repos_count: int = 0
    days_span: float = 0.0
    samples: Tuple[Dict[str, Any], ...] = ()
    suggestion: Optional[str] = None
    evidence_available: bool = True
    evidence_error: Optional[str] = None
    min_n: int = MIN_N

    @property
    def verdicts(self) -> float:
        return self.tp + self.fp

    @property
    def has_min_n(self) -> bool:
        return self.verdicts >= self.min_n

    @property
    def reported_score(self) -> Optional[float]:
        """The number surfaces may show: None until a sample is large enough to mean something."""
        if not self.evidence_available or not self.verdicts or self.state in ("insufficient", "untestable", "evidence_unavailable"):
            return None
        return self.score

    @property
    def status_label(self) -> Optional[str]:
        if not self.evidence_available:
            return "evidence unavailable"
        n = self.adjudicated_n if self.adjudicated_n > 0 else int(self.verdicts)
        if self.state == "untestable":
            return "untestable (insufficient trigger volume)"
        return f"insufficient (n={n})" if self.state == "insufficient" else None

    def as_dict(self) -> Dict[str, Any]:
        return {"triggers": self.triggers, "tp": self.tp, "fp": self.fp, "last_ts": self.last_ts, "score": self.score,
                "reported_score": self.reported_score, "status": self.status_label}


def compute(
    totals: Mapping[str, Any], half_life_days: Optional[float] = None, now: Optional[datetime] = None,
    rule: str = "", *, prior: Optional[Tuple[float, float]] = None, trigger_rate_per_day: Optional[float] = None,
    min_n: int = DEFAULT_MIN_N, eligible_sessions: int = 0, half_life_sessions: Optional[float] = None,
    epsilon: float = DEFAULT_ARCHIVE_EPSILON, rule_type: str = "trap", pinned: bool = False, contested: int = 0,
    caught: int = 0, leaked: int = 0, adjudicated_tp: int = 0, adjudicated_fp: int = 0, sessions_count: int = 0,
    repos_count: int = 0, days_span: float = 0.0, samples: Sequence[Mapping[str, Any]] = (), silence_lr: float = 1.0,
    evidence_available: bool = True, evidence_error: Optional[str] = None,
) -> Fitness:
    base_tp, base_fp = _num(totals.get("tp", 0) or 0), _num(totals.get("fp", 0) or 0)
    adj_n = int(adjudicated_tp) + int(adjudicated_fp)
    tp, fp = base_tp + float(adjudicated_tp) + 0.5 * float(caught), base_fp + float(adjudicated_fp) + 1.0 * float(leaked)
    if tp == int(tp) and isinstance(totals.get("tp", 0), int) and caught % 2 == 0:
        tp = int(tp)
    if fp == int(fp) and isinstance(totals.get("fp", 0), int):
        fp = int(fp)
    n, triggers = _num(tp) + _num(fp), int(_num(totals.get("triggers", 0))) + adj_n + int(caught) + int(leaked)
    a0, b0 = cap_prior(prior[0], prior[1]) if prior is not None else (0.0, 0.0)
    prior_mass = a0 + b0
    prior_share = (prior_mass / (prior_mass + n)) if (prior_mass + n) > 0.0 else 0.0
    prior_disclosure = f"prior supplies {int(round(prior_share * 100))}% of the evidence" if prior_mass > 0.0 else None
    mde = round(compute_mde_180d(trigger_rate_per_day), 4) if trigger_rate_per_day is not None else None
    time_decay = decay_factor(totals.get("last_ts"), half_life_days, now)
    sess_decay = session_decay_factor(eligible_sessions, half_life_sessions) if half_life_sessions is not None and eligible_sessions > 0 else 1.0
    combined_decay = sess_decay if eligible_sessions > 0 else time_decay
    effective_weight = round(1.0 * combined_decay, 6)
    score = round(wilson_lower_bound(_num(tp) + a0, n + prior_mass) * combined_decay, 4) if n > 0 else 0.0
    misfire = round(wilson_lower_bound(_num(fp), n), 4) if n > 0 else 0.0
    cp_lo, cp_hi = clopper_pearson_interval(tp, n, alpha=0.10, prior=prior)
    p_below_07 = beta_cdf(0.7, 1.0 + _num(tp) + a0, 1.0 + _num(fp) + b0) if n > 0 else 0.0
    override_rate = round(float(contested) / float(max(1, int(contested) + int(triggers))), 4) if contested > 0 else 0.0
    flagged_for_review = bool(contested > 0 and (contested >= 3 or override_rate >= 0.25))
    archive_candidate = bool(rule_type == "trap" and not pinned and eligible_sessions > 0 and effective_weight < epsilon)
    enough_n = n >= min_n
    demote_ready = bool(enough_n and (misfire > 0.5 or p_below_07 >= 0.9 or cp_hi < 0.7))
    if adj_n > 0:
        enough_pos = (adjudicated_tp >= 25 and adjudicated_fp == 0) or (adj_n >= 42 and adjudicated_fp <= 1 and cp_lo >= 0.88)
        enough_div = (sessions_count == 0 or sessions_count >= 3) and (repos_count >= 2 or days_span >= 14.0 or (repos_count == 0 and days_span == 0.0))
        promote_ready = bool(enough_n and rule_type == "trap" and enough_pos and enough_div)
    else:
        promote_ready = bool(enough_n and rule_type == "trap" and n >= 20 and score >= 0.85)
    suggestion: Optional[str] = None
    if not evidence_available:
        state, suggestion = "evidence_unavailable", None
    elif mde is not None and mde > MDE_UNTESTABLE_THRESHOLD:
        state = "untestable"
    elif demote_ready:
        state, suggestion = "decided", ("demote" if rule_type in ("gate", "invariant") else "archive")
    elif promote_ready:
        state, suggestion = "decided", "promote"
    elif archive_candidate:
        state, suggestion = "decided", "archive"
    else:
        state = "inconclusive" if enough_n else "insufficient"
    return Fitness(
        rule=rule, triggers=triggers, tp=tp, fp=fp, last_ts=totals.get("last_ts"), score=score, misfire=misfire,
        state=state, adjudicated_n=adj_n, adjudicated_tp=int(adjudicated_tp), adjudicated_fp=int(adjudicated_fp),
        caught=int(caught), leaked=int(leaked), contested=int(contested), override_rate=override_rate,
        flagged_for_review=flagged_for_review, precision_lo=round(cp_lo, 4), precision_hi=round(cp_hi, 4),
        p_below_demote=round(p_below_07, 4), prior_mass=round(prior_mass, 4), prior_share=round(prior_share, 4),
        prior_disclosure=prior_disclosure, mde=mde, eligible_sessions=int(eligible_sessions),
        decay_factor=round(combined_decay, 6), effective_weight=effective_weight, archive_candidate=archive_candidate,
        silence_lr=round(float(silence_lr), 6), sessions_count=int(sessions_count), repos_count=int(repos_count),
        days_span=round(float(days_span), 2), samples=tuple(dict(s) for s in list(samples)[:3]), suggestion=suggestion,
        evidence_available=evidence_available, evidence_error=evidence_error, min_n=int(min_n),
    )


def _read_session_expiry_config(workspace: Any) -> Tuple[float, float]:
    from aegis_core.config import ConfigError, RepoConfig
    from aegis_core.rules import workspace_root

    try:
        cfg = RepoConfig.load(workspace_root(workspace))
    except ConfigError:
        cfg = RepoConfig()
    return float(cfg.half_life_sessions), float(cfg.epsilon)


def _extract_rule_prior(rule: Any) -> Optional[Tuple[float, float]]:
    meta = getattr(rule, "meta", None)
    prior_raw = (meta.get("prior") or meta.get("pack_prior")) if isinstance(meta, Mapping) else None
    if isinstance(prior_raw, Mapping):
        a = _num(prior_raw.get("alpha", prior_raw.get("tp", 0)))
        b = _num(prior_raw.get("beta", prior_raw.get("fp", 0)))
        if a + b > 0:
            return (a, b)
    return None


def _extract_rule_trigger_rate(rule: Any) -> Optional[float]:
    meta = getattr(rule, "meta", None)
    if isinstance(meta, Mapping):
        for key in ("trigger_rate_per_day", "expected_triggers_per_day"):
            if isinstance(meta.get(key), (int, float)):
                return float(meta[key])
    return None


def _collect_t4_events_for_rules(
    workspace: Any, rules: Sequence[Any], now: Optional[datetime] = None, *, proj_credits: Any = None,
) -> Dict[str, Dict[str, Any]]:
    from aegis_core import credit
    from aegis_core.errors import PathTraversalError
    from aegis_core.storage import read_jsonl
    from aegis_core.telemetry_engine import ledger
    rule_map = {r.id: r for r in rules}
    info: Dict[str, Dict[str, Any]] = {
        r.id: {
            "adjudicated_tp": 0,
            "adjudicated_fp": 0,
            "caught": 0,
            "leaked": 0,
            "contested": 0,
            "sessions": set(),
            "repos": set(),
            "timestamps": [],
            "samples": [],
            "post_reinforce_exposures": {},
            "last_ts": None,
        }
        for r in rules
    }
    try:
        raw_rows = read_jsonl(ledger.ledger_path(workspace)).rows
    except (PathTraversalError, OSError):
        return info
    proj = proj_credits if proj_credits is not None else credit.project_credits(workspace)
    confirmed_checks = {(c.check, c.rule) for c in proj.credits if c.counts and c.result == "tp"}
    active_detections: Dict[Tuple[str, str, str, str], str] = {}
    for raw in raw_rows:
        if not isinstance(raw, dict):
            continue
        rid = str(raw.get("rule") or raw.get("for_rule") or "")
        if rid not in info:
            continue
        b = info[rid]
        ts = raw.get("ts") or raw.get("timestamp")
        ev = raw.get("event")
        if ev is None:
            if (raw.get("outcome") or raw.get("signal")) in ("tp", "success", "pass") and not ledger.is_ambient_session_row(raw):
                b["post_reinforce_exposures"] = {}
        elif ev == "report" and (str(raw.get("check")), rid) in confirmed_checks:
            b["post_reinforce_exposures"] = {}
            if isinstance(ts, str) and ts and (b["last_ts"] is None or ts > b["last_ts"]):
                b["last_ts"] = ts
        elif ev == "adjudication":
            verdict = raw.get("verdict")
            if verdict == "tp":
                b["adjudicated_tp"] += 1
                b["post_reinforce_exposures"] = {}
            elif verdict == "fp":
                b["adjudicated_fp"] += 1
            if raw.get("session"):
                b["sessions"].add(str(raw["session"]))
            if raw.get("repo"):
                b["repos"].add(str(raw["repo"]))
            if isinstance(ts, str) and ts:
                b["timestamps"].append(ts)
                if b["last_ts"] is None or ts > b["last_ts"]:
                    b["last_ts"] = ts
            if len(b["samples"]) < 3:
                b["samples"].append({
                    "kind": "adjudication",
                    "verdict": verdict,
                    "ref": raw.get("ref"),
                    "file": raw.get("file"),
                    "line": raw.get("line"),
                    "summary": raw.get("summary") or raw.get("snippet") or "",
                })
        elif ev == "detection":
            disp = str(raw.get("disposition") or "")
            d_key = (rid, str(raw.get("file") or ""), str(raw.get("pattern") or ""), str(raw.get("branch") or "main"))
            prev_disp = active_detections.get(d_key)
            if prev_disp == "caught":
                b["caught"] = max(0, b["caught"] - 1)
            elif prev_disp == "leaked":
                b["leaked"] = max(0, b["leaked"] - 1)
            if disp in ("caught", "leaked"):
                active_detections[d_key] = disp
            if disp == "caught":
                b["caught"] += 1
                b["post_reinforce_exposures"] = {}
            elif disp == "leaked":
                b["leaked"] += 1
            if isinstance(ts, str) and ts and (b["last_ts"] is None or ts > b["last_ts"]):
                b["last_ts"] = ts
            sample_item = {
                "kind": "detection",
                "disposition": disp,
                "file": raw.get("file"),
                "pattern": raw.get("pattern"),
                "branch": raw.get("branch"),
                "rev": raw.get("rev"),
            }
            replaced = False
            for idx, s_item in enumerate(b["samples"]):
                if (
                    s_item.get("kind") == "detection"
                    and s_item.get("file") == raw.get("file")
                    and s_item.get("pattern") == raw.get("pattern")
                    and s_item.get("branch") == raw.get("branch")
                ):
                    b["samples"][idx] = sample_item
                    replaced = True
                    break
            if not replaced and len(b["samples"]) < 3:
                b["samples"].append(sample_item)
        elif ev == "override":
            b["contested"] += 1
        elif ev == "exposure" and raw.get("session"):
            hb_ok = raw.get("heartbeat") is not False and raw.get("heartbeat_alive") is not False
            b["post_reinforce_exposures"].setdefault(str(raw["session"]), []).append((hb_ok, raw.get("scope_basis")))
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    for rid, b in info.items():
        rule_obj = rule_map[rid]
        scoped_or_trap = bool(getattr(rule_obj, "target_paths", None)) or getattr(rule_obj, "type", "") == "trap"
        b["eligible_sessions"] = sum(
            1 for records in b["post_reinforce_exposures"].values()
            if all(hb for hb, _ in records) and (not scoped_or_trap or all(sb in (None, "", "match") for _, sb in records))
        )
        created_raw = (getattr(rule_obj, "meta", {}) or {}).get("created")
        parsed_created = (
            _parse_ts(created_raw if "T" in created_raw else f"{created_raw}T00:00:00Z")
            if isinstance(created_raw, str) and created_raw
            else None
        )
        b["days_span"] = max(0.0, (moment - parsed_created).total_seconds() / 86400.0) if parsed_created else 0.0
    return info


def for_rules(
    workspace: Any, rules: Iterable[Any], now: Optional[datetime] = None, view: Any = None, *, verify_ci: bool = False,
) -> Dict[str, Fitness]:
    from aegis_core import credit
    from aegis_core.config import ConfigError, RepoConfig
    from aegis_core.telemetry_engine import ledger
    rule_list = list(rules)
    try:
        config = RepoConfig.load(workspace)
    except ConfigError:
        config = RepoConfig()
    half_life_sessions = float(config.half_life_sessions)
    epsilon = float(config.epsilon)
    view_obj = view if view is not None else ledger.read(workspace)
    proj_credits = credit.project_credits(workspace, view=view_obj, verify_ci=verify_ci)
    combined_rows: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str]] = set()
    for r in list(view_obj.rows) + list(proj_credits.outcome_rows):
        k = r.get("key")
        rid = r.get("rule")
        if isinstance(k, str) and k and isinstance(rid, str):
            if (k, rid) in seen_keys:
                continue
            seen_keys.add((k, rid))
        combined_rows.append(r)
    totals = ledger.aggregate_rows(combined_rows)
    t4_by_rule = _collect_t4_events_for_rules(workspace, rule_list, now=now, proj_credits=proj_credits)
    out: Dict[str, Fitness] = {}
    for rule in rule_list:
        rid = rule.id
        rtype = getattr(rule, "type", "trap") or "trap"
        meta = getattr(rule, "meta", {}) or {}
        rule_totals = dict(totals.get(rid, {}))
        t4 = t4_by_rule.get(rid, {})
        if not rule_totals.get("last_ts") and t4.get("last_ts"):
            rule_totals["last_ts"] = t4["last_ts"]
        out[rid] = compute(
            rule_totals, config.expiry_for(rtype), now, rid, prior=_extract_rule_prior(rule),
            trigger_rate_per_day=_extract_rule_trigger_rate(rule), eligible_sessions=int(t4.get("eligible_sessions", 0)),
            half_life_sessions=half_life_sessions, epsilon=epsilon, rule_type=rtype,
            pinned=bool(meta.get("pin") is True or meta.get("pinned") is True), contested=int(t4.get("contested", 0)),
            caught=int(t4.get("caught", 0)), leaked=int(t4.get("leaked", 0)), adjudicated_tp=int(t4.get("adjudicated_tp", 0)),
            adjudicated_fp=int(t4.get("adjudicated_fp", 0)), sessions_count=len(t4.get("sessions", ())),
            repos_count=len(t4.get("repos", ())), days_span=float(t4.get("days_span", 0.0)), samples=t4.get("samples", ()),
            evidence_available=proj_credits.available, evidence_error=proj_credits.error,
        )
    return out


def _python_blobs_at_commit(workspace: Any, commit: str) -> Dict[str, Tuple[str, str]]:
    from aegis_core import gitsafe

    try:
        entries = gitsafe.tree_blobs(workspace, commit)
    except gitsafe.GitError:
        return {}
    return {
        path: entry
        for path, entry in entries.items()
        if path.endswith(".py")
    }


def _violations_at_commit(root: Path, commit: str, rules: Sequence[Any]) -> Set[Tuple[str, str, str]]:
    from aegis_core import gitsafe
    from aegis_core.ast.policy import evaluate_forbid_ast_with_overrides, extract_normalized_ast

    py_blobs = _python_blobs_at_commit(root, commit)
    if not py_blobs:
        return set()
    hits: Set[Tuple[str, str, str]] = set()
    for rel in sorted(py_blobs):
        applicable = [r for r in rules if r.applies_to(rel)]
        if not applicable:
            continue
        try:
            blob = gitsafe.read_blob(root, commit, rel)
            source = blob.decode("utf-8", "replace") if blob else ""
            norm_ast = extract_normalized_ast(rel, workspace_root=root, code=source) if source else None
        except Exception:
            norm_ast = None
        if norm_ast is None:
            continue
        for rule in applicable:
            spec = (getattr(rule, "meta", {}) or {}).get("forbid_ast")
            if not isinstance(spec, dict):
                continue
            try:
                violations, _ = evaluate_forbid_ast_with_overrides(norm_ast, spec, rule_id=rule.id, source=source)
            except Exception:
                continue
            for msg in violations:
                m = _VIOLATION_PATTERN_RE.search(msg)
                hits.add((rule.id, rel, m.group(1) if m else msg))
    return hits


def replay_detector_history(workspace: Any, rules: Optional[Iterable[Any]] = None, *, branch: Optional[str] = None, persist: bool = True) -> List[Dict[str, Any]]:
    from aegis_core import credit, gitsafe
    from aegis_core.rules import load_rules, workspace_root
    root = Path(workspace_root(workspace)).resolve()
    loaded = list(rules) if rules is not None else list(load_rules(root).served)
    forbid_rules = [r for r in loaded if isinstance((getattr(r, "meta", {}) or {}).get("forbid_ast"), Mapping)]
    if not forbid_rules:
        return []
    target_branch = branch or credit.resolve_protected_branch(root) or "main"
    remote_rev = gitsafe.resolve_commit(root, f"refs/remotes/origin/{target_branch}")
    local_rev = gitsafe.resolve_commit(root, f"refs/heads/{target_branch}") or gitsafe.resolve_commit(root, target_branch)
    if remote_rev and local_rev:
        if remote_rev != local_rev and gitsafe.run(["merge-base", "--is-ancestor", remote_rev, local_rev], root).returncode == 0:
            target_rev: Optional[str] = local_rev
        else:
            target_rev = remote_rev
    else:
        target_rev = remote_rev or local_rev
    if target_rev is None:
        if branch is not None:
            return []
        target_rev = gitsafe.resolve_commit(root, "HEAD")
    if not target_rev:
        return []
    rev_res = gitsafe.run(["rev-list", "--parents", "--reverse", target_rev], root)
    commit_lines = [ln.strip().split() for ln in rev_res.stdout.decode("utf-8", "replace").splitlines() if ln.strip()] if rev_res.returncode == 0 else []
    if not commit_lines:
        return []
    hits_cache: Dict[str, Set[Tuple[str, str, str]]] = {}

    def hits_for(sha: str) -> Set[Tuple[str, str, str]]:
        if sha not in hits_cache:
            hits_cache[sha] = _violations_at_commit(root, sha, forbid_rules)
        return hits_cache[sha]

    def commit_subject(sha: str) -> str:
        r = gitsafe.run(["log", "-1", "--format=%s", sha], root)
        return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""

    findings: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    merge_commits = [parts for parts in commit_lines if len(parts) >= 3]
    merge_shas = {parts[0] for parts in merge_commits}
    for parts in merge_commits:
        merge_sha, p1, p2 = parts[0], parts[1], parts[2]
        m_branch = _MERGE_BRANCH_RE.search(commit_subject(merge_sha))
        b_label = m_branch.group(1) if m_branch else f"{target_branch}:{merge_sha[:8]}"
        br_res = gitsafe.run(["rev-list", "--reverse", f"{p1}..{p2}"], root)
        branch_shas = [s.strip() for s in br_res.stdout.decode("utf-8", "replace").splitlines() if s.strip()]
        base_hits, merge_hits = hits_for(p1), hits_for(merge_sha)
        for rid, rel, pat in sorted(merge_hits - base_hits):
            findings[(rid, rel, pat, b_label)] = {"rule": rid, "file": rel, "pattern": pat, "disposition": "leaked", "weight": 1.0, "branch": b_label, "rev": merge_sha}
        for b_sha in branch_shas:
            for rid, rel, pat in sorted(hits_for(b_sha) - base_hits):
                key = (rid, rel, pat, b_label)
                if (rid, rel, pat) not in merge_hits and key not in findings:
                    findings[key] = {"rule": rid, "file": rel, "pattern": pat, "disposition": "caught", "weight": 0.5, "branch": b_label, "rev": b_sha, "fix_rev": merge_sha}
    fp_res = gitsafe.run(["rev-list", "--first-parent", "--reverse", target_rev], root)
    shas = [s.strip() for s in fp_res.stdout.decode("utf-8", "replace").splitlines() if s.strip()] if fp_res.returncode == 0 else [parts[0] for parts in commit_lines]
    if shas:
        tip_hits = hits_for(shas[-1])
        for idx, sha in enumerate(shas):
            if sha in merge_shas:
                continue
            prev_hits = hits_for(shas[idx - 1]) if idx > 0 else set()
            for rid, rel, pat in sorted(hits_for(sha) - prev_hits):
                key = (rid, rel, pat, target_branch)
                if (rid, rel, pat) in tip_hits:
                    findings[key] = {"rule": rid, "file": rel, "pattern": pat, "disposition": "leaked", "weight": 1.0, "branch": target_branch, "rev": sha}
                else:
                    fix_sha = next((s for s in shas[idx + 1:] if (rid, rel, pat) not in hits_for(s)), shas[-1])
                    disp = "leaked" if "revert" in commit_subject(fix_sha).lower() else "caught"
                    findings[key] = {"rule": rid, "file": rel, "pattern": pat, "disposition": disp, "weight": 1.0 if disp == "leaked" else 0.5, "branch": target_branch, "rev": sha, "fix_rev": fix_sha}
    return [dict(i) for i in findings.values()] if not persist else [
        credit.record_detection(root, i["rule"], i["file"], i["pattern"], disposition=i["disposition"], rev=i.get("rev"), branch=i["branch"], fix_rev=i.get("fix_rev"), weight=i["weight"])
        for i in findings.values()
    ]


