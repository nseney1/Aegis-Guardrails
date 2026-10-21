"""Rule fitness, computed at read time from the outcome ledger (ADR 0005 H6, AD-1; v4.3 T4)."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import stats as _stats
from aegis_core.config import DEFAULT_EPSILON, DEFAULT_HALF_LIFE_SESSIONS
from aegis_core.stats import (
    _num,
    beta_cdf,
    beta_ppf,
    clopper_pearson_interval,
    clopper_pearson_lower,
    clopper_pearson_upper,
    regularized_incomplete_beta,
)
from aegis_core.taxonomy import DEFAULT_CONFIDENCE_LEVEL, RULE_TYPES, WILSON_CONFIDENCE_Z_SCORES

__all__ = [
    "DEFAULT_ARCHIVE_EPSILON",
    "DEFAULT_HALF_LIFE_SESSIONS",
    "DEFAULT_MIN_N",
    "Fitness",
    "MAX_PRIOR_MASS",
    "MDE_UNTESTABLE_THRESHOLD",
    "MIN_AGE_DAYS_FOR_PROMOTION",
    "MIN_N",
    "MIN_OBSERVATION_DAYS",
    "ReplayReport",
    "beta_cdf",
    "beta_ppf",
    "cap_prior",
    "clopper_pearson_interval",
    "clopper_pearson_lower",
    "clopper_pearson_upper",
    "combined_totals",
    "compute",
    "compute_mde_180d",
    "compute_silence_credit",
    "for_rules",
    "regularized_incomplete_beta",
    "replay_detector_history",
    "replay_detector_history_report",
    "rule_age_days",
    "session_decay_factor",
    "wilson_interval",
    "wilson_lower_bound",
]

Z = WILSON_CONFIDENCE_Z_SCORES[DEFAULT_CONFIDENCE_LEVEL]
MAX_PRIOR_MASS = 10.0
# One minimum-sample gate (spec T4, section 9): below it no number is shown and no transition is suggested.
MIN_N = 25
DEFAULT_MIN_N = MIN_N
# H and epsilon are defined once, in config (30 sessions, 0.01); these names stay as aliases.
DEFAULT_ARCHIVE_EPSILON = DEFAULT_EPSILON
DEFAULT_MDE_HORIZON_DAYS = 180.0
MDE_UNTESTABLE_THRESHOLD = 0.6
# Below this many days of ledger history the trigger volume says nothing: 180 / (1.24324 / 0.6)^2 = 41.9.
MIN_OBSERVATION_DAYS = 42.0
# A rule must have been tried this long before evidence may promote it.
MIN_AGE_DAYS_FOR_PROMOTION = 30
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


def rule_age_days(rule: Any, now: Optional[datetime] = None) -> int:
    """Days since the rule's ``created`` date (0 when it has none or it cannot be read)."""
    created = (getattr(rule, "meta", None) or {}).get("created")
    if isinstance(created, datetime):
        created_dt = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    elif isinstance(created, str) and created:
        text = created.strip()
        text = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            created_dt = datetime.fromisoformat(text) if "T" in text else datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return 0
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
    elif hasattr(created, "isoformat"):  # a date
        created_dt = datetime(created.year, created.month, created.day, tzinfo=timezone.utc)
    else:
        return 0
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return max(0, (current - created_dt).days)


def session_decay_factor(eligible_sessions: int, half_life_sessions: Optional[float] = DEFAULT_HALF_LIFE_SESSIONS) -> float:
    return 1.0 if (eligible_sessions <= 0 or not half_life_sessions or half_life_sessions <= 0) else float(2.0 ** (-float(eligible_sessions) / float(half_life_sessions)))


@dataclass(frozen=True)
class Fitness:
    rule: str = ""
    triggers: int = 0
    tp: float = 0.0
    fp: float = 0.0
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
        if not self.evidence_available or not self.verdicts or self.state in ("insufficient", "untestable"):
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
    totals: Mapping[str, Any], now: Optional[datetime] = None, rule: str = "", *,
    prior: Optional[Tuple[float, float]] = None, trigger_rate_per_day: Optional[float] = None,
    observed_days: Optional[float] = None, min_n: int = DEFAULT_MIN_N, eligible_sessions: int = 0,
    half_life_sessions: Optional[float] = DEFAULT_HALF_LIFE_SESSIONS, epsilon: float = DEFAULT_ARCHIVE_EPSILON, rule_type: str = "trap", pinned: bool = False, contested: int = 0,
    caught: int = 0, leaked: int = 0, adjudicated_tp: int = 0, adjudicated_fp: int = 0, sessions_count: int = 0,
    repos_count: int = 0, days_span: float = 0.0, silence_lr: float = 1.0,
    evidence_available: bool = True, evidence_error: Optional[str] = None, age_days: Optional[float] = None,
) -> Fitness:
    """The one decision engine (R-evidence-7): a rule's state and the transition its evidence
    supports. ``promote``, ``demote`` and ``archive`` appear only in state ``decided``, and never
    without the evidence (``evidence_available``) or below ``min_n``. ``age_days`` (None: not
    gated) below MIN_AGE_DAYS_FOR_PROMOTION blocks promotion."""
    base_tp, base_fp = _num(totals.get("tp", 0) or 0), _num(totals.get("fp", 0) or 0)
    adj_n = int(adjudicated_tp) + int(adjudicated_fp)
    # Spec T4: labels are the only fp source. A leaked finding is a true alarm that landed (a
    # "needs enforcement" count), and caught/leaked are dispositions, not triggers.
    tp = round(base_tp + float(adjudicated_tp) + 0.5 * float(caught), 6)
    fp = round(base_fp + float(adjudicated_fp), 6)
    n, triggers = tp + fp, int(_num(totals.get("triggers", 0)))
    a0, b0 = cap_prior(prior[0], prior[1]) if prior is not None else (0.0, 0.0)
    # Spec T4: evidence decays by eligible exposure sessions, never by calendar days, and every
    # posterior statistic uses the decayed counts, so a stale verdict lapses towards the (undecayed)
    # prior. The raw n still guards the sample gate.
    decay = session_decay_factor(eligible_sessions, half_life_sessions) if half_life_sessions is not None else 1.0
    tp_w, fp_w = tp * decay, fp * decay
    n_w = tp_w + fp_w
    prior_mass = a0 + b0
    prior_share = (prior_mass / (prior_mass + n_w)) if (prior_mass + n_w) > 0.0 else 0.0
    prior_disclosure = f"prior supplies {int(round(prior_share * 100))}% of the evidence" if prior_mass > 0.0 else None
    rate = trigger_rate_per_day
    if rate is None and observed_days is not None and observed_days >= MIN_OBSERVATION_DAYS:
        rate = n / observed_days
    mde = round(compute_mde_180d(rate), 4) if rate is not None else None
    effective_weight = round(decay, 6)
    score = round(wilson_lower_bound(tp + a0, n + prior_mass) * decay, 4) if n > 0 else 0.0
    misfire = round(wilson_lower_bound(fp_w, n_w), 4) if n > 0 else 0.0
    cp_lo, cp_hi = clopper_pearson_interval(tp_w, n_w, alpha=0.10, prior=prior)
    p_below_07 = beta_cdf(0.7, 1.0 + tp_w + a0, 1.0 + fp_w + b0) if n > 0 else 0.0
    override_rate = round(float(contested) / float(max(1, int(contested) + int(triggers))), 4) if contested > 0 else 0.0
    flagged_for_review = bool(contested > 0 and (contested >= 3 or override_rate >= 0.25))
    archive_candidate = bool(rule_type == "trap" and not pinned and eligible_sessions > 0 and effective_weight < epsilon)
    enough_n = n >= min_n
    # The posterior alone: without a prior, the Wilson and Clopper-Pearson terms never demote a
    # rule it keeps (checked over every (tp, fp) in 0..85).
    demote_ready = bool(enough_n and p_below_07 >= 0.9)
    spec = RULE_TYPES.get(rule_type)
    movable = bool(spec is not None and spec.promotes_to and (age_days is None or age_days >= MIN_AGE_DAYS_FOR_PROMOTION))
    if adj_n > 0:
        enough_pos = (adjudicated_tp >= 25 and adjudicated_fp == 0) or (adj_n >= 42 and adjudicated_fp <= 1 and cp_lo >= 0.88)
        enough_div = (sessions_count == 0 or sessions_count >= 3) and (repos_count >= 2 or days_span >= 14.0 or (repos_count == 0 and days_span == 0.0))
        promote_ready = bool(enough_n and movable and enough_pos and enough_div)
    else:
        promote_ready = bool(enough_n and movable and n >= 20 and score >= 0.85)
    suggestion: Optional[str] = None
    if not evidence_available:  # a flag, not a state: nothing is decided on evidence cut short
        state = "inconclusive" if enough_n else "insufficient"
    elif demote_ready:
        state, suggestion = "decided", ("demote" if spec is not None and spec.demotes_to else "archive")
    elif promote_ready:
        state, suggestion = "decided", "promote"
    elif archive_candidate:
        state, suggestion = "decided", "archive"
    elif mde is not None and mde > MDE_UNTESTABLE_THRESHOLD:
        state = "untestable"
    else:
        state = "inconclusive" if enough_n else "insufficient"
    return Fitness(
        rule=rule, triggers=triggers, tp=tp, fp=fp, last_ts=totals.get("last_ts"), score=score, misfire=misfire,
        state=state, adjudicated_n=adj_n, adjudicated_tp=int(adjudicated_tp), adjudicated_fp=int(adjudicated_fp),
        caught=int(caught), leaked=int(leaked), contested=int(contested), override_rate=override_rate,
        flagged_for_review=flagged_for_review, precision_lo=round(cp_lo, 4), precision_hi=round(cp_hi, 4),
        p_below_demote=round(p_below_07, 4), prior_mass=round(prior_mass, 4), prior_share=round(prior_share, 4),
        prior_disclosure=prior_disclosure, mde=mde, eligible_sessions=int(eligible_sessions),
        decay_factor=round(decay, 6), effective_weight=effective_weight, archive_candidate=archive_candidate,
        silence_lr=round(float(silence_lr), 6), sessions_count=int(sessions_count), repos_count=int(repos_count),
        days_span=round(float(days_span), 2), suggestion=suggestion,
        evidence_available=evidence_available, evidence_error=evidence_error, min_n=int(min_n),
    )


def _reinforce(bucket: Dict[str, Any], at: Optional[datetime]) -> None:
    """Evidence that the rule worked restarts its decay at the evidence's own time: exposures
    recorded later than it keep counting (replay appends an old catch after newer exposures). A
    reinforcement or an exposure without a time clears as by ledger position."""
    if at is None:
        bucket["post_reinforce_exposures"] = {}
        return
    kept = {session: [r for r in records if r[2] is not None and r[2] > at]
            for session, records in bucket["post_reinforce_exposures"].items()}
    bucket["post_reinforce_exposures"] = {session: records for session, records in kept.items() if records}


def _collect_t4_events_for_rules(
    workspace: Any, rules: Sequence[Any], now: Optional[datetime] = None, *, proj_credits: Any = None,
    adjudications: Any = None, raw_rows: Optional[Sequence[Any]] = None,
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
            "post_reinforce_exposures": {},
            "last_ts": None,
            "first_seen": None,
        }
        for r in rules
    }
    if raw_rows is None:
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
        seen_at = _parse_ts(ts)
        if seen_at is not None and (b["first_seen"] is None or seen_at < b["first_seen"]):
            b["first_seen"] = seen_at
        ev = raw.get("event")
        if ev is None:
            if (raw.get("outcome") or raw.get("signal")) in ("tp", "success", "pass") and not ledger.is_ambient_session_row(raw):
                _reinforce(b, seen_at)
        elif ev == "report" and (str(raw.get("check")), rid) in confirmed_checks:
            _reinforce(b, seen_at)
            if isinstance(ts, str) and ts and (b["last_ts"] is None or ts > b["last_ts"]):
                b["last_ts"] = ts
        elif ev == "detection":
            disp = str(raw.get("disposition") or "")
            # One unit per introducing commit (the PR), as replay and credit.record_detection key it.
            d_key = (rid, str(raw.get("file") or ""), str(raw.get("pattern") or ""), str(raw.get("rev") or ""))
            prev_disp = active_detections.get(d_key)
            if prev_disp == "caught":
                b["caught"] = max(0, b["caught"] - 1)
            elif prev_disp == "leaked":
                b["leaked"] = max(0, b["leaked"] - 1)
            if disp in ("caught", "leaked"):
                active_detections[d_key] = disp
            if disp == "caught":
                b["caught"] += 1
                _reinforce(b, seen_at)
            elif disp == "leaked":
                b["leaked"] += 1
            if isinstance(ts, str) and ts and (b["last_ts"] is None or ts > b["last_ts"]):
                b["last_ts"] = ts
        elif ev == "override":
            b["contested"] += 1
        elif ev == "exposure" and raw.get("session"):
            hb_ok = raw.get("heartbeat") is not False and raw.get("heartbeat_alive") is not False
            b["post_reinforce_exposures"].setdefault(str(raw["session"]), []).append((hb_ok, raw.get("scope_basis"), seen_at))
        # A ledger "adjudication" row is read and never counted: any writer can append one. Labels
        # count only as git content at the reviewed BASE (aegis_core.adjudication, R-evidence-3).
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    labels_by_rule = getattr(adjudications, "by_rule", None) or {}
    for rid, b in info.items():
        rule_obj = rule_map[rid]
        stamps: List[datetime] = []
        reinforced: Optional[datetime] = None
        for label in labels_by_rule.get(rid, ()):
            b["adjudicated_tp" if label["verdict"] == "tp" else "adjudicated_fp"] += 1
            b["sessions"].update([label["session"]] if label.get("session") else [])
            b["repos"].update([label["repo"]] if label.get("repo") else [])
            stamp = _parse_ts(label.get("ts"))
            if stamp is not None:
                stamps.append(stamp)
                if label["verdict"] == "tp" and (reinforced is None or stamp > reinforced):
                    reinforced = stamp
        scoped_or_trap = bool(getattr(rule_obj, "target_paths", None)) or getattr(rule_obj, "type", "") == "trap"
        # A merged tp label reinforces the rule as of its ts: only exposures after it decay it.
        windows = [[r for r in records if reinforced is None or (r[2] is not None and r[2] > reinforced)]
                   for records in b["post_reinforce_exposures"].values()]
        b["eligible_sessions"] = sum(
            1 for records in windows
            if records and all(hb for hb, _, _ in records)
            and (not scoped_or_trap or all(sb in (None, "", "match") for _, sb, _ in records))
        )
        b["days_span"] = (max(stamps) - min(stamps)).total_seconds() / 86400.0 if stamps else 0.0
        # Trigger volume is measured from the ledger, never from branch-editable frontmatter (H6).
        b["observed_days"] = (moment - b["first_seen"]).total_seconds() / 86400.0 if b["first_seen"] else None
    return info


def combined_totals(view: Any, proj: Any) -> Dict[str, Any]:
    """Per-rule ledger totals of ``view``'s outcome rows plus the credit projection's confirmed rows,
    each (key, rule) once."""
    from aegis_core.telemetry_engine import ledger

    combined_rows: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[str, str]] = set()
    for r in list(view.rows) + list(proj.outcome_rows):
        k, rid = r.get("key"), r.get("rule")
        if isinstance(k, str) and k and isinstance(rid, str):
            if (k, rid) in seen_keys:
                continue
            seen_keys.add((k, rid))
        combined_rows.append(r)
    return ledger.aggregate_rows(combined_rows)


def for_rules(
    workspace: Any, rules: Iterable[Any], now: Optional[datetime] = None, view: Any = None, *, verify_ci: bool = False,
    adjudications: Any = None,
) -> Dict[str, Fitness]:
    """Fitness per rule from the ledger, CI-confirmed credit and the labels merged at the reviewed
    BASE (``adjudications``: read with ``adjudication.read_adjudications`` unless given; scan
    passes an empty set so it spawns no git for them)."""
    from aegis_core import adjudication, credit
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
    totals = combined_totals(view_obj, proj_credits)
    labels = adjudications if adjudications is not None else adjudication.read_adjudications(workspace)
    t4_by_rule = _collect_t4_events_for_rules(workspace, rule_list, now=now, proj_credits=proj_credits,
                                              adjudications=labels, raw_rows=getattr(view_obj, "raw_rows", None))
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
            rule_totals, now, rid, observed_days=t4.get("observed_days"),
            eligible_sessions=int(t4.get("eligible_sessions", 0)),
            half_life_sessions=half_life_sessions, epsilon=epsilon, rule_type=rtype,
            pinned=bool(meta.get("pin") is True or meta.get("pinned") is True), contested=int(t4.get("contested", 0)),
            caught=int(t4.get("caught", 0)), leaked=int(t4.get("leaked", 0)), adjudicated_tp=int(t4.get("adjudicated_tp", 0)),
            adjudicated_fp=int(t4.get("adjudicated_fp", 0)), sessions_count=len(t4.get("sessions", ())),
            repos_count=len(t4.get("repos", ())), days_span=float(t4.get("days_span", 0.0)),
            evidence_available=proj_credits.available, evidence_error=proj_credits.error,
            age_days=rule_age_days(rule, now),
        )
    return out


def _rule_key(rule: Any) -> Tuple[str, str]:
    spec = (getattr(rule, "meta", {}) or {}).get("forbid_ast")
    return rule.id, json.dumps(spec, sort_keys=True, default=str)


def _blob_texts(root: Path, oids: List[str]) -> Dict[str, Optional[str]]:
    """The text of each blob, read in one batch; a blob git cannot give back is None (UNVERIFIED)."""
    from aegis_core import gitsafe

    try:
        blobs = gitsafe.read_blobs(root, oids) if oids else {}
    except gitsafe.GitError:  # one bad object fails the batch: find which, one at a time
        blobs = {}
        for oid in oids:
            try:
                blobs.update(gitsafe.read_blobs(root, [oid]))
            except gitsafe.GitError:
                continue
    return {oid: (blobs[oid].decode("utf-8", "replace") if oid in blobs else None) for oid in oids}


def _patterns(rel: str, text: Optional[str], rules: Sequence[Any]) -> Dict[Tuple[str, str], Optional[FrozenSet[str]]]:
    """The violated patterns of each rule in one blob; None where it cannot be read or evaluated."""
    from aegis_core.ast.policy import evaluate_forbid_ast_structured, extract_normalized_ast

    try:
        tree = extract_normalized_ast(rel, code=text) if text else None
    except Exception:
        return {_rule_key(r): None for r in rules}
    out: Dict[Tuple[str, str], Optional[FrozenSet[str]]] = {}
    for rule in rules:
        spec = (getattr(rule, "meta", {}) or {}).get("forbid_ast")
        try:
            found = evaluate_forbid_ast_structured(tree, spec, rule_id=rule.id, source=text) if tree is not None and isinstance(spec, dict) else []
        except Exception:
            out[_rule_key(rule)] = None
            continue
        out[_rule_key(rule)] = frozenset(f["pattern"] for f in found if not f["unknown"] and f["override"] is None)
    return out


def _violations_at_commit(root: Path, commit: str, rules: Sequence[Any], skipped: Set[str],
                          cache: Dict[Tuple[str, Tuple[str, str]], Optional[FrozenSet[str]]]) -> Set[Tuple[str, str, str]]:
    """The (rule, file, pattern) hits at ``commit``: one tree listing and one batched read of the blobs
    ``cache`` (keyed by blob and rule) does not hold; a file whose blob, syntax tree or evaluation
    fails is added to ``skipped`` rather than read as clean."""
    from aegis_core import gitsafe

    wanted = {rel: (oid, [r for r in rules if r.applies_to(rel)])
              for rel, (_mode, oid) in sorted(gitsafe.tree_blobs(root, commit).items()) if rel.endswith(".py")}
    wanted = {rel: entry for rel, entry in wanted.items() if entry[1]}
    needed: Dict[str, Tuple[str, Dict[Tuple[str, str], Any]]] = {}
    for rel, (oid, applicable) in wanted.items():
        for rule in applicable:
            if (oid, _rule_key(rule)) not in cache:
                needed.setdefault(oid, (rel, {}))[1][_rule_key(rule)] = rule
    texts = _blob_texts(root, list(needed))
    for oid, (rel, by_key) in needed.items():
        for key, found in _patterns(rel, texts[oid], list(by_key.values())).items():
            cache[(oid, key)] = None if texts[oid] is None else found
    hits: Set[Tuple[str, str, str]] = set()
    for rel, (oid, applicable) in wanted.items():
        for rule in applicable:
            found = cache[(oid, _rule_key(rule))]
            if found is None:
                skipped.add(rel)
            else:
                hits.update((rule.id, rel, pattern) for pattern in found)
    return hits


@dataclass(frozen=True)
class ReplayReport:
    """What a detector replay walked and what it could not read: ``files_skipped`` and ``errors``
    make its findings partial (UNVERIFIED); ``skipped_reason`` says why nothing was walked."""

    detections: List[Dict[str, Any]]
    branch: Optional[str] = None
    commits: int = 0
    files_skipped: Tuple[str, ...] = ()
    errors: Tuple[str, ...] = ()
    skipped_reason: Optional[str] = None
    tip: Optional[str] = None  # the commit a complete replay reached: the next one may start there
    rules: Optional[str] = None  # the digest of the forbid_ast rules it replayed

    def as_dict(self) -> Dict[str, Any]:
        return {"branch": self.branch, "commits": self.commits, "files_skipped": list(self.files_skipped),
                "errors": list(self.errors), "skipped_reason": self.skipped_reason, "detections": len(self.detections)}


_BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")


def _base_branch(root: Path, branch: Optional[str]) -> Optional[str]:
    """``branch``, else the branch the user-scope ``rules.base_ref`` names (``<b>``, ``origin/<b>``,
    ``refs/heads/<b>``, ``refs/remotes/origin/<b>``; any other form is no branch), else the
    protected branch. Never HEAD: that may be an unmerged branch."""
    from aegis_core import credit
    from aegis_core.config import read_user_config

    if branch:
        return branch
    rules_cfg = (read_user_config(root) or {}).get("rules")
    ref = rules_cfg.get("base_ref") if isinstance(rules_cfg, dict) else None
    if isinstance(ref, str):
        ref = ref.strip()
        for prefix in ("refs/remotes/origin/", "refs/heads/", "origin/"):
            if ref.startswith(prefix):
                ref = ref[len(prefix):]
                break
        if _BRANCH_NAME.fullmatch(ref) and ref != "HEAD" and ".." not in ref and not ref.endswith((".lock", "/")):
            return ref
    return credit.resolve_protected_branch(root)


def _utc_stamp(iso: str) -> Optional[str]:
    try:
        moment = datetime.fromisoformat(iso.strip())
    except ValueError:
        return None
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if moment.tzinfo else None


def _rules_digest(rules: Sequence[Any]) -> str:
    entries = sorted([*_rule_key(r), str(getattr(r, "digest", "") or ""),
                      json.dumps(list(getattr(r, "target_paths", None) or ()), default=str)] for r in rules)
    return hashlib.sha256(json.dumps(entries).encode("utf-8", "surrogatepass")).hexdigest()


def _target_rev(root: Path, facts: Any, branch: str) -> Optional[str]:
    """origin's ``branch`` unless the local one is ahead of it, else whichever exists."""
    from aegis_core import gitevidence, gitsafe

    tips = gitevidence.branch_tips(facts, branch)
    if len(tips) == 2:
        remote, local = tips
        return local if remote != local and gitevidence.is_ancestor(facts, remote, local) else remote
    return tips[0] if tips else gitsafe.resolve_commit(root, branch)


def _open_at(root: Path, branch: str, rules: Sequence[Any], old: Sequence[str], merges: Set[str],
             at_tip: Set[Tuple[str, str, str]]) -> List[Tuple[str, str, str, str]]:
    """The first-parent findings a replay up to ``old[-1]`` left without a fix (the ledger's latest
    row per unit) whose hit is still there: a later commit may fix them."""
    from aegis_core import credit

    ids, line = {r.id for r in rules}, set(old) - merges
    latest: Dict[Tuple[str, str, str, str], Mapping[str, Any]] = {}
    for row in credit.read_rows(root):
        if row.get("event") == "detection":
            latest[(str(row.get("rule") or ""), str(row.get("file") or ""), str(row.get("pattern") or ""), str(row.get("rev") or ""))] = row
    return [key for key, row in latest.items()
            if key[0] in ids and key[3] in line and key[:3] in at_tip and row.get("disposition") == "leaked"
            and row.get("fix_rev") is None and row.get("branch") == branch]


def replay_detector_history_report(
    workspace: Any, rules: Optional[Iterable[Any]] = None, *, branch: Optional[str] = None, persist: bool = True,
    since: Optional[Mapping[str, Any]] = None,
) -> ReplayReport:
    """Replay the forbid_ast rules over the history of the base branch (spec T4.1). Raises
    gitsafe.GitError when git cannot walk it; a finding carries its evidence commit's time.

    ``since`` is the ``tip``/``rules``/``branch`` of an earlier complete replay (derived.json): when
    the same rules were replayed on the same branch and only single-parent commits follow that
    tip, only they are walked, and the findings still open at the tip get the fix a new commit
    makes. Anything else (no tip, a forged one, a rewritten branch, an edited rule, a merge)
    walks everything."""
    from aegis_core import gitevidence, gitsafe
    from aegis_core.rules import load_rules, workspace_root
    root = Path(workspace_root(workspace)).resolve()
    loaded = list(rules) if rules is not None else list(load_rules(root).served)
    forbid_rules = [r for r in loaded if isinstance((getattr(r, "meta", {}) or {}).get("forbid_ast"), Mapping)]
    if not forbid_rules:
        return ReplayReport([], skipped_reason="no forbid_ast rule")
    with gitsafe.memo():
        target_branch = _base_branch(root, branch)
        if not target_branch:
            return ReplayReport([], skipped_reason="no base branch")
        target_rev = _target_rev(root, gitevidence.repo_facts(root), target_branch)
        if not target_rev:
            return ReplayReport([], target_branch, skipped_reason=f"no commit on {target_branch}")
        digest = _rules_digest(forbid_rules)
        stored = since if isinstance(since, Mapping) and since.get("rules") == digest and since.get("branch") == target_branch else {}
        tip = stored.get("tip") if isinstance(stored.get("tip"), str) else None

        def walk(*args: str) -> List[str]:
            res = gitsafe.run(["rev-list", *args, target_rev], root)
            if res.returncode != 0:
                raise gitsafe.GitError(f"git rev-list {target_branch} failed (exit {res.returncode})")
            return [ln.strip() for ln in res.stdout.decode("utf-8", "replace").splitlines() if ln.strip()]

        if tip == target_rev:
            return ReplayReport([], target_branch, int(walk("--count")[0]), tip=tip, rules=digest)
        return _replay(root, forbid_rules, target_branch, walk, tip, digest, persist)


def _replay(root: Path, forbid_rules: List[Any], target_branch: str, walk: Callable[..., List[str]],
            tip: Optional[str], digest: str, persist: bool) -> ReplayReport:
    from aegis_core import credit, gitsafe

    commit_lines = [ln.split() for ln in walk("--parents", "--reverse")]
    described = dict(ln.split("\0", 1) for ln in walk("--format=%H%x00%cI%x00%s") if not ln.startswith("commit ") and "\0" in ln)
    stamps = {sha: rest.split("\0", 1)[0] for sha, rest in described.items()}
    subjects = {sha: rest.split("\0", 1)[-1] for sha, rest in described.items()}
    shas = walk("--first-parent", "--reverse")
    parents = {parts[0]: parts[1:] for parts in commit_lines}
    merge_shas = {sha for sha, ps in parents.items() if len(ps) >= 2}
    start = 0
    if tip is not None and tip in shas:
        old, todo = set(), [tip]
        while todo:
            sha = todo.pop()
            if sha not in old:
                old.add(sha)
                todo.extend(parents.get(sha, ()))
        # Only single-parent commits after the tip: every merge is then old, and so is its finding.
        start = shas.index(tip) + 1 if not (merge_shas - old) else 0
    skipped: Set[str] = set()
    cache: Dict[Tuple[str, Tuple[str, str]], Optional[FrozenSet[str]]] = {}
    hits_cache: Dict[str, Set[Tuple[str, str, str]]] = {}

    def hits_for(sha: str) -> Set[Tuple[str, str, str]]:
        if sha not in hits_cache:
            hits_cache[sha] = _violations_at_commit(root, sha, forbid_rules, skipped, cache)
        return hits_cache[sha]

    findings: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for parts in [] if start else [p for p in commit_lines if len(p) >= 3]:
        merge_sha, p1, p2 = parts[0], parts[1], parts[2]
        m_branch = _MERGE_BRANCH_RE.search(subjects.get(merge_sha, ""))
        b_label = m_branch.group(1) if m_branch else f"{target_branch}:{merge_sha[:8]}"
        br_res = gitsafe.run(["rev-list", "--reverse", f"{p1}..{p2}"], root)
        branch_shas = [s.strip() for s in br_res.stdout.decode("utf-8", "replace").splitlines() if s.strip()]
        base_hits, merge_hits = hits_for(p1), hits_for(merge_sha)
        for rid, rel, pat in sorted(merge_hits - base_hits):
            findings[(rid, rel, pat, merge_sha)] = {"rule": rid, "file": rel, "pattern": pat, "disposition": "leaked", "weight": 1.0, "branch": b_label, "rev": merge_sha}
        # Fixed on the branch before the merge: caught, once per merge, at the first branch commit with the hit.
        fixed_here: Set[Tuple[str, str, str]] = set()
        for b_sha in branch_shas:
            for rid, rel, pat in sorted(hits_for(b_sha) - base_hits - merge_hits - fixed_here):
                fixed_here.add((rid, rel, pat))
                findings[(rid, rel, pat, b_sha)] = {"rule": rid, "file": rel, "pattern": pat, "disposition": "caught", "weight": 0.5, "branch": b_label, "rev": b_sha, "fix_rev": merge_sha}
    if start:
        for rid, rel, pat, rev in _open_at(root, target_branch, forbid_rules, shas[:start], merge_shas, hits_for(shas[start - 1])):
            fix_sha = next((s for s in shas[start:] if (rid, rel, pat) not in hits_for(s)), None)
            if fix_sha:
                findings[(rid, rel, pat, rev)] = {"rule": rid, "file": rel, "pattern": pat, "disposition": "leaked", "weight": 1.0, "branch": target_branch, "rev": rev, "fix_rev": fix_sha}
    # Spec T4.1: a hit that reached the protected first-parent line landed, whether a later fix or
    # revert removed it (fix_rev) or not: leaked. Only the merge-branch loop above yields caught.
    for idx in range(start, len(shas)):
        sha = shas[idx]
        if sha in merge_shas:
            continue
        prev_hits = hits_for(shas[idx - 1]) if idx > 0 else set()
        for rid, rel, pat in sorted(hits_for(sha) - prev_hits):
            fix_sha = next((s for s in shas[idx + 1:] if (rid, rel, pat) not in hits_for(s)), None)
            findings[(rid, rel, pat, sha)] = {"rule": rid, "file": rel, "pattern": pat, "disposition": "leaked", "weight": 1.0, "branch": target_branch, "rev": sha, "fix_rev": fix_sha}
    # The evidence is as old as the commit that introduced (or merged) the hit, never the sync.
    detections = [dict(i) for i in findings.values()] if not persist else credit.record_detections(
        root, [dict(i, ts=_utc_stamp(stamps.get(i["rev"], ""))) for i in findings.values()])
    # Only a complete, persisted replay may be resumed: the next one reads the ledger it wrote.
    complete = persist and not skipped and bool(shas)
    return ReplayReport(detections, target_branch, len(commit_lines), tuple(sorted(skipped)),
                        tip=shas[-1] if complete else None, rules=digest)


def replay_detector_history(workspace: Any, rules: Optional[Iterable[Any]] = None, *, branch: Optional[str] = None, persist: bool = True) -> List[Dict[str, Any]]:
    """The findings of ``replay_detector_history_report``."""
    return replay_detector_history_report(workspace, rules, branch=branch, persist=persist).detections
