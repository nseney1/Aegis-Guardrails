"""Insight review: TF-IDF matching of counted insights to rules, top-3 neighbours, the human
decisions that hide or resurface insights, and the closed-template proposal."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Set, Tuple

from aegis_core.insights.capture import JOIN_WINDOW_S, _corroborating_hook, _row_source
from aegis_core.insights.keys import (
    COUNTABLE_LEVELS,
    INSIGHT_SCHEMA_VERSION,
    _append_user_insights,
    insights_path,
    read_insight_rows,
)
from aegis_core.primitives import parse_utc, utc_stamp
from aegis_core.redaction import redact_insight_text
from aegis_core.storage import atomic_write_text
from aegis_core.workspace.layout import WorkspaceLayout

if TYPE_CHECKING:
    # For annotations only: the rule parser is imported where review needs it, never at load.
    from aegis_core.rules import Rule

__all__ = [
    "RULE_MATCH_SIM",
    "RULE_MATCH_SIM_WITH_PATH",
    "record_decision",
    "review_insights",
    "write_proposal",
]

REJECTION_RESURFACE_COUNT = 2
# TF-IDF cosine thresholds, hand-set in 4.3 and not measured (spec T8 asks for a measured one;
# the measurement is deferred): a rule matches an insight that shares a path with it at
# RULE_MATCH_SIM_WITH_PATH and any insight at RULE_MATCH_SIM; recurrence counts at RECURRENCE_SIM.
RULE_MATCH_SIM_WITH_PATH = 0.15
RULE_MATCH_SIM = 0.30
DECISIONS = ("propose", "reject", "snooze", "merge-into-rule", "noise", "confirm")
# The latest of these naming an insight decides whether review lists it (noise hides for good).
_RULING_DECISIONS = ("propose", "merge-into-rule", "snooze", "reject")


def _effective_level(row: Mapping[str, Any], confirmed_ids: Set[str]) -> Optional[str]:
    """The level a row counts at: an agent capture is a suggestion until a human confirms it."""
    source = _row_source(row)
    if source == "hook":
        return "W2"
    if source == "cli":
        return "H" if row.get("level") == "H" else "cli"
    if source == "mcp":
        return "cli" if str(row.get("id") or "") in confirmed_ids else "suggestion"
    return None


def _confirmed(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Optional[str]]:
    """{insight id: kind or None} of the suggestions a human confirmed."""
    found: Dict[str, Optional[str]] = {}
    for r in rows:
        if r.get("event") == "decision" and r.get("decision") == "confirm":
            kind = r.get("kind") if isinstance(r.get("kind"), str) else None
            found.update({str(i): kind or found.get(str(i)) for i in r.get("insight_ids") or []})
    return found


def _superseded(rows: Sequence[Mapping[str, Any]]) -> Set[int]:
    """The ``id()`` of each cli row that a later H row restates: the documented H recipe re-runs
    ``insight add`` with ``--commit``, and one correction must not count twice. Each H row takes
    one earlier cli row of its text and kind, the latest with its paths, else the latest (a re-run
    without --paths takes the work tree's), so it never takes a second correction of that text."""
    earlier: Dict[Tuple[str, str], List[Mapping[str, Any]]] = {}
    found: Set[int] = set()
    for r in rows:
        if r.get("event") != "insight" or _row_source(r) != "cli":
            continue
        pool = earlier.setdefault((str(r.get("text") or ""), str(r.get("kind") or "")), [])
        if r.get("level") != "H":
            pool.append(r)
        elif pool:
            at = next((i for i in range(len(pool) - 1, -1, -1) if pool[i].get("paths") == r.get("paths")), -1)
            found.add(id(pool.pop(at)))  # by position: rows without an id can be equal dicts
    return found


_STOPWORDS = frozenset(
    "a an the and or but if then else to of in on at for with by from up about into over after "
    "is are was were be been being have has had do does did don t not no never stop don't shouldn't "
    "mustn't should must can could would will just please you your i me my we our it its this that "
    "these those there here what which who why how when where again already said told asked wanted "
    "last time as keep doing using adding wrong incorrect broke broken breaks mistake instead rather "
    "than nope nah revert undo use always avoid make sure only any all every some rule trap prevent "
    "recurring defect modules module file files".split()
)
_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def _stem(word: str) -> str:
    for suf in ("ing", "ed", "es", "s", "ly"):
        if word.endswith(suf) and len(word) > len(suf) + 2:
            return word[: -len(suf)]
    return word


def _tokenize(text: str) -> List[str]:
    if not isinstance(text, str):
        return []
    tokens: List[str] = []
    for raw in _TOKEN_RE.findall(text.lower()):
        for part in raw.split("_"):
            if len(part) > 1 and part not in _STOPWORDS:
                st = _stem(part)
                if len(st) > 1 and st not in _STOPWORDS:
                    tokens.append(st)
    return tokens


def _tfidf_vectors(docs: Sequence[Sequence[str]]) -> List[Dict[str, float]]:
    n = len(docs)
    if not n:
        return []
    df: Counter[str] = Counter(t for doc in docs for t in set(doc))
    vecs: List[Dict[str, float]] = []
    for doc in docs:
        vec = {
            t: (1.0 + math.log(c)) * (math.log((n + 1.0) / (df[t] + 1.0)) + 1.0)
            for t, c in Counter(doc).items()
        }
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        vecs.append({k: v / norm for k, v in vec.items()})
    return vecs


def _cosine(a: Mapping[str, float], b: Mapping[str, float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    return sum(v * b.get(k, 0.0) for k, v in a.items())


def _load_md_rules(workspace: Any, folder: Path, *, recursive: bool = False) -> List[Rule]:
    if not folder.is_dir():
        return []
    from aegis_core.rules import Rule
    from aegis_core.yaml_engine.frontmatter import split_frontmatter
    from aegis_core.yaml_engine.parser import AegisYAMLError, parse_yaml_subset

    root_path = Path(os.fspath(workspace)).resolve()
    items: List[Rule] = []
    for md in sorted(folder.rglob("*.md") if recursive else folder.glob("*.md")):
        if not md.is_file() or md.is_symlink():
            continue
        try:
            raw = md.read_bytes()
            _, fm, body = split_frontmatter(raw.decode("utf-8"))
            meta = parse_yaml_subset(fm) if fm else {}
            if not isinstance(meta, dict):
                meta = {}
        except (OSError, UnicodeDecodeError, AegisYAMLError):
            continue
        items.append(
            Rule(
                id=str(meta.get("id") or md.stem),
                path=md.relative_to(root_path).as_posix(),
                type=str(meta.get("type") or "trap"),
                meta=meta,
                body=body,
                digest=hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest(),
            )
        )
    return items


_Exposures = Dict[str, List[Tuple[str, datetime, Optional[str]]]]


def _exposure_index(root: Path) -> _Exposures:
    """{rule: [(host, ts, rev)]} from one pass over the ledger's exposure rows."""
    from aegis_core import credit

    index: _Exposures = {}
    for row in credit.read_rows(root):
        rule_id, ts, rev = row.get("rule"), parse_utc(row.get("ts")), row.get("rev")
        if row.get("event") == "exposure" and isinstance(rule_id, str) and ts is not None:
            index.setdefault(rule_id, []).append(
                (str(row.get("host") or ""), ts, rev if isinstance(rev, str) and rev else None))
    return index


def _rule_was_exposed(rule: Rule, row: Mapping[str, Any], exposures: _Exposures) -> bool:
    # A None rev is a row written before exposures carried one: it matches any revision.
    host, ts = str(row.get("host") or ""), parse_utc(row.get("ts"))
    return bool(host and ts is not None and any(
        h == host and abs((e_ts - ts).total_seconds()) <= JOIN_WINDOW_S
        for h, e_ts, rev in exposures.get(rule.id, ()) if rev is None or rule.digest.startswith(rev)))


def _paths_overlap_rule(paths: Iterable[str], rule: Rule) -> bool:
    """An insight without paths overlaps every rule; otherwise the rule must apply to one of them."""
    plist = [p for p in paths if p]
    return not plist or any(rule.applies_to(p) for p in plist)


class _RuleMatch(NamedTuple):
    kind: str
    rule: Rule
    similarity: float


def record_decision(
    workspace: Any,
    *,
    decision: str,
    insight_ids: Sequence[str],
    reason: Optional[str] = None,
    rule_id: Optional[str] = None,
    kind: Optional[str] = None,
    home: Optional[Path] = None,
) -> Dict[str, Any]:
    """A human decision on the insights it names; ``confirm`` names the suggestions a human
    confirms (and their ``kind``)."""
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {list(DECISIONS)}, got {decision!r}")
    ids = [str(i) for i in insight_ids if str(i).strip()]
    if not ids:
        raise ValueError(f"{decision} needs at least one insight id")
    row: Dict[str, Any] = {"v": INSIGHT_SCHEMA_VERSION, "ts": utc_stamp(), "event": "decision",
                           "decision": decision, "insight_ids": ids}
    if kind:
        row["kind"] = str(kind)
    if reason:
        row["reason"] = redact_insight_text(str(reason))
    if rule_id:
        row["rule_id"] = str(rule_id)
    _append_user_insights(insights_path(workspace, home=home), [row])
    return row


def _match_insights_to_rules(
    countable: Sequence[Tuple[int, Dict[str, Any]]],
    ins_vecs: Sequence[Mapping[str, float]],
    rule_entries: Sequence[Tuple[str, Rule, List[str]]],
    rule_vecs: Sequence[Mapping[str, float]],
) -> List[Optional[_RuleMatch]]:
    matches: List[Optional[_RuleMatch]] = []
    for i, (_, row) in enumerate(countable):
        paths_i = set(row.get("paths") or [])
        best: Optional[_RuleMatch] = None
        for r_idx, (kind, robj, _) in enumerate(rule_entries):
            sim = _cosine(ins_vecs[i], rule_vecs[r_idx])
            matched = (_paths_overlap_rule(paths_i, robj) and sim >= RULE_MATCH_SIM_WITH_PATH) or sim >= RULE_MATCH_SIM
            if matched and (best is None or sim > best.similarity):
                best = _RuleMatch(kind=kind, rule=robj, similarity=sim)
        matches.append(best)
    return matches


def _neighbours(ids: Sequence[str], vecs: Sequence[Mapping[str, float]]) -> List[List[Dict[str, Any]]]:
    """Each insight's top 3 others by cosine with a similarity above 0, ties by id."""
    found: List[List[Dict[str, Any]]] = []
    for i, vec in enumerate(vecs):
        ranked = sorted(((_cosine(vec, other), ids[j]) for j, other in enumerate(vecs) if j != i),
                        key=lambda x: (-x[0], x[1]))[:3]
        found.append([{"id": nid, "similarity": round(sim, 4)} for sim, nid in ranked if sim > 0.0])
    return found


def _hidden(order: Mapping[str, int], near: Mapping[str, Set[str]],
            decisions: Sequence[Tuple[int, Mapping[str, Any]]]) -> Set[str]:
    """The insights the latest ruling decision naming them hides: propose and merge-into-rule
    until a later decision names them again; snooze and reject until REJECTION_RESURFACE_COUNT
    insights newer than the decision have a member of its group among their top-3 neighbours."""
    latest: Dict[str, Tuple[int, Mapping[str, Any]]] = {}
    for d_idx, d_row in decisions:  # in log order: a later decision wins
        latest.update({str(i): (d_idx, d_row) for i in d_row.get("insight_ids") or []})
    resurfaced: Dict[int, bool] = {}
    for d_idx, d_row in {v[0]: v for v in latest.values()}.values():  # each deciding row once
        if d_row.get("decision") in ("snooze", "reject"):
            group = {str(i) for i in d_row.get("insight_ids") or []}
            newer = sum(1 for other, idx in order.items() if idx > d_idx and near[other] & group)
            resurfaced[d_idx] = newer >= REJECTION_RESURFACE_COUNT
    return {ins_id for ins_id, (d_idx, _) in latest.items() if ins_id in order and not resurfaced.get(d_idx)}


def _match_entry(row: Mapping[str, Any], match: Optional[_RuleMatch], exposures: _Exposures) -> Dict[str, Any]:
    if match is None:
        return {"status": "no_rule", "rule": None, "similarity": 0.0}
    if match.kind == "active":
        status = "exposed_and_ignored" if _rule_was_exposed(match.rule, row, exposures) else "not_exposed"
    else:
        status = "matches_proposal" if match.kind == "proposal" else "matches_archived"
    return {"status": status, "rule": match.rule.id, "similarity": round(match.similarity, 4)}


def review_insights(workspace: Any, *, home: Optional[Path] = None) -> Dict[str, Any]:
    """Each counted insight in log order with its rule match and its top-3 neighbours (spec T8:
    the human groups them by naming ids in a decision); ``suppressed`` holds the ones a decision
    hides, ``suggestions`` the unconfirmed agent captures."""
    all_rows = read_insight_rows(workspace, home=home)
    noise_ids = {
        str(x)
        for r in all_rows
        if r.get("event") == "decision" and r.get("decision") == "noise"
        for x in (r.get("insight_ids") or [])
        if x
    }
    decisions = [(idx, r) for idx, r in enumerate(all_rows)
                 if r.get("event") == "decision" and r.get("decision") in _RULING_DECISIONS]
    confirmed = _confirmed(all_rows)
    # Review is the authority on corroboration: recomputed here, read-only, whatever the order
    # of capture and prompt. A corroborated suggestion annotates its hook row and never counts.
    hook_rows = [r for r in all_rows if r.get("event") == "insight" and _row_source(r) == "hook"
                 and str(r.get("id") or "") not in noise_ids]
    suggestions: List[Dict[str, Any]] = []
    countable: List[Tuple[int, Dict[str, Any]]] = []
    corroborated: Dict[str, List[str]] = {}
    levels: Dict[int, Tuple[str, Optional[str]]] = {}
    confirmed_ids = set(confirmed)
    superseded = _superseded(all_rows)
    for idx, row in enumerate(all_rows):
        ins_id = str(row.get("id") or f"row-{idx}")
        if row.get("event") != "insight" or ins_id in noise_ids or id(row) in superseded:
            continue
        level = _effective_level(row, confirmed_ids)
        if _row_source(row) == "mcp":
            # Confirming a corroborated capture would count its correction a second time.
            m_hook = _corroborating_hook(hook_rows, str(row.get("host") or ""), row.get("ts"), str(row.get("text") or ""))
            if m_hook:
                corroborated.setdefault(m_hook, []).append(ins_id)
                continue
            if level == "suggestion":
                suggestions.append(row)
                continue
        if level in COUNTABLE_LEVELS:
            countable.append((idx, row))
            levels[idx] = (level, confirmed.get(ins_id) if _row_source(row) == "mcp" else row.get("kind"))
    if not countable:
        return {"insights": [], "suppressed": [], "suggestions": suggestions}
    from aegis_core.rules import load_rules

    root = Path(os.fspath(workspace)).resolve()
    layout = WorkspaceLayout(root)
    active = list(load_rules(root).served) if layout.rules_dir.is_dir() else []
    proposals = _load_md_rules(root, layout.aegis_dir / "proposals")
    archived = _load_md_rules(root, layout.rules_dir / ".archive", recursive=True)
    ins_tokens = [_tokenize(str(r.get("text") or "")) for _, r in countable]
    rule_entries = [
        (k, r, _tokenize(f"{r.id} {r.meta.get('hypothesis', '')} {r.body}"))
        for k, rl in (("active", active), ("proposal", proposals), ("archived", archived))
        for r in rl
    ]
    all_vecs = _tfidf_vectors(ins_tokens + [toks for _, _, toks in rule_entries])
    n_ins = len(countable)
    ins_vecs, rule_vecs = all_vecs[:n_ins], all_vecs[n_ins:]
    ids = [str(row.get("id") or f"row-{idx}") for idx, row in countable]
    near = _neighbours(ids, ins_vecs)
    matches = _match_insights_to_rules(countable, ins_vecs, rule_entries, rule_vecs)
    # One ledger read per review, and none when no insight matches an active rule.
    exposures = _exposure_index(root) if any(m is not None and m.kind == "active" for m in matches) else {}
    hidden = _hidden({i: idx for i, (idx, _) in zip(ids, countable)},
                     {i: {n["id"] for n in ns} for i, ns in zip(ids, near)}, decisions)
    shown: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []
    for ins_id, (idx, row), ns, match in zip(ids, countable, near, matches):
        (suppressed if ins_id in hidden else shown).append({
            "id": ins_id,
            "level": levels[idx][0],
            "kind": levels[idx][1],
            "text": str(row.get("text") or ""),
            "paths": [str(p) for p in row.get("paths") or []],
            "match": _match_entry(row, match, exposures),
            "neighbours": ns,
            "corroborated": corroborated.get(ins_id, []),
        })
    return {"insights": shown, "suppressed": suppressed, "suggestions": suggestions}


_SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_VERBATIM_MIN_CHARS = 25


def _under(prefix: str, paths: Sequence[str]) -> bool:
    return any(p == prefix or (prefix.endswith("/") and p.startswith(prefix)) for p in paths)


def _proposal_targets(members: Sequence[Sequence[str]], rows: Sequence[Mapping[str, Any]]) -> List[str]:
    """At most 3 directory prefixes as ``<prefix>**``, scored members-under x
    (ln((1+N)/(1+df)) + 1) over every insight row with paths; the best (ties: deeper, then by
    name), then the best for the members still uncovered. A top-level file is kept as its bare
    name, which (a pattern without ``/``) matches every file of that name in any directory."""
    candidates: Set[str] = set()
    for path in {p for ps in members for p in ps}:
        parts = path.split("/")
        candidates.update(["/".join(parts[:i]) + "/" for i in range(1, len(parts))] or [path])
    corpus = [[str(p) for p in r["paths"]] for r in rows if r.get("event") == "insight" and r.get("paths")]

    def score(prefix: str) -> float:
        df = sum(1 for ps in corpus if _under(prefix, ps))
        return sum(1 for ps in members if _under(prefix, ps)) * (math.log((1 + len(corpus)) / (1 + df)) + 1)

    chosen: List[str] = []
    uncovered = list(members)
    for prefix in sorted(candidates, key=lambda c: (-score(c), -c.count("/"), c)):
        if len(chosen) == 3 or not uncovered:
            break
        if any(_under(prefix, ps) for ps in uncovered):
            chosen.append(prefix)
            uncovered = [ps for ps in uncovered if not _under(prefix, ps)]
    return [c + "**" if c.endswith("/") else c for c in chosen]


def write_proposal(
    workspace: Any,
    *,
    proposal_id: str,
    insight_ids: Sequence[str],
    summary_bullets: Sequence[str] = (),
    kind: Optional[str] = None,
    home: Optional[Path] = None,
) -> Path:
    """The closed-template proposal (spec T8 Propose): an advisory trap whose kind (the reviewer's,
    else the one its counted insights share), count, ids and target_paths come from the insights."""
    clean_id = proposal_id.strip()
    if not _SAFE_ID_RE.match(clean_id):
        raise ValueError(f"invalid proposal_id {proposal_id!r}")
    # Only human text is protected: an agent capture must not be able to veto a proposal. A
    # short prompt ("no", "revert") protects only a bullet equal to it.
    rows = read_insight_rows(workspace, home=home)
    confirmed = _confirmed(rows)
    confirmed_ids = set(confirmed)
    levels = {id(r): _effective_level(r, confirmed_ids) for r in rows if r.get("event") == "insight"}
    protected = [
        str(r.get("text") or "").strip().lower()
        for r in rows
        if levels.get(id(r)) in ("H", "cli", "W2") and str(r.get("text") or "").strip()
    ]
    typed_kind = " ".join(str(kind).split()) if kind and str(kind).strip() else ""
    typed_clean = redact_insight_text(typed_kind, max_len=64)
    written = [redact_insight_text(str(b).strip(), max_len=200) for b in summary_bullets if str(b).strip()]
    # Stored text is redacted, so a typed copy holding an email or a home path differs from it
    # raw: the forms the proposal writes (the bullet quotes the kind without backticks) are linted too.
    for cand in (kind or "", *summary_bullets, typed_clean, typed_clean.replace("`", ""), *written):
        clow = str(cand).strip().lower()
        if clow and any(ex == clow or (len(ex) >= _VERBATIM_MIN_CHARS and ex in clow)
                        or (len(clow) >= _VERBATIM_MIN_CHARS and clow in ex) for ex in protected):
            raise ValueError("proposal may not contain verbatim H/cli/W2 prompt text")
    ids = list(dict.fromkeys(str(i).strip() for i in insight_ids if str(i).strip()))
    superseded = _superseded(rows)
    counted = {str(r.get("id")): r for r in rows if levels.get(id(r)) in COUNTABLE_LEVELS and id(r) not in superseded}
    missing = [i for i in ids if i not in counted]
    if not ids or missing:
        raise ValueError(f"not a counted insight: {', '.join(missing) or 'none given'}")
    members = [counted[i] for i in ids]
    kinds = sorted({str(k) for k in (confirmed.get(i) if _row_source(r) == "mcp" else r.get("kind")
                                     for i, r in zip(ids, members)) if k})
    chosen_kind = typed_kind or (kinds[0] if len(kinds) == 1 else "")
    if not chosen_kind:
        raise ValueError(f"the insights share no single kind ({', '.join(kinds) or 'none'}); pass --kind")
    member_paths = [[str(p) for p in r.get("paths") or []] for r in members]
    if not any(member_paths):
        raise ValueError("the insights carry no paths, so the proposal would target every file; "
                         "record them with aegis rule insight add --paths")
    targets = _proposal_targets([ps for ps in member_paths if ps], rows)
    clean_kind = redact_insight_text(chosen_kind, max_len=64)
    bullets = [f"{len(members)} counted correction(s) of kind `{clean_kind.replace('`', '')}`."]
    bullets += written
    hyp = f"Prevent recurring {clean_kind} issues in {', '.join(targets)}."
    lines = [
        "---",
        f"id: {clean_id}",
        "type: trap",
        "status: proposal",
        "enforcement: advisory",
        f"kind: {json.dumps(clean_kind)}",
        f"count: {len(members)}",
        f"hypothesis: {json.dumps(hyp)}",
        "target_paths:\n" + "\n".join(f"  - {json.dumps(p)}" for p in targets),
        "insight_ids:\n" + "\n".join(f"  - {json.dumps(i)}" for i in ids),
        "---",
        f"# Proposal: {clean_id}\n",
        "## Guidance\n",
        "\n".join(f"- {b}" for b in bullets) + "\n",
    ]
    prop_dir = WorkspaceLayout(Path(os.fspath(workspace)).resolve()).aegis_dir / "proposals"
    prop_dir.mkdir(parents=True, exist_ok=True)
    target = prop_dir / f"{clean_id}.md"
    atomic_write_text(target, "\n".join(lines))
    return target
