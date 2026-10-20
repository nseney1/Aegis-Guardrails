"""The scan service: the rules that apply to the files about to change.

aegis_scan (MCP) and ``aegis scan`` (CLI) both call ``scan``. Instead of loading every
rule into a system prompt, it returns only the rules for the changed files:

1. Rules come from the one loader (aegis_core.rules) through a per-workspace cache. If
   any rule file cannot be loaded, the scan fails closed and names it: a partial rule
   set is never presented as the whole one.
2. Rules match files as ``Rule.applies_to`` says (the one matcher, aegis_core.match,
   plus the forbid_ast test-file policy aegis check enforces).
3. Mandatory rules (gates and invariants, and rules declaring ``enforcement: gate``)
   come first but take at most MANDATORY_SLOT_CAP of the ``budget`` rule slots; the
   rest go to advisory rules by ledger fitness (aegis_core.fitness). Mandatory rules
   that do not get a slot are listed in ``omitted_mandatory``, never dropped silently.
4. The whole response is clamped to the token budget (AEGIS_MAX_JIT_TOKENS or
   ``.aegis/config.json`` jit.max_tokens): a rule that does not fit is omitted and
   counted, and a lower-priority rule never displaces a higher one.
5. ``stale_rules`` lists rules edited since the last ``aegis sync``; they are served
   like any other rule. Markdown under .aegis/rules that is not a rule costs one bounded
   ``warnings`` line.
6. Rules that bind (gates, invariants, ``enforcement: gate``) are the reviewed BASE
   versions (aegis_core.rule_integrity), not the working tree's: ``rules_base`` says which
   commit and whether it is review-witnessed, and ``unreviewed_rules`` lists (id, title and
   kind of change only) what this branch added, changed or removed. Those are never served
   as mandatory. Outside git nothing is anchored and neither key appears.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePath
import posixpath
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_core.adjudication import Adjudications
from aegis_core.fitness import Fitness, compute, for_rules
from aegis_core.match import normalize_path, workspace_files
from aegis_core import rule_integrity
from aegis_core.rule_integrity import MANDATORY_SLOT_CAP
from aegis_core.rule_inventory import RuleInventoryError
from aegis_core.rules import Rule, RuleCache, RuleSet, workspace_root
from aegis_core.taxonomy import (
    JIT_DEFAULT_MAX_TOKENS,
    JIT_DEFAULT_RULE_COUNT_BUDGET,
    RULE_TYPES,
    RuleType,
    WORDS_TO_TOKENS_FACTOR,
)
from aegis_core.workspace.layout import RULES_RELDIR

__all__ = [
    "MANDATORY_SLOT_CAP",
    "NO_CHANGES_TEXT",
    "NO_MATCH_TEXT",
    "RULE_CACHE",
    "estimate_tokens",
    "resolve_token_budget",
    "scan",
    "scan_user_layer",
]

# Per-process cache of parsed rules; the MCP server keeps it across tool calls.
RULE_CACHE = RuleCache()

# MANDATORY_SLOT_CAP (aegis_core.rule_integrity): mandatory rules may take at most that many
# of a scan's rule slots, so a few rules that declare themselves mandatory on `**` cannot
# starve every advisory rule. Adding one past it is a governance change aegis check --ci flags.

# The server sends a scan as json.dumps(result), which is ASCII, so a response the
# budget admits is at most 4 bytes per budgeted token.
ASCII_CHARS_PER_TOKEN = 4

NO_CHANGES_TEXT = "No changed files detected. Governance guidance will be provided when files are modified."
NO_MATCH_TEXT = "No governance rules match your current changes."
_STATUS_FAIL = "FAIL"


def estimate_tokens(text: object | None) -> int:
    """Estimate a token count: the larger of ~1.35 per word and one per 4 ASCII characters
    plus one per non-ASCII character.

    A word count alone sees text without spaces (CJK, base64, a minified line) as a
    single word, so the character floor is what lets the budget bound the bytes sent.
    """
    if text is None:
        return 0
    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return 0
    ascii_chars = len(text.encode("ascii", "ignore"))
    by_chars = -(-ascii_chars // ASCII_CHARS_PER_TOKEN) + (len(text) - ascii_chars)
    by_words = int(len(text.split()) * WORDS_TO_TOKENS_FACTOR)
    return max(by_words, by_chars)


def resolve_token_budget(workspace: Any, max_tokens: Optional[int] = None) -> int:
    """Token budget: argument > AEGIS_MAX_JIT_TOKENS > .aegis/config.json jit.max_tokens > default."""
    if max_tokens is not None:
        try:
            return int(max_tokens)
        except (ValueError, TypeError):
            pass
    from aegis_core.config import jit_max_tokens

    return jit_max_tokens(workspace, JIT_DEFAULT_MAX_TOKENS)


def _git_changed_files(workspace: Any) -> List[str]:
    """Files changed in the working tree or the index."""
    from aegis_core import gitsafe

    return gitsafe.changed_files(workspace, "working") or []


@dataclass(frozen=True)
class _Match:
    rule: Rule
    files: Tuple[str, ...]
    exact: bool
    fitness: Fitness


def _match(rule: Rule, matched: Tuple[str, ...], fitness: Fitness) -> _Match:
    exact = any(normalize_path(p) == normalize_path(f) for p in rule.target_paths for f in matched)
    return _Match(rule, matched, exact, fitness)


def _mandatory_tier(rule: Rule) -> int:
    if rule.type == RuleType.GATE:
        return 3
    if rule.type == RuleType.INVARIANT:
        return 2
    return 1  # a rule that declares enforcement: gate


def _rank(matches: List[_Match], mandatory: bool) -> List[_Match]:
    def key(m: _Match) -> tuple:
        tier = -_mandatory_tier(m.rule) if mandatory else 0
        return (tier, -m.fitness.score, not m.exact, -len(m.files), m.rule.id)

    return sorted(matches, key=key)


def _item(m: _Match) -> Dict[str, Any]:
    rule = m.rule
    spec = RULE_TYPES.get(rule.type or "")
    return {
        "name": rule.id,
        "_path": rule.path,
        "type": rule.type,
        "enforcement": spec.label if spec else str(rule.type).upper(),
        "hypothesis": rule.meta.get("hypothesis", ""),
        "prediction": rule.meta.get("prediction", ""),
        "matched_files": list(m.files),
        "fitness": m.fitness.reported_score,
    }


def _fitness_text(fit: Fitness) -> str:
    if fit.reported_score is not None:
        return f"{fit.reported_score:.2f}"
    if fit.evidence_available and not fit.triggers and not fit.verdicts:
        return "no evidence yet"
    return fit.status_label or "—"


def _text(m: _Match) -> str:
    rule = m.rule
    spec = RULE_TYPES.get(rule.type or "")
    emoji = spec.emoji if spec else "📋"
    label = spec.label if spec else str(rule.type).upper()
    out = f"{emoji} [{label}] {rule.id}\n"
    out += f"   Hypothesis: {rule.meta.get('hypothesis', '')}\n"
    prediction = rule.meta.get("prediction")
    if prediction:
        out += f"   If violated: {prediction}\n"
    out += f"   Triggered by: {', '.join(m.files[:5])}\n"
    if rule.body:
        lines = rule.body.strip().split("\n")[:8]
        out += f"   Detail: {' '.join(line.strip() for line in lines)[:300]}\n"
    out += f"   Fitness: {_fitness_text(m.fitness)}\n"
    return out


def _constraint(m: _Match) -> Dict[str, Any]:
    rule = m.rule
    return {
        "name": rule.id,
        "type": rule.type,
        "tier": rule.enforcement,
        "hypothesis": rule.meta.get("hypothesis", ""),
        "prediction": rule.meta.get("prediction", ""),
        "matched_files": list(m.files),
    }


def _is_invariant(constraint: Dict[str, Any]) -> bool:
    return constraint.get("type") == RuleType.INVARIANT


def _omitted_line(omitted: int) -> str:
    noun = "rule" if omitted == 1 else "rules"
    return f"⚠️ {omitted} more {noun} omitted (raise AEGIS_MAX_JIT_TOKENS)"


def _omitted_mandatory_line(total: int, names: List[str]) -> str:
    noun = "rule applies" if total == 1 else "rules apply"
    line = f"⚠️ {total} more mandatory {noun} to these files and {'was' if total == 1 else 'were'} not shown"
    if names:
        line += ": " + ", ".join(names)
        if len(names) < total:
            line += f" and {total - len(names)} more"
    return line


def _invariant_line(constraint: Dict[str, Any]) -> str:
    return f"- 🧱 [INVARIANT] {constraint['name']}: {constraint['hypothesis']}\n"


def _render(staged: List[Dict[str, Any]], omitted: int, mandatory_total: int, mandatory_named: List[str]) -> str:
    parts: List[str] = []
    invariants = [s for s in staged if _is_invariant(s["constraint"])]
    if invariants:
        parts.append("## Pre-Edit Invariants & Constraints\n")
        parts.append("CRITICAL: You must adhere to the following invariants when modifying target files:\n")
        parts.extend(_invariant_line(s["constraint"]) for s in invariants)
    if staged:
        parts.append("## Active Governance Rules\n")
        parts.extend(s["text"] for s in staged)
    if omitted:
        parts.append(f"\n{_omitted_line(omitted)}\n")
    if mandatory_total:
        parts.append(f"\n{_omitted_mandatory_line(mandatory_total, mandatory_named)}\n")
    return "\n".join(parts) if parts else NO_MATCH_TEXT


def _payload(
    staged: List[Dict[str, Any]],
    omitted: int,
    omitted_mandatory: List[Dict[str, Any]],
    shown: int,
    stats: Dict[str, Any],
    stale: List[Dict[str, Any]],
    warnings: List[str],
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """The response; ``shown`` of the ``omitted_mandatory`` entries are listed by name
    (all of them unless the token budget cannot hold them), and all are counted.
    ``extras`` are added as they are: they count against the token budget like the rest."""
    listed = omitted_mandatory[:shown]
    guidance = _render(staged, omitted, len(omitted_mandatory), [o["name"] for o in listed])
    payload: Dict[str, Any] = {
        "relevant_rules": [s["item"] for s in staged],
        "guidance": guidance,
        "invariant_warnings": [s["constraint"] for s in staged if _is_invariant(s["constraint"])],
        "rules_staged": len(staged),
        "omitted_mandatory": listed,
        "stale_rules": stale,
        "stats": dict(stats, clamped=omitted > 0, omitted=omitted, omitted_mandatory=len(omitted_mandatory)),
    }
    if warnings:
        payload["warnings"] = list(warnings)
    if extras:
        payload.update(extras)
    return payload


def _tokens(value: object) -> int:
    """Tokens of a value as the server serializes it (json.dumps, ASCII-escaped)."""
    return estimate_tokens(json.dumps(value))


def _failure(message: str, rule_errors: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"status": _STATUS_FAIL, "error": message}
    if rule_errors is not None:
        result["rule_errors"] = rule_errors
    return result


_IGNORED_NAMED = 3


def _ignored_warning(ruleset: RuleSet) -> str:
    """One bounded line however many files are ignored: every scan response pays for it."""
    paths = [i.path for i in ruleset.ignored]
    head = (
        f"1 file under {RULES_RELDIR} is not a rule and was ignored" if len(paths) == 1
        else f"{len(paths)} files under {RULES_RELDIR} are not rules and were ignored"
    )
    named = ", ".join(paths[:_IGNORED_NAMED])
    more = f" and {len(paths) - _IGNORED_NAMED} more" if len(paths) > _IGNORED_NAMED else ""
    return f"{head} (aegis status lists why): {named}{more}"


def _broken(ruleset: RuleSet) -> Dict[str, Any]:
    errors = [{"path": r.path, "error": r.error or ""} for r in ruleset.errors]
    listed = "; ".join(f"{e['path']}: {e['error']}" for e in errors[:5])
    more = f" (and {len(errors) - 5} more)" if len(errors) > 5 else ""
    return _failure(
        f"{len(errors)} rule file(s) cannot be served, so no partial rule set is returned: "
        f"{listed}{more}. Fix or move them; `aegis status` lists them.",
        errors,
    )


def scan(
    workspace: Any,
    changed_files: Optional[List[str]] = None,
    budget: Optional[int] = None,
    max_tokens: Optional[int] = None,
) -> Dict[str, Any]:
    """The rules for ``changed_files`` (default: the git working tree and index changes).

    ``budget`` is the number of rule slots (default JIT_DEFAULT_RULE_COUNT_BUDGET);
    ``max_tokens`` bounds the whole response. Returns ``{"status": "FAIL", "error"}``
    (with ``rule_errors``) when the rules cannot all be loaded.
    """
    from aegis_core.sync import read_derived, stale_rules

    token_budget = resolve_token_budget(workspace, max_tokens)
    try:
        view = rule_integrity.effective(workspace, RULE_CACHE)
    except RuleInventoryError as exc:
        return _failure(f"the rules directory cannot be read safely: {exc}")
    except rule_integrity.IntegrityError as exc:
        return _failure(f"the reviewed (base) version of the rules cannot be read, so none is served: {exc}")
    ruleset = view.ruleset
    if ruleset.errors:
        return _broken(ruleset)

    # Workspace-relative, each file once, as every other surface matches them.
    files = workspace_files(workspace_root(workspace), changed_files if changed_files else _git_changed_files(workspace))
    stale = stale_rules(ruleset, read_derived(workspace))
    # Labels are read only by decision callers: scan ranks without them and spawns no git for them.
    return _select(ruleset, files, budget, token_budget, stale,
                   lambda served: for_rules(workspace, served, adjudications=Adjudications()), _integrity_extras(view))


# Titles are branch-local text that reaches an agent: only the first few are listed.
_UNREVIEWED_LISTED = 10


def _integrity_extras(view: "rule_integrity.Effective") -> Dict[str, Any]:
    """``rules_base`` and ``unreviewed_rules`` (id, title, kind of change; nothing else) for a scan."""
    if view.anchor is None:
        return {}
    extras: Dict[str, Any] = {"rules_base": view.anchor.as_dict()}
    if view.unreviewed:
        extras["unreviewed_rules"] = [u.as_dict() for u in view.unreviewed[:_UNREVIEWED_LISTED]]
        if len(view.unreviewed) > _UNREVIEWED_LISTED:
            extras["unreviewed_total"] = len(view.unreviewed)
    return extras


def _trim_unreviewed(extras: Dict[str, Any]) -> bool:
    """Drop the last listed unreviewed rule (branch-local text, bounded by the budget like the rest),
    keeping the true count; False when none is listed."""
    listed = extras.pop("unreviewed_rules", None)
    if not listed:
        return False
    extras.setdefault("unreviewed_total", len(listed))
    if len(listed) > 1:
        extras["unreviewed_rules"] = listed[:-1]
    return True


def scan_user_layer(
    changed_files: Optional[List[str]] = None,
    budget: Optional[int] = None,
    max_tokens: Optional[int] = None,
) -> Dict[str, Any]:
    """The rules of the read-only user layer (``~/.aegis/rules``, ADR 0005 H8) for files
    in no governed workspace.

    There is no workspace, so there is no ledger (every rule has neutral fitness), no
    derived state, no repository config and no git diff: only the given files are
    matched. Nothing is created or written; a missing layer serves no rules.
    ``user_layer`` reports the directory and how many rules it serves.
    """
    from aegis_core.workspace.layout import UserLayout

    token_budget = resolve_token_budget(None, max_tokens)
    layout = UserLayout.current()
    ruleset = RuleSet(())
    if layout is not None and layout.rules_dir.is_dir() and not layout.rules_dir.is_symlink():
        try:
            ruleset = RULE_CACHE.get(layout.home)
        except RuleInventoryError as exc:
            return _failure(f"the user rules directory cannot be read safely: {exc}")
        if ruleset.errors:
            return _broken(ruleset)
    neutral = compute({})
    payload = _select(ruleset, _layer_files(changed_files or []), budget, token_budget, [],
                      lambda served: {rule.id: neutral for rule in served})
    payload["user_layer"] = {"path": _layer_path(layout.rules_dir) if layout is not None else None,
                             "rules": len(ruleset.served)}
    return payload


def _layer_path(rules_dir: Path) -> str:
    """Where the user layer lives: its parent resolved, the last part as is, so a
    symlinked rules directory (never served) is reported where it is, not where it points."""
    try:
        return str(rules_dir.parent.resolve() / rules_dir.name)
    except (OSError, RuntimeError, ValueError):  # a symlink loop raises RuntimeError before 3.13
        return str(rules_dir)


def _layer_files(files: List[str]) -> List[str]:
    """Files as POSIX paths for the user layer: there is no root to make them relative
    to, so an absolute path loses only its anchor (``**/`` and basename patterns match)."""
    out: List[str] = []
    for raw in files:
        if not isinstance(raw, str) or not raw.strip():
            continue
        pure = PurePath(raw)
        if pure.is_absolute():
            rel = pure.as_posix()[len(pure.anchor.replace("\\", "/")):]
        else:
            rel = posixpath.normpath(normalize_path(raw))
        if rel in ("", ".", "..") or rel.startswith("../") or rel in out:
            continue
        out.append(rel)
    return out


def _select(
    ruleset: RuleSet,
    files: List[str],
    budget: Optional[int],
    token_budget: int,
    stale: List[Dict[str, Any]],
    fitness_of: Callable[[List[Rule]], Dict[str, Fitness]],
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Match, rank, slot and clamp ``ruleset``'s served rules for ``files``."""
    slots = JIT_DEFAULT_RULE_COUNT_BUDGET if budget is None else max(0, int(budget))
    served = list(ruleset.served)
    warnings = [_ignored_warning(ruleset)] if ruleset.ignored else []
    stats = {
        "total_rules": len(served),
        "matched": 0,
        "budget": slots,
        "changed_files": len(files),
        "estimated_tokens": 0,
        "max_tokens_budget": token_budget,
    }
    extras = dict(extras or {})
    if not files:
        while True:
            payload = _payload([], 0, [], 0, stats, stale, warnings, extras)
            payload["guidance"] = NO_CHANGES_TEXT
            payload["stats"]["estimated_tokens"] = _tokens(payload)
            if payload["stats"]["estimated_tokens"] <= token_budget or not _trim_unreviewed(extras):
                return payload

    # Fitness reads the ledger and projects credit: only for rules that matched, and only if any did.
    hits = [(r, f) for r, f in ((r, tuple(r.matching_files(files))) for r in served) if f]
    fits = fitness_of([r for r, _f in hits]) if hits else {}
    matches = [_match(r, f, fits[r.id]) for r, f in hits]
    stats["matched"] = len(matches)
    mandatory = _rank([m for m in matches if m.rule.mandatory], mandatory=True)
    advisory = _rank([m for m in matches if not m.rule.mandatory], mandatory=False)
    cap = min(MANDATORY_SLOT_CAP, slots)
    chosen = mandatory[:cap]
    capped = mandatory[cap:]
    chosen += advisory[:max(0, slots - len(chosen))]

    entries = [{"match": m, "item": _item(m), "text": _text(m), "constraint": _constraint(m)} for m in chosen]
    omitted_mandatory = [{"name": m.rule.id, "type": m.rule.type, "reason": "slot_cap"} for m in capped]

    # Fill in priority order and stop at the first rule that does not fit, so a
    # lower-priority rule never displaces a higher one. Then confirm against the
    # serialized response: the per-entry estimate is additive only up to rounding.
    # The count of omitted mandatory rules is always reported; their names are listed
    # as far as the budget allows, after the rules themselves.
    used = _tokens(_payload([], 1, omitted_mandatory, 0, stats, stale, warnings, extras))
    staged: List[Dict[str, Any]] = []
    clamped: List[Dict[str, Any]] = []
    for entry in entries:
        cost = _tokens(entry["item"]) + _tokens(entry["text"])
        if _is_invariant(entry["constraint"]):
            cost += _tokens(entry["constraint"]) + _tokens(_invariant_line(entry["constraint"]))
        if clamped or used + cost > token_budget:
            clamped.append(entry)
            continue
        staged.append(entry)
        used += cost

    def note_clamped(entry: Dict[str, Any]) -> None:
        rule = entry["match"].rule
        if rule.mandatory:
            omitted_mandatory.append({"name": rule.id, "type": rule.type, "reason": "token_budget"})

    for entry in clamped:
        note_clamped(entry)
    shown = len(omitted_mandatory)
    while True:
        payload = _payload(staged, len(clamped), omitted_mandatory, shown, stats, stale, warnings, extras)
        # Measure with the widest count that can pass, so writing the real one cannot overflow.
        payload["stats"]["estimated_tokens"] = token_budget
        tokens = _tokens(payload)
        if tokens <= token_budget:
            break
        if shown:
            shown -= 1  # names go before rules do
        elif _trim_unreviewed(extras):
            pass  # then the unreviewed list, last entry first
        elif staged:
            entry = staged.pop()
            clamped.insert(0, entry)
            note_clamped(entry)
            shown = 0
        else:
            break  # a budget below the empty response: nothing more can go
    payload["stats"]["estimated_tokens"] = tokens
    return payload
