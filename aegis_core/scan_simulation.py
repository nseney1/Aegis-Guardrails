"""Bounded lint simulation over a captured scan and request-local selection hooks."""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_core import gitsafe
from aegis_core.adjudication import Adjudications
from aegis_core.fitness import Fitness
from aegis_core.guidance_projection import GuidanceProjectionError, GuidanceResult
from aegis_core.match import normalize_path
from aegis_core.packs import MAX_RULE_BYTES
from aegis_core.rule_inventory import RuleInventory
from aegis_core.rules import Rule, RuleCache, RuleSet, workspace_root
from aegis_core.skills.slots import PLATFORM_SLOT_PROFILES, scan_registry

__all__ = [
    "COLD_LIST_LIMIT",
    "COLD_SAMPLE_LIMIT",
    "ColdRule",
    "SIMULATION_FAIL_STATUS",
    "SimulationBudget",
    "SimulationCache",
    "SimulationHooks",
    "simulate_rule_selection",
]

COLD_SAMPLE_LIMIT, COLD_LIST_LIMIT = 10, 20000
SIMULATION_FAIL_STATUS = "FAIL"
_NOT_EVALUATED = "not evaluated: "
_REASON_OVER_LIMIT = "scan inputs over limit"
_REASON_UNAVAILABLE = "scan inputs unavailable"
_REASON_PROJECTION = "scan projection failed"
_REASON_API = "scan API unavailable"
_REASON_BUDGET = "simulation budget exceeded"
_REASON_DIFFERS = "candidate differs from scan snapshot"
_REASON_NO_CHANGES = "no changed files"
_INSTALLED_SELECTED = "scan simulation: selected in all profiles"
_COLD_SELECTED = "scan simulation: would be selected in all profiles at cold start"
_COLD_NO_SAMPLE = "scan simulation: no sample for hypothetical cold start"
_INSTALLED_OMITTED = "scan simulation: not selected in profiles: "
_COLD_NEVER = "scan simulation: never served at cold start"
_MODE_INSTALLED = "installed"
_MODE_COLD = "cold"


@dataclass(frozen=True)
class SimulationHooks:
    """Capture the caller's replaceable seams once, without rebinding module globals."""

    capture: Callable[..., Any]
    result_type: type
    select_guidance: Optional[Callable[..., Any]]
    fitness_of: Callable[..., Dict[str, Fitness]]
    cold_rules: Callable[[Tuple[Rule, ...], List[int]], Tuple[Rule, ...]]
    output_limit: int
    match_budget: int
    fail_status: str = SIMULATION_FAIL_STATUS


class _SimulationLimit(ValueError):
    pass


_SIMULATION_FAILURES = (
    _SimulationLimit, GuidanceProjectionError, gitsafe.GitError, OSError, ValueError, RuntimeError)


def _not_evaluated(rules: Tuple[Rule, ...], reason: str) -> Dict[str, str]:
    """One refusal prefix for capture-wide and cold-only rows."""
    return dict.fromkeys((rule.id for rule in rules), _NOT_EVALUATED + reason)


def _failure_reason(exc: BaseException) -> str:
    """Map one simulation failure to a fixed reason. Exception text is never copied."""
    if isinstance(exc, _SimulationLimit):
        return _REASON_OVER_LIMIT
    if isinstance(exc, GuidanceProjectionError):
        return _REASON_PROJECTION
    if isinstance(exc, gitsafe.GitError):
        if exc.code == "git_output_limit":
            return _REASON_OVER_LIMIT
        return _REASON_UNAVAILABLE
    return _REASON_UNAVAILABLE


def _omitted_profiles(rule_id: str, selected: Dict[str, set]) -> List[str]:
    return sorted(name for name, identities in selected.items() if rule_id not in identities)


def _simulation_verdict(mode: str, rule_id: str, selected: Optional[Dict[str, set]], *,
                        differs: bool = False, sample_count: Optional[int] = None) -> str:
    """One mode-aware verdict for an installed rule or a hypothetical cold draft."""
    if differs:
        return _NOT_EVALUATED + _REASON_DIFFERS
    if mode == _MODE_COLD:
        if not sample_count:
            return _COLD_NO_SAMPLE
        omitted = _omitted_profiles(rule_id, selected or {})
        if not omitted:
            return _COLD_SELECTED
        message = _COLD_NEVER + " (0/" + str(sample_count) + ")"
        if selected is not None and len(omitted) < len(selected):
            return message + " in profiles: " + ", ".join(omitted)
        return message
    if selected is None:
        return _NOT_EVALUATED + _REASON_NO_CHANGES
    omitted = _omitted_profiles(rule_id, selected)
    if not omitted:
        return _INSTALLED_SELECTED
    return _INSTALLED_OMITTED + ", ".join(omitted)


def _projection_failed(result: Any, fail_status: str, *, status_first: bool) -> bool:
    if status_first:
        return result.get("status") == fail_status or not isinstance(result, GuidanceResult)
    return not isinstance(result, GuidanceResult) or result.get("status") == fail_status


def _check_simulation_inventory(inventory: RuleInventory) -> None:
    """Refuse a source before parsing; never reread lint's captured paths."""
    if len(inventory.entries) > 2048:
        raise _SimulationLimit
    total = 0
    for entry in inventory.entries:
        size = max(entry.size, len(entry.content))
        total += size
        if size > MAX_RULE_BYTES or total > 8 * 1024 * 1024:
            raise _SimulationLimit


class SimulationCache(RuleCache):
    """Reuse lint's checked working bytes; bound any differing reviewed source."""

    def __init__(self, inventory: RuleInventory, ruleset: RuleSet) -> None:
        super().__init__()
        self.captured = inventory, ruleset
        self.different_candidates: frozenset[str] = frozenset()
        self.effective: Optional[RuleSet] = None

    def compare_candidates(self, effective: RuleSet) -> None:
        """Compare the full effective snapshot before any file matching occurs."""
        source = {rule.id: rule for rule in effective.rules}
        self.effective = effective
        self.different_candidates = frozenset(
            rule.id for rule in self.captured[1].rules
            if rule.id not in source or source[rule.id].path != rule.path or source[rule.id].raw != rule.raw)

    def snapshot(self, workspace: Any) -> Tuple[RuleInventory, RuleSet]:
        return self.captured

    def base_rules(self, root: str, inventory: RuleInventory, load: Callable[[], RuleSet]) -> RuleSet:
        _check_simulation_inventory(inventory)
        return super().base_rules(root, inventory, load)


def simulate_rule_selection(workspace: Any, inventory: RuleInventory, ruleset: RuleSet, hooks: SimulationHooks) -> Dict[str, str]:
    """Lint current changed files through real scan selection, without writes.

    Use lint's bounded working snapshot to capture scan's effective rules,
    fitness, defaults and envelope once, then replay each built-in host registry.
    Installed verdicts require identical captured candidate bytes, including for
    amendments. New served rules absent from that snapshot are judged individually
    as if accepted, at fitness 0.0. Refusals are fixed text.
    """
    candidates = ruleset.rules

    def refusal(reason: str) -> Dict[str, str]:
        return _not_evaluated(candidates, reason)

    if not callable(hooks.select_guidance):
        return refusal(_REASON_API)
    try:
        _check_simulation_inventory(inventory)
        cache = SimulationCache(inventory, ruleset)
        with gitsafe.memo():
            captured = hooks.capture(workspace, None, None, None, None, cache)
        if not isinstance(captured, hooks.result_type):
            return refusal(_REASON_PROJECTION)
        if not captured._projection.changed_files:
            messages = _simulation_messages(cache, candidates, None)
        else:
            selected = _simulation_profiles(captured, workspace, hooks.fail_status)
            if selected is None:
                return refusal(_REASON_PROJECTION)
            messages = _simulation_messages(cache, candidates, selected)
    except _SIMULATION_FAILURES as exc:
        return refusal(_failure_reason(exc))
    cold = _cold_candidates(cache, candidates)
    if cold:
        messages.update(_cold_messages(workspace, cache, captured, cold, hooks))
    return messages


def _simulation_profiles(captured: Any, workspace: Any, fail_status: str) -> Optional[Dict[str, set]]:
    selected: Dict[str, set] = {}
    for profile in PLATFORM_SLOT_PROFILES:
        result = captured.with_registry(scan_registry(profile, workspace))
        if _projection_failed(result, fail_status, status_first=True):
            return None
        selected[profile] = set(result.exposure_rule_ids())
    return selected


def _simulation_messages(cache: SimulationCache, candidates: Tuple[Rule, ...], selected: Optional[Dict[str, set]]) -> Dict[str, str]:
    return {rule.id: _simulation_verdict(
        _MODE_INSTALLED, rule.id, selected, differs=rule.id in cache.different_candidates)
        for rule in candidates}


def _cold_candidates(cache: SimulationCache, candidates: Tuple[Rule, ...]) -> Tuple[Rule, ...]:
    effective = cache.effective
    if effective is None:
        return ()
    installed = {rule.id for rule in effective.rules}
    chosen: Dict[str, Rule] = {}
    for rule in candidates:
        if rule.served and rule.id not in installed:
            chosen.setdefault(rule.id, rule)
    return tuple(chosen.values())


def _cold_path_ok(path: object) -> bool:
    if not isinstance(path, str) or not 0 < len(path) <= 1024:
        return False
    if any(char in path for char in ("\x00", "\\", "\n", "\r")):
        return False
    if path.startswith("/") or PurePath(path).is_absolute():
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def _cold_paths(workspace: Any, output_limit: int) -> Optional[Tuple[str, ...]]:
    # No stdin: capture never opens scratch. Retain an existing caller's custody.
    with nullcontext() if gitsafe.custody_active() else gitsafe.custody(scratch=Path(workspace_root(workspace)).anchor, stdout_limit=output_limit):
        listed = gitsafe.list_files(workspace)
    if not isinstance(listed, (list, tuple)):
        return None
    if len(listed) > COLD_LIST_LIMIT:
        raise _SimulationLimit
    return tuple(sorted(path for path in listed if _cold_path_ok(path)))


class SimulationBudget(ValueError):
    pass


@dataclass(frozen=True)
class ColdRule(Rule):
    """A frozen source rule sharing the lint run's bounded, memoized matcher."""
    _match_path: Optional[Callable[[Rule, str, bool], bool]] = field(default=None, repr=False, compare=False)

    def applies_to(self, path: str, *, exact: bool = False) -> bool:
        if self._match_path is None:
            raise SimulationBudget
        return self._match_path(self, path, exact)

    def rank_exact(self, matched: Tuple[str, ...]) -> bool:
        """Exact ranking through this draft's bounded matcher."""
        return any(self.applies_to(path, exact=True) for path in matched)

    def matching_files(self, files: List[str]) -> List[str]:
        return [path for path in dict.fromkeys(map(normalize_path, files)) if self.applies_to(path)]


def _cold_sample(draft: Rule, paths: Tuple[str, ...]) -> List[str]:
    sample: List[str] = []
    for path in paths:
        if draft.applies_to(path):
            sample.append(path)
            if len(sample) == COLD_SAMPLE_LIMIT:
                break
    return sample


def _cold_select(workspace: Any, captured: Any, ruleset: RuleSet, files: List[str], fitness_of: Callable[[List[Rule]], Dict[str, Fitness]], select_guidance: Callable[..., Any], fail_status: str) -> Optional[Dict[str, set]]:
    selected: Dict[str, set] = {}
    projection = captured._projection
    # Unaccepted sibling diagnostics are outside this as-if-accepted selection.
    extras = {key: value for key, value in projection.extras.items() if key not in ("unreviewed_rules", "unreviewed_total")}
    for profile in PLATFORM_SLOT_PROFILES:
        selected[profile] = set()
        registry = scan_registry(profile, workspace)
        for path in files:
            result = select_guidance(ruleset, [path], projection.budget, projection.token_budget, list(projection.stale), fitness_of, dict(extras), registry)
            if _projection_failed(result, fail_status, status_first=False):
                return None
            selected[profile].update(result.exposure_rule_ids())
    return selected


def _cold_verdicts(workspace: Any, cache: SimulationCache, captured: Any, drafts: Tuple[Rule, ...], hooks: SimulationHooks) -> Dict[str, str]:
    listed = _cold_paths(workspace, hooks.output_limit)
    effective = cache.effective
    if listed is None or effective is None:
        return _not_evaluated(drafts, _REASON_UNAVAILABLE)
    installed = [rule for rule in effective.rules if rule.served]
    fits = hooks.fitness_of(workspace, installed, adjudications=Adjudications())
    remaining = [hooks.match_budget]
    bounded = hooks.cold_rules(effective.rules + drafts, remaining)
    messages = {}
    for index, rule in enumerate(bounded[len(effective.rules):]):
        try:
            if remaining[0] <= 0:
                raise SimulationBudget
            rules = tuple(installed for installed in bounded[:len(effective.rules)] if installed.id != rule.id) + (rule,)
            files = _cold_sample(rules[-1], listed)
            if not files:
                messages[rule.id] = _simulation_verdict(_MODE_COLD, rule.id, None, sample_count=0)
                continue
            scored = {**fits, rule.id: Fitness(rule=rule.id, score=0.0)}
            ruleset = RuleSet(rules, effective.ignored, effective.fingerprint)
            selected = _cold_select(workspace, captured, ruleset, files, lambda served: {r.id: scored[r.id] for r in served}, hooks.select_guidance, hooks.fail_status)
            if selected is None:
                messages[rule.id] = _NOT_EVALUATED + _REASON_PROJECTION
                continue
            messages[rule.id] = _simulation_verdict(_MODE_COLD, rule.id, selected, sample_count=len(files))
        except SimulationBudget:
            messages.update(_not_evaluated(drafts[index:], _REASON_BUDGET))
            break
    return messages


def _cold_messages(workspace: Any, cache: SimulationCache, captured: Any, drafts: Tuple[Rule, ...], hooks: SimulationHooks) -> Dict[str, str]:
    try:
        return _cold_verdicts(workspace, cache, captured, drafts, hooks)
    except _SIMULATION_FAILURES as exc:
        return _not_evaluated(drafts, _failure_reason(exc))


