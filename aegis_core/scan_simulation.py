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
    "SimulationBudget",
    "SimulationCache",
    "SimulationHooks",
    "simulate_rule_selection",
]

_STATUS_FAIL = "FAIL"
COLD_SAMPLE_LIMIT, COLD_LIST_LIMIT = 10, 20000
_COLD_NO_SAMPLE = "scan simulation: no sample"
_SIM_SELECTED = "scan simulation: selected in all profiles"
_SIM_OMITTED = "scan simulation: not selected in profiles: "


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


class _SimulationLimit(ValueError):
    pass


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
    Matching candidate bytes must
    match the captured effective rule; a concurrent edit or reviewed-base
    substitution never supplies a verdict about different candidate bytes.
    A served rule absent from that snapshot is judged as if accepted, at fitness 0.0. Refusals are fixed text.
    """
    candidates = ruleset.rules
    def refusal(reason: str) -> Dict[str, str]:
        return dict.fromkeys((rule.id for rule in candidates), "not evaluated: " + reason)

    if not callable(hooks.select_guidance):
        return refusal("scan API unavailable")
    try:
        _check_simulation_inventory(inventory)
        cache = SimulationCache(inventory, ruleset)
        with gitsafe.memo():
            captured = hooks.capture(workspace, None, None, None, None, cache)
        if not isinstance(captured, hooks.result_type):
            return refusal("scan projection failed")
        if not captured._projection.changed_files:
            messages = refusal("no changed files")
        else:
            selected = _simulation_profiles(captured, workspace)
            if selected is None:
                return refusal("scan projection failed")
            messages = _simulation_messages(cache, candidates, selected)
    except _SimulationLimit:
        return refusal("scan inputs over limit")
    except GuidanceProjectionError:
        return refusal("scan projection failed")
    except gitsafe.GitError:
        return refusal("scan inputs unavailable")
    except (OSError, ValueError, RuntimeError):
        return refusal("scan inputs unavailable")
    cold = _cold_candidates(cache, candidates)
    if cold:
        messages.update(_cold_messages(workspace, cache, captured, cold, hooks))
    return messages


def _simulation_profiles(captured: Any, workspace: Any) -> Optional[Dict[str, set]]:
    selected: Dict[str, set] = {}
    for profile in PLATFORM_SLOT_PROFILES:
        result = captured.with_registry(scan_registry(profile, workspace))
        if result.get("status") == _STATUS_FAIL or not isinstance(result, GuidanceResult):
            return None
        selected[profile] = set(result.exposure_rule_ids())
    return selected


def _simulation_messages(cache: SimulationCache, candidates: Tuple[Rule, ...], selected: Dict[str, set]) -> Dict[str, str]:
    messages = {}
    for rule in candidates:
        if rule.id in cache.different_candidates:
            messages[rule.id] = "not evaluated: candidate differs from scan snapshot"
        elif all(rule.id in identities for identities in selected.values()):
            messages[rule.id] = _SIM_SELECTED
        else:
            omitted = sorted(profile for profile, identities in selected.items() if rule.id not in identities)
            messages[rule.id] = _SIM_OMITTED + ", ".join(omitted)
    return messages


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


def _cold_refusal(rules: Tuple[Rule, ...], reason: str) -> Dict[str, str]:
    return dict.fromkeys((rule.id for rule in rules), "not evaluated: " + reason)


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


def _cold_select(workspace: Any, captured: Any, ruleset: RuleSet, files: List[str], fitness_of: Callable[[List[Rule]], Dict[str, Fitness]], select_guidance: Callable[..., Any]) -> Optional[Dict[str, set]]:
    selected: Dict[str, set] = {}
    projection = captured._projection
    # Unaccepted sibling diagnostics are outside this as-if-accepted selection.
    extras = {key: value for key, value in projection.extras.items() if key not in ("unreviewed_rules", "unreviewed_total")}
    for profile in PLATFORM_SLOT_PROFILES:
        result = select_guidance(ruleset, files, projection.budget, projection.token_budget, list(projection.stale), fitness_of, dict(extras), scan_registry(profile, workspace))
        if not isinstance(result, GuidanceResult) or result.get("status") == _STATUS_FAIL:
            return None
        selected[profile] = set(result.exposure_rule_ids())
    return selected


def _cold_verdicts(workspace: Any, cache: SimulationCache, captured: Any, drafts: Tuple[Rule, ...], hooks: SimulationHooks) -> Dict[str, str]:
    listed = _cold_paths(workspace, hooks.output_limit)
    effective = cache.effective
    if listed is None or effective is None:
        return _cold_refusal(drafts, "scan inputs unavailable")
    installed = [rule for rule in effective.rules if rule.served]
    fits = hooks.fitness_of(workspace, installed, adjudications=Adjudications())
    remaining = [hooks.match_budget]
    bounded = hooks.cold_rules(effective.rules + drafts, remaining)
    messages = {}
    for index, rule in enumerate(bounded[len(effective.rules):]):
        try:
            if remaining[0] <= 0:
                raise SimulationBudget
            rules = bounded[:len(effective.rules)] + (rule,)
            files = _cold_sample(rules[-1], listed)
            if not files:
                messages[rule.id] = _COLD_NO_SAMPLE
                continue
            scored = {**fits, rule.id: Fitness(rule=rule.id, score=0.0)}
            ruleset = RuleSet(rules, effective.ignored, effective.fingerprint)
            selected = _cold_select(workspace, captured, ruleset, files, lambda served: {r.id: scored[r.id] for r in served}, hooks.select_guidance)
            if selected is None:
                messages[rule.id] = "not evaluated: scan projection failed"
                continue
            omitted = sorted(name for name, identities in selected.items() if rule.id not in identities)
            messages[rule.id] = _SIM_OMITTED + ", ".join(omitted) if omitted else _SIM_SELECTED
        except SimulationBudget:
            messages.update(_cold_refusal(drafts[index:], "simulation budget exceeded"))
            break
    return messages


def _cold_messages(workspace: Any, cache: SimulationCache, captured: Any, drafts: Tuple[Rule, ...], hooks: SimulationHooks) -> Dict[str, str]:
    try:
        return _cold_verdicts(workspace, cache, captured, drafts, hooks)
    except _SimulationLimit:
        return _cold_refusal(drafts, "scan inputs over limit")
    except GuidanceProjectionError:
        return _cold_refusal(drafts, "scan projection failed")
    except gitsafe.GitError as exc:
        return _cold_refusal(drafts, "scan inputs over limit" if exc.code == "git_output_limit" else "scan inputs unavailable")
    except (OSError, ValueError, RuntimeError):
        return _cold_refusal(drafts, "scan inputs unavailable")


