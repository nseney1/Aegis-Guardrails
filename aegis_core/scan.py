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

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import json
from pathlib import Path, PurePath
import posixpath
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis_core.adjudication import Adjudications
from aegis_core.fitness import Fitness, compute, for_rules
from aegis_core.guidance_projection import (
    ASCII_CHARS_PER_TOKEN as ASCII_CHARS_PER_TOKEN,
    GuidanceProjectionError, GuidanceResult, ScanExposure, ServedRule,
    MAX_GUIDANCE_CHARS, WITHHELD_GUIDANCE,
    assembled_text, checked_result_copy, raw_rule_text,
    estimate_tokens as estimate_tokens,
    field_text, finish_payload, project_detail, project_display_data, project_display_text,
    project_error_name, project_field, project_identifier,
    projection_refusal, projection_refusal_reason, projection_refusal_repair, rule_error_rows_fit,
)
from aegis_core.match import normalize_path, workspace_files
from aegis_core import gitsafe, match as rule_match, rule_integrity
from aegis_core.rule_integrity import MANDATORY_SLOT_CAP, PolicyProvenance, ServedPolicy, policy_provenance
from aegis_core.rule_inventory import RuleInventory, RuleInventoryError
from aegis_core.rules import Rule, RuleCache, RuleSet, load_rules, workspace_root
from aegis_core.skills.slots import SlotRegistry
from aegis_core.scan_simulation import (
    COLD_LIST_LIMIT as _COLD_LIST_LIMIT,
    ColdRule as _ColdRule, SIMULATION_FAIL_STATUS as _STATUS_FAIL,
    SimulationBudget as _SimulationBudget,
    SimulationHooks,
    simulate_rule_selection as simulate_selection,
)
from aegis_core.taxonomy import (
    JIT_DEFAULT_MAX_TOKENS,
    JIT_DEFAULT_RULE_COUNT_BUDGET,
    RULE_TYPES,
    RuleType,
    WORDS_TO_TOKENS_FACTOR as WORDS_TO_TOKENS_FACTOR,
)
from aegis_core.workspace.layout import RULES_RELDIR
from aegis_core.yaml_engine.frontmatter import split_frontmatter

__all__ = [
    "MANDATORY_SLOT_CAP",
    "NO_CHANGES_TEXT",
    "NO_MATCH_TEXT",
    "RULE_CACHE",
    "estimate_tokens",
    "resolve_token_budget",
    "scan",
    "scan_user_layer",
    "select_guidance",
    "simulate_rule_selection",
]

# Per-process cache of parsed rules; the MCP server keeps it across tool calls.
RULE_CACHE = RuleCache()

# MANDATORY_SLOT_CAP (aegis_core.rule_integrity): mandatory rules may take at most that many
# of a scan's rule slots, so a few rules that declare themselves mandatory on `**` cannot
# starve every advisory rule. Adding one past it is a governance change aegis check --ci flags.

# The server sends a scan as json.dumps(result), which is ASCII, so a response the
# budget admits is at most 4 bytes per budgeted token.

NO_CHANGES_TEXT = "No changed files detected. Governance guidance will be provided when files are modified."
NO_MATCH_TEXT = "No governance rules match your current changes."
_COLD_OUTPUT_LIMIT = 1024 * 1024
_COLD_MATCH_BUDGET = 16384


def resolve_token_budget(workspace: Any, max_tokens: Optional[int] = None) -> int:
    """Token budget: argument > AEGIS_MAX_JIT_TOKENS > .aegis/config.json jit.max_tokens > default."""
    if max_tokens is not None:
        try:
            return int(max_tokens)
        except (ValueError, TypeError):
            pass
    from aegis_core.config import jit_max_tokens

    return jit_max_tokens(workspace, JIT_DEFAULT_MAX_TOKENS)


def _git_changed_files(workspace: Any) -> Optional[List[str]]:
    """Files changed in the working tree or the index."""
    from aegis_core import gitsafe

    return gitsafe.changed_files(workspace, "working")


@dataclass(frozen=True)
class _Match:
    rule: Rule
    files: Tuple[str, ...]
    exact: bool
    fitness: Fitness


class _SelectedPayload(dict):
    """Rendered selection plus non-serialized canonical telemetry identities."""

    def __init__(self, payload: Dict[str, Any], staged: List[Dict[str, Any]]) -> None:
        super().__init__(payload)
        self.served = tuple(entry["match"] for entry in staged)
        self.rule_ids = tuple(match.rule.id for match in self.served)
        self.mandatory_count = sum(entry["match"].rule.mandatory for entry in staged)


class _SelectionFailure(dict):
    """A checked refusal envelope, independent of the guidance token budget."""


@dataclass(frozen=True)
class _Projection:
    """Request-local source/fitness snapshot, never serialized or reread from disk."""

    matches: Tuple[_Match, ...]
    total_rules: int
    changed_files: int
    exposure_paths: Optional[Tuple[str, ...]]
    budget: int
    token_budget: int
    stale: Tuple[Dict[str, Any], ...]
    warnings: Tuple[str, ...]
    extras: Dict[str, Any]

    def render(self, registry: Optional[SlotRegistry]) -> GuidanceResult:
        identities: Tuple[str, ...] = ()
        revisions: Tuple[Tuple[str, str], ...] = ()
        snapshot = None
        mandatory_count = 0
        try:
            selected = _select_projection(self, registry)
            selected_mandatory = selected.mandatory_count if isinstance(selected, _SelectedPayload) else None
            payload = selected if isinstance(selected, _SelectionFailure) else finish_payload(
                selected, preserve_omissions=True, staged_mandatory_count=selected_mandatory)
            if isinstance(selected, _SelectedPayload) and payload is selected:
                identities = selected.rule_ids
                proofs = tuple((match, policy_provenance(match.rule)) for match in selected.served)
                revisions = tuple((match.rule.id, proof.identity[0]) for match, proof in proofs
                                  if proof.identity is not None)
                mandatory_count = selected.mandatory_count
                if (self.exposure_paths is not None and (revisions or not identities)
                        and all(proof.identity is not None or proof.synthetic for _, proof in proofs)):
                    snapshot = _exposure_snapshot(self.exposure_paths, proofs, payload)
            elif self.exposure_paths == () and not self.changed_files and payload.get("status") != _STATUS_FAIL:
                snapshot = _exposure_snapshot((), (), payload)
        except GuidanceProjectionError as exc:
            payload = _failure(exc.code)
        return _ScanResult(payload, self, identities, mandatory_count, snapshot, revisions)


def _exposure_paths(raw: List[str], normalized: List[str]) -> Optional[Tuple[str, ...]]:
    # Limit attribution's retained copy without affecting the guidance selection.
    if len(raw) > 256 or sum(map(len, raw)) > 16 * 1024:
        return None
    if any(not path or path.startswith(("/", "../")) or path in (".", "..")
           or posixpath.normpath(path) != path for path in raw):
        return None
    exact = set(raw)
    if exact != set(normalized) or any(path != normalize_path(path) for path in exact):
        return None
    return tuple(sorted(exact))


def _exposure_snapshot(paths: Tuple[str, ...], proofs: Tuple[Tuple[_Match, PolicyProvenance], ...],
                       payload: dict) -> ScanExposure:
    rules: List[ServedRule] = []
    coverage = []
    for match, proof in proofs:
        rule = match.rule
        matched = tuple(sorted(match.files))
        coverage.append((rule.id, matched))
        if proof.identity is None:
            continue
        revision, kind = proof.identity
        # Git may normalize a CRLF checkout. Accept only the original or LF-normalized blob.
        variants = (rule.raw, rule.raw.replace(b"\r\n", b"\n")) if b"\r\n" in rule.raw else (rule.raw,)
        blobs = tuple(gitsafe.blob_id(raw, length) for raw in variants for length in (40, 64))
        rules.append(ServedPolicy(rule.id, revision, rule.path, matched, blobs, kind))
    digest = sha256(json.dumps(payload, sort_keys=True).encode("ascii")).hexdigest()
    normalized = payload
    provenance = payload.get("rules_base")
    if isinstance(provenance, dict) and provenance.get("source") == "local-head":
        # Unreviewed local HEAD movement changes the response's provenance, but
        # not the served instruction or its revision. Keep the wire digest exact.
        basis = {key: value for key, value in provenance.items() if key != "commit"}
        normalized = {**payload, "rules_base": basis}
    covered = tuple(sorted(coverage))
    # Implicit receipt equality includes canonical coverage even if displayed paths coincide.
    attribution_digest = sha256(json.dumps((normalized, covered), sort_keys=True).encode("ascii")).hexdigest()
    return ScanExposure(paths, tuple(sorted(rules, key=lambda rule: rule.rule_id)),
                        digest, attribution_digest, covered)


class _ScanResult(GuidanceResult):
    def __init__(self, payload: Dict[str, Any], projection: _Projection,
                 identities: Tuple[str, ...], mandatory_count: int, snapshot: Optional[ScanExposure],
                 revisions: Tuple[Tuple[str, str], ...]) -> None:
        super().__init__(payload)
        self._projection = projection
        self._canonical_rule_ids = identities
        self._mandatory_count = mandatory_count
        self._exposure = snapshot
        self._revisions = revisions

    def with_registry(self, registry: SlotRegistry) -> Dict[str, Any]:
        return self._projection.render(registry)

    def exposure_rule_ids(self) -> Tuple[str, ...]:
        return self._canonical_rule_ids

    def exposure_snapshot(self) -> Optional[ScanExposure]:
        return self._exposure

    def exposure_revisions(self) -> Tuple[Tuple[str, str], ...]:
        return self._revisions

    def staged_mandatory_count(self) -> int:
        return self._mandatory_count


def _match(rule: Rule, matched: Tuple[str, ...], fitness: Fitness) -> _Match:
    rank_exact = getattr(rule, "rank_exact", None)
    if rank_exact is None:
        exact = any(normalize_path(p) == normalize_path(f) for p in rule.target_paths for f in matched)
    else:
        exact = rank_exact(matched)
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


def _unstripped_body(rule: Rule) -> str:
    """Recover structure from bounded raw bytes; never trust the stripped body."""
    if type(rule.raw) is not bytes or not rule.raw:
        return WITHHELD_GUIDANCE
    try:
        text = raw_rule_text(rule.raw, split_frontmatter)
    except GuidanceProjectionError:
        raise
    except ValueError:
        raise GuidanceProjectionError("guidance_projection_limit") from None
    if text is None:
        return WITHHELD_GUIDANCE
    status, frontmatter, body = split_frontmatter(text)
    return body if status == "ok" and frontmatter and frontmatter.strip() else WITHHELD_GUIDANCE


class _RuleProjectionError(GuidanceProjectionError):
    """Private attribution from a fixed field boundary, never exception text."""

    def __init__(self, code: str, path: str, field: str) -> None:
        super().__init__(code)
        self.code, self.path, self.field = code, path, field


def _project_at(rule: Rule, field: str, operation: Callable[..., Any], *args: Any) -> Any:
    try:
        return operation(*args)
    except GuidanceProjectionError as exc:
        raise _RuleProjectionError(exc.code, rule.path, field) from None


def _text(m: _Match, registry: Optional[SlotRegistry] = None) -> str:
    rule = m.rule
    spec = RULE_TYPES.get(rule.type or "")
    emoji = spec.emoji if spec else "📋"
    label = spec.label if spec else str(rule.type).upper()
    out = f"{emoji} [{label}] {rule.id}\n"
    hypothesis = _project_at(rule, "hypothesis", field_text, rule.meta.get("hypothesis", ""))
    out += f"   Hypothesis: {hypothesis}\n"
    prediction = rule.meta.get("prediction")
    if prediction:
        prediction_text = _project_at(rule, "prediction", field_text, prediction)
        out += f"   If violated: {prediction_text}\n"
    out += f"   Triggered by: {', '.join(m.files[:5])}\n"
    body = _project_at(rule, "detail", _unstripped_body, rule)
    if body.strip():
        detail = _project_at(rule, "detail", project_detail, body, registry)
        out += f"   Detail: {detail}\n"
    out += f"   Fitness: {_fitness_text(m.fitness)}\n"
    return out


def _entry(m: _Match, registry: Optional[SlotRegistry]) -> Dict[str, Any]:
    # Do not mutate cached rules or enforcement metadata. All served copies of
    # hypothesis/prediction share this one rendering, including invariant text.
    meta = dict(m.rule.meta)
    for key in ("hypothesis", "prediction"):
        meta[key] = _project_at(m.rule, key, project_field, meta.get(key, ""), registry)
    if len(m.files) > 4096:
        raise _RuleProjectionError("guidance_projection_limit", m.rule.path, "matched_files")
    display_files = _project_at(m.rule, "matched_files", project_display_data,
                                {"matched_files": list(m.files)}, registry)["matched_files"]
    # Entry identifiers belong to the displayed detail boundary. Attribute
    # their refusals too, preserving earlier failed rules and the first code.
    projected = replace(m, rule=replace(m.rule, meta=meta,
                                        id=_project_at(m.rule, "detail", project_identifier, m.rule.id),
                                        path=_project_at(m.rule, "detail", project_identifier, m.rule.path)),
                        files=tuple(display_files))
    return {"match": m, "item": _item(projected), "text": _text(projected, registry),
            "constraint": _constraint(projected)}


def _projection_entries(matches: List[_Match], registry: Optional[SlotRegistry]) -> Tuple[list, Optional[dict]]:
    """Collect safe locations within the failure envelope's node/character caps."""
    entries, errors = [], []
    code, size = None, 0
    for match in matches:
        try:
            entries.append(_entry(match, registry))
        except GuidanceProjectionError as exc:
            code = code or exc.code
            reason = projection_refusal_reason(exc.code, exc.field) if isinstance(exc, _RuleProjectionError) else None
            if reason is None or not rule_error_rows_fit(len(errors) + 1):
                return [], _failure(code)
            try:
                path = project_error_name(exc.path)
            except GuidanceProjectionError:
                return [], _failure(code)
            size += len(path) + len(reason) + len("patherror")
            if size + len("statusFAILerrorrule_errors") + len(code) > MAX_GUIDANCE_CHARS:
                return [], _failure(code)
            errors.append({"path": path, "error": reason})
    if code is None:
        return entries, None
    return [], _failure(code, errors)


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
    return f"- 🧱 [INVARIANT] {constraint['name']}: {field_text(constraint['hypothesis'])}\n"


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
    return assembled_text("\n".join(parts) if parts else NO_MATCH_TEXT)


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
    if projection_refusal_repair(message) is not None:
        return projection_refusal(message, rule_errors)
    result: Dict[str, Any] = {"status": _STATUS_FAIL, "error": assembled_text(message)}
    if rule_errors is not None:
        result["rule_errors"] = rule_errors
    try:
        # The message and rows are assembled here from projected components.
        # Validate their envelope bounds without redacting across boundaries.
        checked_result_copy(result, None)
        return result
    except GuidanceProjectionError as exc:
        return {"status": _STATUS_FAIL, "error": exc.code}


_IGNORED_NAMED = 3


def _ignored_warning(ruleset: RuleSet) -> str:
    """One bounded line however many files are ignored: every scan response pays for it."""
    total = len(ruleset.ignored)
    head = (
        f"1 file under {RULES_RELDIR} is not a rule and was ignored" if total == 1
        else f"{total} files under {RULES_RELDIR} are not rules and were ignored"
    )
    paths = [project_identifier(item.path) for item in ruleset.ignored[:_IGNORED_NAMED]]
    more = f" and {total - _IGNORED_NAMED} more" if total > _IGNORED_NAMED else ""
    if sum(map(len, paths)) + len(head) + len(more) + 64 > MAX_GUIDANCE_CHARS:
        raise GuidanceProjectionError("guidance_projection_limit")
    named = ", ".join(paths)
    return assembled_text(f"{head} (aegis status lists why): {named}{more}")


def _broken(ruleset: RuleSet) -> Dict[str, Any]:
    broken = ruleset.errors
    # Check the shared envelope node cap before allocating error rows.
    if not rule_error_rows_fit(len(broken)):
        return _failure("guidance_projection_limit")
    errors, size = [], 0
    try:
        for rule in broken:
            path = project_error_name(rule.path)
            reason = project_display_text(rule.error or "", max_len=None)
            size += len(path) + len(reason)
            if size > MAX_GUIDANCE_CHARS:
                raise GuidanceProjectionError("guidance_projection_limit")
            errors.append({"path": path, "error": assembled_text(reason)})
        head = f"{len(errors)} rule file(s) cannot be served, so no partial rule set is returned: "
        more = f" (and {len(errors) - 5} more)" if len(errors) > 5 else ""
        tail = ". Fix or move them; `aegis status` lists them."
        listed_size = sum(len(item["path"]) + len(item["error"]) + 4 for item in errors[:5])
        if listed_size + len(head) + len(more) + len(tail) > MAX_GUIDANCE_CHARS:
            raise GuidanceProjectionError("guidance_projection_limit")
        listed = "; ".join(f"{item['path']}: {item['error']}" for item in errors[:5])
        return _failure(head + listed + more + tail, errors)
    except GuidanceProjectionError as exc:
        return _failure(exc.code)


def scan(
    workspace: Any,
    changed_files: Optional[List[str]] = None,
    budget: Optional[int] = None,
    max_tokens: Optional[int] = None,
    *,
    registry: Optional[SlotRegistry] = None,
    exposure_allowed: bool = True,
) -> Dict[str, Any]:
    """The rules for ``changed_files`` (default: the git working tree and index changes).

    ``budget`` is the number of rule slots (default JIT_DEFAULT_RULE_COUNT_BUDGET);
    ``max_tokens`` bounds the whole response. Returns ``{"status": "FAIL", "error"}``
    (with ``rule_errors``) when the rules cannot all be loaded.
    ``registry`` is a sanitized request snapshot; None preserves unresolved
    templates for direct callers. Projection resource refusal uses the fixed
    error code ``guidance_projection_limit`` without quoting rule content.
    """
    with gitsafe.memo():  # one answer per repository question for the whole scan
        return _scan(workspace, changed_files, budget, max_tokens, registry, exposure_allowed=exposure_allowed)


def _scan(workspace: Any, changed_files: Optional[List[str]], budget: Optional[int],
          max_tokens: Optional[int], registry: Optional[SlotRegistry], cache: Optional[RuleCache] = None,
          *, exposure_allowed: bool = True) -> Dict[str, Any]:
    from aegis_core.sync import read_derived, stale_rules

    token_budget = resolve_token_budget(workspace, max_tokens)
    try:
        view = rule_integrity.effective(workspace, RULE_CACHE if cache is None else cache)
    except RuleInventoryError as exc:
        return _failure(f"the rules directory cannot be read safely: {project_display_text(str(exc))}")
    except rule_integrity.IntegrityError as exc:
        # Simulation is the only capture that carries compare_candidates. A typed
        # custody cap stays a GitError so the shared mapper can name it; every
        # other caller still receives the reviewed-base failure result.
        cause = exc.__cause__
        if (cache is not None and getattr(cache, "compare_candidates", None) is not None
                and isinstance(cause, gitsafe.GitError) and cause.code == "git_output_limit"):
            raise cause from None
        reason = project_display_text(str(exc))
        return _failure(f"the reviewed (base) version of the rules cannot be read, so none is served: {reason}")
    ruleset = view.ruleset
    if ruleset.errors:
        return _broken(ruleset)
    if cache is not None:
        compare_candidates = getattr(cache, "compare_candidates", None)
        if compare_candidates is not None:
            compare_candidates(ruleset)

    # Workspace-relative, each file once, as every other surface matches them.
    root = workspace_root(workspace)
    raw_files = changed_files or _git_changed_files(workspace)
    files = workspace_files(root, raw_files or [])
    exact_scope = None
    if exposure_allowed and raw_files is not None and (changed_files or gitsafe.toplevel(root) == Path(root)):
        exact_scope = _exposure_paths(raw_files, files)
    stale = stale_rules(ruleset, read_derived(workspace))
    # Labels are read only by decision callers: scan ranks without them and spawns no git for them.
    return select_guidance(ruleset, files, budget, token_budget, stale,
                   lambda served: for_rules(workspace, served, adjudications=Adjudications(), effective_view=view),
                   _integrity_extras(view), registry, exposure_paths=exact_scope)


def simulate_rule_selection(workspace: Any, inventory: RuleInventory, ruleset: RuleSet) -> Dict[str, str]:
    """Simulate lint selection with the current scan seams and request-local limits."""
    hooks = SimulationHooks(_scan, _ScanResult, select_guidance, for_rules, _cold_rules,
                            _COLD_OUTPUT_LIMIT, _COLD_MATCH_BUDGET, _STATUS_FAIL)
    return simulate_selection(workspace, inventory, ruleset, hooks)


def _cold_rules(rules: Tuple[Rule, ...], remaining: List[int]) -> Tuple[Rule, ...]:
    outcomes, targets = {}, {(r.id, r.path, r.digest): (r.skips_tests, tuple(dict.fromkeys(r.target_paths))) for r in rules}
    def evaluate(pattern: str, path: str, exact: bool) -> bool:
        if remaining[0] <= 0:
            raise _SimulationBudget
        remaining[0] -= 1  # Every step costs one, including cached negatives and ranking.
        key = pattern, path, exact
        if key not in outcomes:
            outcomes[key] = normalize_path(pattern) == normalize_path(path) if exact else rule_match.matches(pattern, path)
        return outcomes[key]
    def applies(rule: Rule, path: str, exact: bool) -> bool:
        skip_tests, patterns = targets[(rule.id, rule.path, rule.digest)]
        if not exact and skip_tests and rule_match.is_test_path(path):
            return False
        return any(evaluate(pattern, path, exact) for pattern in patterns)
    return tuple(_ColdRule(**vars(replace(rule, meta={**rule.meta, "target_paths": targets[(rule.id, rule.path, rule.digest)][1]})), _match_path=applies) for rule in rules)


# Titles are branch-local text that reaches an agent: only the first few are listed.
_UNREVIEWED_LISTED = 10


def _integrity_extras(view: "rule_integrity.Effective") -> Dict[str, Any]:
    """``rules_base`` and ``unreviewed_rules`` (id, title, kind of change; nothing else) for a scan."""
    if view.anchor is None:
        return {}
    extras: Dict[str, Any] = {"rules_base": asdict(view.anchor)}
    if view.unreviewed:
        extras["unreviewed_rules"] = [asdict(u) for u in view.unreviewed[:_UNREVIEWED_LISTED]]
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
    *,
    registry: Optional[SlotRegistry] = None,
    extras: Optional[Dict[str, Any]] = None,
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
            return _failure(f"the user rules directory cannot be read safely: {project_display_text(str(exc))}")
        if ruleset.errors:
            return _broken(ruleset)
    neutral = compute({})
    envelope = dict(extras or {})
    envelope["user_layer"] = {"path": _layer_path(layout.rules_dir) if layout is not None else None,
                              "rules": len(ruleset.served)}
    return select_guidance(ruleset, _layer_files(changed_files or []), budget, token_budget, [],
                   lambda served: {rule.id: neutral for rule in served}, envelope, registry)


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


def select_guidance(
    ruleset: RuleSet,
    files: List[str],
    budget: Optional[int],
    token_budget: int,
    stale: List[Dict[str, Any]],
    fitness_of: Callable[[List[Rule]], Dict[str, Fitness]],
    extras: Optional[Dict[str, Any]] = None,
    registry: Optional[SlotRegistry] = None,
    *,
    exposure_paths: Optional[Tuple[str, ...]] = None,
) -> Dict[str, Any]:
    """Capture matching source and fitness once, then select and project it.

    The result retains private, non-serialized inputs so the legacy renderer can
    bind its registry before truncation and budgeting, with no second source or
    ledger read. Simulation supplies pure fitness; scan supplies its lazy reader.
    """
    slots = JIT_DEFAULT_RULE_COUNT_BUDGET if budget is None else max(0, int(budget))
    served = list(ruleset.served)
    hits = [(r, f) for r, f in ((r, tuple(r.matching_files(files))) for r in served) if f] if files else []
    fits = fitness_of([r for r, _f in hits]) if hits else {}
    try:
        source = checked_result_copy(dict(extras or {}, stale_rules=stale,
                                      warnings=[_ignored_warning(ruleset)] if ruleset.ignored else []), None)
    except GuidanceProjectionError as exc:
        return _failure(exc.code)
    projection = _Projection(
        tuple(_match(r, f, fits[r.id]) for r, f in hits), len(served), len(files), exposure_paths,
        slots, token_budget,
        tuple(source["stale_rules"]), tuple(source["warnings"]),
        {k: v for k, v in source.items() if k not in {"stale_rules", "warnings"}},
    )
    return projection.render(registry)


def _select_projection(projection: _Projection, registry: Optional[SlotRegistry]) -> Dict[str, Any]:
    """Pure rendering/selection over the original request's captured inputs."""
    slots, token_budget = projection.budget, projection.token_budget
    matches = projection.matches
    warnings = list(projection.warnings)
    if registry is not None:
        warnings.extend(w for w in registry.sanitized().warnings if w not in warnings)
    # Only this producer owns the structured warning components. A later public
    # re-render treats these assembled strings as untrusted text.
    auxiliary = project_display_data(dict(projection.extras, stale_rules=list(projection.stale)), registry)
    # Finalized warning identifiers are literal even when they spell a slot.
    source = checked_result_copy(dict(auxiliary, warnings=warnings), None)
    warnings = source["warnings"]
    stats = {
        "total_rules": projection.total_rules,
        "matched": len(matches),
        "budget": slots,
        "changed_files": projection.changed_files,
        "estimated_tokens": 0,
        "max_tokens_budget": token_budget,
    }
    stale = auxiliary["stale_rules"]
    extras = {k: v for k, v in auxiliary.items() if k not in {"stale_rules", "warnings"}}
    if not projection.changed_files:
        while True:
            payload = _payload([], 0, [], 0, stats, stale, warnings, extras)
            payload["guidance"] = NO_CHANGES_TEXT
            payload["stats"]["estimated_tokens"] = _tokens(payload)
            if payload["stats"]["estimated_tokens"] <= token_budget or not _trim_unreviewed(extras):
                return payload

    mandatory = _rank([m for m in matches if m.rule.mandatory], mandatory=True)
    advisory = _rank([m for m in matches if not m.rule.mandatory], mandatory=False)
    cap = min(MANDATORY_SLOT_CAP, slots)
    chosen = mandatory[:cap]
    capped = mandatory[cap:]
    chosen += advisory[:max(0, slots - len(chosen))]

    entries, failure = _projection_entries(chosen, registry)
    if failure is not None:
        return _SelectionFailure(failure)
    omitted_mandatory = [{"name": project_identifier(m.rule.id), "type": m.rule.type,
                          "reason": "slot_cap"} for m in capped]

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
            omitted_mandatory.append({"name": project_identifier(rule.id), "type": rule.type,
                                      "reason": "token_budget"})

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
            # The full warning and verbose omission prose are optional costs;
            # the mandatory omission count is not. Compact inside selection,
            # before final accounting, rather than replacing it with FAIL.
            payload["guidance"] = "Guidance omitted."
            if _tokens(payload) > token_budget and warnings:
                payload["warnings"] = ["scan warning; slot placeholders may be unresolved"]
            tokens = _tokens(payload)
            break
    payload["stats"]["estimated_tokens"] = tokens
    return _SelectedPayload(payload, staged)
