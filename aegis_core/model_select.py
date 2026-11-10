"""Host-neutral policy selection with bounded, atomically published JSONL history.

select_model returns (choice, record); subject identifies a lane/endpoint/generation.
host_kinds is required registry data supplied by the caller, never inferred here.
Policy requires team_id, team_family, manager_family, family_hosts (ordered host
lists), family_order (two families), target_shares, flexible_tasks and review_families
(task -> stage -> family, including primary). Optional task_intents maps task ->
family -> intent. Hosts, models, shares, review families and effort overrides are
data. Encode T4 correctness, T5 security, T6 lenses and T8 stage declarations in
policy. T8 primary uses the marker "opposite" and optional second uses "author".
The core infers no vendor from a name.

T2 writers and T13 helpers stay on team_family; T3 requires lane_family matching
team_family. Writer roles refuse a supplied lane_family outside team_family. T1 uses
manager_family. Only explicitly flexible helper tasks split. The chooser ports
family_split.py for nonzero shares: empty history picks family_order[0]; thereafter
pick it while its share is strictly below target, otherwise family_order[1]. A
zero-share flexible family is never chosen: this is an intentional divergence from
the build tool's 0.0/1.0 quirks; the interior targets retain exact parity.
Share arithmetic is exact Fraction.
All reviews require a known author. T4/T5 primaries and T6 stages each cover both
families; a security lens may share the author's family.
T8 primary derives the opposite family and second derives the author's family,
so paired checks always cover both families. Review stage names are closed.
T7 records set author_family to the chosen family and refuse a contradictory
author, providing the binding for a subsequent T8 check. No Router seat, launch
or effort update is added.

MR-1c exception: unprobed bindings remain usable until probes exist. Every choice
and record carries admission (unprobed or admitted); rejected refuses. Validation
matches MR-1's band/coverage/model-token rules with the caller's required registry.
Standalone validate_bindings may infer hosts when inspecting a document only.
Deferred to MR-1c/MR-3b: T6 whole-change on a non-coding model, and "Opus gating"
for Claude-authored docs. These require further binding/admission policy data.

File inputs must be regular, not symlinks, and are read with no-follow opens and
a fixed byte cap before JSON decoding. Config opens walk from a held filesystem
root descriptor with no-follow opens for every directory component and compare
the final entry and descriptor with the expected inode. Parsed and file inputs
share structural budgets before validation. OS path rejections use invalid_bindings,
invalid_policy or unsafe_decision_path; semantic refusals, lock timeouts and
descriptor write/fsync errors retain their own codes. Decision reads stream bounded lines with
cumulative byte/record caps; read_decisions yields records without retaining them.
Consume or close that iterator promptly: it holds the .lock during iteration.
At the cap, archive/rotate the log and carry forward calibrated policy explicitly.
Decision directories must exist, belong to the current uid, and forbid group/other
writes. Logs must be owner-owned regular files without group/other write bits,
verified on the opened descriptor. Log names ending in .lock refuse invalid_log_path.
Missing-log reads in an existing valid directory create neither directories nor
locks. Missing directories and any .. path component refuse unsafe_decision_path.
Path text is capped at MAX_INPUT_BYTES characters and 256 separators before pathlib parsing, and
invalid decision path types refuse unsafe_decision_path without raw TypeError.
Platforms lacking
POSIX directory descriptors refuse anchored_io_unavailable, with no path fallback.
Directory acquisition resolves the parent once, then walks from the filesystem
root with no-follow directory opens relative to held descriptors. The acquired
leaf must match the expected and anchored-entry identities, owner and mode.
An append streams validated old bytes and the new line into an exclusive no-follow
sibling at a held directory descriptor, fchmods/fsyncs its descriptor, checks its
identity, then renames within that descriptor and fsyncs the directory. A partial
write/error before publication leaves the original untouched. Cleanup failures
are chained under an original failure without masking its type or code. No corrupt history
is repaired or reset. Use select_and_append for launches: its one anchored lock
covers read, select and atomic publication. Low-level append_decision refuses a
new stale_decision when counts_before disagrees with matching-split counts or
previous_decision_id disagrees with the same-team chain head.
Existing decision IDs may receive outcome observations; those keep decision_id.
Counts use split_id, the hash of target_shares and family_order; unrelated policy
edits preserve counts and policy_id remains audit provenance. Restoring an earlier
split resumes only that split's counts. Every split_id requires its exact snapshot.
An explicit outcome.launch_status="not_launched" excludes a HOLD or failed start;
only an explicit "launched" can reverse that state. An initial decision without
status counts as launched, while status-free observations preserve its state.
Other outcome data is opaque.
Each new launch hashes previous_decision_id (the previous new decision for its
team, across policies); observations do not advance the chain. Replay refuses a
broken chain with invalid_history:decision_chain: restore_complete_decision_log.
Replay checks each new row's chronological counts_before per team/split and the
split result (including zero-share exclusion); historical observations update
counts without rechecking their original snapshot against later counts.
Every reader enforces a fixed family set per team across all policies, including
when selection is for another team. Recorded T4/T5 primaries under one policy
identity must remain consistent and cover both families when both appear.
Selection re-derives same-team history reasons, split eligibility and stage/fixed
families from the supplied policy's rules. Earlier calibrated splits retain
their own validated targets/order; a row claiming the supplied policy_id must
match its current targets/order too. Policy rule changes that contradict earlier
choices require a new history rather than silently reinterpreting those choices.
Records include policy_id (SHA256 of bounded canonical policy JSON).
Before hashing/encoding, records have 64-level, 1024-node, 256-item collection,
425-bit integer and aggregate byte budgets; encoding stops at the line limit.
Config input node budgets scale with MAX_INPUT_BYTES; the byte cap also bounds
nodes because each JSON node consumes at least one byte. Record budgets stay fixed.
History rows have one canonical form: sorted-key compact ASCII JSON plus one LF.
Append, disk validation and replay measure those exact bytes including the LF;
noncanonical disk rows refuse invalid_history, with no silent normalization.
Internal reader rows are validated once per pass and reused by selection without
re-encoding or hashing. select_and_append retains only validated immutable raw
lines (at most MAX_HISTORY_BYTES, MAX_HISTORY_RECORDS) for publication under its
same anchored lock, avoiding a second validation pass. Its explicit lock timeout
is 60 seconds for the 4096-row cap and a queued peer. Low-level append validates
its own streaming rewrite. Both remain O(n) under fixed caps. Identity is not authentication. These APIs
grant neither admission authority nor native execution qualification.
"""
from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager, ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
from fractions import Fraction
import re
import secrets
import stat
import sys

from aegis_core.storage import LockTimeoutError, file_lock

__all__ = ["MAX_LINE_BYTES", "MAX_INPUT_BYTES", "MAX_HISTORY_BYTES", "MAX_HISTORY_RECORDS",
           "ModelSelectionError", "validate_bindings", "select_model", "select_and_append",
           "append_decision", "read_decisions"]

MAX_LINE_BYTES = 4096
MAX_INPUT_BYTES = 262144
MAX_HISTORY_BYTES = 4 * 1024 * 1024
MAX_HISTORY_RECORDS = 4096
_MAX_PATH_SEPARATORS = 256
_LOCK_TIMEOUT_SECONDS = 60.0  # cap-sized validation/publication, including a queued peer
_HISTORY_LIMIT = "history_limit_exceeded: archive_or_rotate_decision_log"
_CHAIN_ERROR = "invalid_history:decision_chain: restore_complete_decision_log"
_INTENTS = ("light", "standard", "deep", "extended", "max")
_CLASSES = ("coding", "frontier", "scout", "mechanical")
_ROLES = ("orchestrator", "decider", "implementer", "integrator", "reviewer")
_TASK_ROLES = {
    "T1": ("orchestrator", "decider"),
    "T2": ("implementer", "integrator"),
    "T3": ("implementer", "integrator"),
    "T4": ("reviewer",), "T5": ("reviewer",), "T6": ("reviewer",),
    "T7": ("implementer", "integrator"), "T8": ("reviewer",),
    "T9": ("implementer", "integrator"), "T10": ("implementer", "integrator"),
    "T11": ("implementer", "integrator"), "T12": ("implementer", "integrator"),
    "T13": ("implementer", "integrator"), "T14": ("implementer", "integrator"),
}
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SUBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_FLEXIBLE = ("T7", "T9", "T10", "T11", "T12", "T14")
_REVIEWS = ("T4", "T5", "T6", "T8")
_STAGES = {"T4": ("primary",), "T5": ("primary",),
           "T6": ("primary", "correctness", "security", "whole"), "T8": ("primary", "second")}
_DIR_FD_SUPPORTED = (os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and
                     hasattr(os, "fchmod") and hasattr(os, "getuid") and
                     all(fn in os.supports_dir_fd for fn in (os.open, os.stat, os.rename, os.unlink)))
_CHOICE_KEYS = {"host", "class", "model", "level", "family", "reason", "admission"}
_RECORD_KEYS = {"schema", "decision_id", "team_id", "task_kind", "role_kind", "intent", "author_family",
                "choice", "split_eligible", "target_shares", "counts_before", "outcome", "subject",
                "admission", "review_stage", "family_order", "policy_id", "split_id", "previous_decision_id"}


class ModelSelectionError(ValueError):
    """Stable refusal code, without reflecting untrusted input in diagnostics."""


def _require(condition, error):
    if not condition:
        raise ModelSelectionError(error)


def _token(value):
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _keys(value, keys, error):
    _require(type(value) is dict and set(value) == set(keys), error)


def _member(value, options):
    return type(value) is str and value in options


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("nonfinite_json")


def _loads(raw, error):
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ModelSelectionError(error) from exc


def _path_value(value, error):
    _require(isinstance(value, (str, os.PathLike)), error)
    raw = value if isinstance(value, str) else value.__fspath__()
    _require(type(raw) is str and len(raw) <= MAX_INPUT_BYTES, error)
    _require(sum(raw.count(separator) for separator in (os.sep, os.altsep) if separator) <=
             _MAX_PATH_SEPARATORS, error)
    return Path(raw)


def _input(value, error):
    if isinstance(value, (str, os.PathLike)):
        try:
            with _open_regular(_path_value(value, error), error, MAX_INPUT_BYTES) as stream:
                raw = stream.read(MAX_INPUT_BYTES + 1)
            _require(len(raw) <= MAX_INPUT_BYTES, error)
        except ModelSelectionError:
            raise
        except (ValueError, OSError) as exc:
            raise ModelSelectionError(error) from exc
        value = _loads(raw, error)
    _json_value(value, error, limit=MAX_INPUT_BYTES)
    return value


def validate_bindings(value, *, host_kinds=None):
    """Return (role rows by kind, binding rows by (host, class)); refuse invalid_bindings.

    host_kinds supplies the caller's host registry. Otherwise hosts are inferred
    from data; every such host still needs every role class and band endpoint.
    """
    error = "invalid_bindings"
    data = _input(value, error)
    if host_kinds is not None:
        _require(type(host_kinds) in (list, tuple, set, frozenset) and len(host_kinds) <= 256 and
                 all(_token(h) for h in host_kinds), error)
    registry = None if host_kinds is None else set(host_kinds)
    _keys(data, ("schema", "roles", "hosts"), error)
    _require(data["schema"] == "aegis.model-bindings/v1", error)
    _require(type(data["roles"]) is list and type(data["hosts"]) is list and data["hosts"], error)
    roles, hosts, models = {}, {}, set()
    for row in data["roles"]:
        _keys(row, ("kind", "model_class", "band"), error)
        kind, band = row["kind"], row["band"]
        _require(_member(kind, _ROLES) and kind not in roles, error)
        # Product seats are coding class; cheaper/frontier helper admission is separate.
        _require(row["model_class"] == "coding", error)
        _keys(band, ("floor", "default", "ceiling"), error)
        _require(all(_member(v, _INTENTS) for v in band.values()), error)
        floor, default, ceiling = (_INTENTS.index(band[k]) for k in ("floor", "default", "ceiling"))
        _require(floor <= default <= ceiling, error)
        roles[kind] = row
    _require(set(roles) == set(_ROLES), error)
    for row in data["hosts"]:
        _keys(row, ("host", "class", "model", "levels", "admission"), error)
        host, model_class = row["host"], row["class"]
        _require(_token(host) and _member(model_class, _CLASSES) and
                 type(row["model"]) is str and _IDENTIFIER.fullmatch(row["model"]) is not None, error)
        _require(registry is None or host in registry, error)
        _require((host, model_class) not in hosts and (host, row["model"]) not in models, error)
        levels, admission = row["levels"], row["admission"]
        _require(type(levels) is dict and bool(levels) and set(levels) <= set(_INTENTS), error)
        _require(all(_member(v, ("low", "medium", "high", "xhigh", "max")) for v in levels.values()), error)
        _require(len(set(levels.values())) == len(levels), error)
        _keys(admission, levels, error)
        _require(all(_member(v, ("unprobed", "admitted", "rejected")) for v in admission.values()), error)
        hosts[host, model_class] = row
        models.add((host, row["model"]))
    if registry is None:
        registry = {h for h, _ in hosts}
    _require(bool(registry) and all(_token(h) for h in registry) and all(h in registry for h, _ in hosts), error)
    for role in roles.values():
        for host in registry:
            binding = hosts.get((host, role["model_class"]))
            _require(binding is not None, error)
            for edge in ("default", "ceiling"):
                intent = role["band"][edge]
                _require(intent in binding["levels"] and binding["admission"][intent] != "rejected", error)
    return roles, hosts


def _shares(value, error):
    _require(type(value) is dict and bool(value) and all(_token(k) for k in value),
             error + ":target_shares_shape" if error == "invalid_policy" else error)
    _require(all(type(v) in (int, float) and 0 <= v <= 1 and math.isfinite(v) for v in value.values()),
             error + ":target_shares_values" if error == "invalid_policy" else error)
    _require(sum(Fraction(str(v)) for v in value.values()) == 1,
             error + ":target_shares_sum" if error == "invalid_policy" else error)


def _policy(value, hosts):
    error = "invalid_policy"
    data = _input(value, error)
    required = {"team_id", "manager_family", "team_family", "target_shares", "family_hosts",
                "family_order", "flexible_tasks", "review_families"}
    _require(type(data) is dict and required <= set(data) and set(data) <= required | {"task_intents"}, error + ":shape")
    _require(_token(data["team_id"]), error + ":team_id")
    shares, families = data["target_shares"], data["family_hosts"]
    _shares(shares, error)
    _keys(families, shares, error + ":family_hosts_keys")
    _require(_member(data["manager_family"], families), error + ":manager_family")
    _require(_member(data["team_family"], families), error + ":team_family")
    order = data["family_order"]
    _require(type(order) is list and len(order) == 2 and all(_member(f, families) for f in order) and
             len(set(order)) == 2 and set(order) == set(families), error + ":family_order")
    flexible = data["flexible_tasks"]
    _require(type(flexible) is list and all(_member(t, _FLEXIBLE) for t in flexible) and
             len(set(flexible)) == len(flexible), error + ":flexible_tasks")
    reviews = data["review_families"]
    _keys(reviews, _REVIEWS, error + ":review_families_keys")
    for task, stages in reviews.items():
        _require(type(stages) is dict and "primary" in stages and all(_member(s, _STAGES[task]) for s in stages),
                 error + ":review_families:" + task + ":stages")
        if task == "T8":
            _require(stages["primary"] == "opposite" and stages.get("second", "author") == "author",
                     error + ":t8_markers")
        else:
            _require(all(_member(f, families) for f in stages.values()),
                     error + ":review_families:" + task + ":families")
    _require({reviews["T4"]["primary"], reviews["T5"]["primary"]} == set(families), error + ":formal_primaries")
    _require(set(reviews["T6"].values()) == set(families), error + ":t6_family_coverage")
    seen = set()
    for names in families.values():
        _require(type(names) is list and bool(names) and all(_token(n) for n in names), error + ":family_hosts_values")
        _require(len(set(names)) == len(names) and not seen.intersection(names), error + ":family_hosts_unique")
        _require(all(any(h == name for h, _ in hosts) for name in names), error + ":family_hosts_registry")
        seen.update(names)
    overrides = data.get("task_intents", {})
    _require(type(overrides) is dict, error + ":task_intents_shape")
    for task, intents in overrides.items():
        _require(_member(task, _TASK_ROLES) and type(intents) is dict and bool(intents), error + ":task_intents_task")
        _require(set(intents) <= set(families) and all(_member(v, _INTENTS) for v in intents.values()),
                 error + ":task_intents_values")
    return data


def _identity(record, *, checked=False):
    """Outcome observations retain the identity of their original decision."""
    if not checked:
        _json_value(record, "invalid_history", limit=MAX_LINE_BYTES - 1)
    payload = {k: v for k, v in record.items() if k not in ("outcome", "decision_id")}
    return hashlib.sha256(_encoded(payload, MAX_LINE_BYTES - 1, "invalid_history", checked=True)).hexdigest()


def _split_identity(shares, order):
    return hashlib.sha256(_encoded({"target_shares": shares, "family_order": order},
                                   MAX_LINE_BYTES - 1, "invalid_history")).hexdigest()


def _split_snapshot(shares, order):
    """Freeze validated scalar JSON forms, preserving 1 versus 1.0 and signed zero."""
    return tuple((key, repr(value)) for key, value in sorted(shares.items())), tuple(order)


def _json_value(value, error, depth=0, budget=None, limit=MAX_LINE_BYTES):
    """Count canonical JSON bytes and bound work before hashing/encoding."""
    if budget is None:
        budget = [0, 0]
    too_large = "decision_line_too_large" if limit <= MAX_LINE_BYTES else error
    _require(depth <= 64, error)
    budget[0] += 1
    # Every JSON node consumes at least one byte; input work scales with its byte cap.
    _require(budget[0] <= (1024 if limit <= MAX_LINE_BYTES else limit), too_large)
    if value is None or type(value) is bool:
        budget[1] += 5 if value is False else 4
    elif type(value) is str:
        _require(len(value) <= limit, too_large)
        # Count escaped ASCII JSON bytes without encoding/allocating the string.
        budget[1] += 2
        for char in value:
            code = ord(char)
            budget[1] += (2 if char in '"\\\b\f\n\r\t' else
                          (1 if 32 <= code < 127 else (6 if code <= 65535 else 12)))
            _require(budget[1] <= limit, too_large)
    elif type(value) is int:
        _require(value.bit_length() <= 425, too_large)  # at most 128 decimal digits
        budget[1] += len(str(value))  # conversion is bounded by the bit-length check
    elif type(value) is float:
        _require(math.isfinite(value), error)
        budget[1] += len(repr(value))
    elif type(value) in (list, dict):
        _require(len(value) <= 256, too_large)
        budget[1] += 2 + max(0, len(value) - 1) + (len(value) if type(value) is dict else 0)
        if type(value) is dict:
            for key, item in value.items():
                _require(type(key) is str, error)
                _json_value(key, error, depth + 1, budget, limit)
                _json_value(item, error, depth + 1, budget, limit)
        else:
            for item in value:
                _json_value(item, error, depth + 1, budget, limit)
    else:
        raise ModelSelectionError(error)
    _require(budget[1] <= limit, too_large)


def _encoded(value, limit, error, *, checked=False):
    if not checked:
        _json_value(value, error, limit=limit)
    result = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    try:
        for chunk in encoder.iterencode(value):
            _require(len(result) + len(chunk) <= limit,
                     "decision_line_too_large" if limit <= MAX_LINE_BYTES else error)
            result.extend(chunk.encode("ascii"))
    except (ValueError, RecursionError) as exc:
        # Preserve semantic refusals raised by the bounded encoder above.
        if isinstance(exc, ModelSelectionError):
            raise
        raise ModelSelectionError(error) from exc
    return bytes(result)


def _record(record, error):
    _json_value(record, error, limit=MAX_LINE_BYTES - 1)
    _keys(record, _RECORD_KEYS, error)
    _require(type(record["policy_id"]) is str and re.fullmatch(r"[0-9a-f]{64}", record["policy_id"]) is not None, error)
    _require(type(record["split_id"]) is str and re.fullmatch(r"[0-9a-f]{64}", record["split_id"]) is not None, error)
    previous = record["previous_decision_id"]
    _require(type(previous) is str and (previous == "" or re.fullmatch(r"[0-9a-f]{64}", previous) is not None), error)
    outcome = record["outcome"]
    if type(outcome) is dict and "launch_status" in outcome:
        _require(_member(outcome["launch_status"], ("launched", "not_launched")), "invalid_history:launch_status")
    _require(record["schema"] == "aegis.model-decision/v1" and _token(record["team_id"]), error)
    _require(type(record["subject"]) is str and _SUBJECT.fullmatch(record["subject"]) is not None, error)
    task, role = record["task_kind"], record["role_kind"]
    _require(_member(task, _TASK_ROLES) and _member(role, _TASK_ROLES[task]), error)
    _require(_member(record["intent"], _INTENTS) and type(record["split_eligible"]) is bool, error)
    choice = record["choice"]
    _keys(choice, _CHOICE_KEYS, error)
    _require(all(_token(v) for k, v in choice.items() if k != "model") and
             type(choice["model"]) is str and _IDENTIFIER.fullmatch(choice["model"]) is not None and
             choice["class"] in _CLASSES and choice["level"] in ("low", "medium", "high", "xhigh", "max"), error)
    _require(_member(record["admission"], ("unprobed", "admitted")) and
             choice["admission"] == record["admission"], error)
    shares = record["target_shares"]
    _shares(shares, error)
    _require(choice["family"] in shares, error)
    order = record["family_order"]
    _require(type(order) is list and len(order) == 2 and all(_member(f, shares) for f in order) and
             len(set(order)) == 2 and set(order) == set(shares), error)
    counts = record["counts_before"]
    _keys(counts, shares, error)
    _require(all(type(v) is int and v >= 0 for v in counts.values()), error)
    expected = ("manager_family",) if task == "T1" else (("lane_family",) if task == "T3" else (
        ("review_policy",) if role == "reviewer" else (
            ("family_split", "team_family") if task in _FLEXIBLE else ("team_family",))))
    _require(choice["reason"] in expected and
             record["split_eligible"] == (choice["reason"] == "family_split"), error)
    stage = record["review_stage"]
    _require(_member(stage, _STAGES[task]) if role == "reviewer" else stage is None, error)
    author = record["author_family"]
    _require(author is None or _member(author, shares), error)
    _require(role != "reviewer" or author is not None, error)
    _require(task != "T7" or author == choice["family"], error)
    if task == "T8":
        _require(author is not None and ((stage == "primary" and author != choice["family"]) or
                                        (stage == "second" and author == choice["family"])), error)
    _require(record["decision_id"] == _identity(record, checked=True), error)
    if record["split_eligible"]:
        _require(choice["family"] == _split_family(shares, order, counts),
                 "invalid_history:family_split: restore_complete_decision_log")


def _split_family(shares, order, counts):
    first, second = order
    if shares[first] == 0:
        return second
    if shares[second] == 0:
        return first
    total = sum(counts.values())
    return first if total == 0 or Fraction(counts[first], total) < Fraction(str(shares[first])) else second


class _Replay:
    """Bounded chain heads and explicit launch states, tallied by team/split."""
    def __init__(self, team_id=None, split_id=None, shares=(), order=()):
        self.team_id = team_id
        self.counts = dict.fromkeys(shares, 0)
        self.tallies = {(team_id, split_id): self.counts} if team_id is not None else {}
        self.splits = {}
        if team_id is not None:
            _require(split_id == _split_identity(shares, order), "invalid_history")
            self.splits[split_id] = _split_snapshot(shares, order)
        self.family_sets = {team_id: frozenset(shares)} if team_id is not None else {}
        self.formal, self.policy_splits = {}, {}
        self.heads, self.seen = {}, {}

    def add(self, record):
        identity, team = record["decision_id"], record["team_id"]
        families = frozenset(record["target_shares"])
        if team not in self.family_sets:
            self.family_sets[team] = families
        _require(families == self.family_sets[team], "invalid_history")
        split_id = record["split_id"]
        snapshot = _split_snapshot(record["target_shares"], record["family_order"])
        if split_id not in self.splits:
            _require(split_id == _split_identity(record["target_shares"], record["family_order"]), "invalid_history")
            self.splits[split_id] = snapshot
        _require(snapshot == self.splits[split_id], "invalid_history")
        policy_key = (team, record["policy_id"])
        if policy_key not in self.policy_splits:
            self.policy_splits[policy_key] = split_id
        _require(split_id == self.policy_splits[policy_key], "invalid_history")
        if record["task_kind"] in ("T4", "T5"):
            stages = self.formal.setdefault(policy_key, {})
            task, family = record["task_kind"], record["choice"]["family"]
            _require(task not in stages or stages[task] == family, "invalid_history")
            stages[task] = family
            _require(len(stages) != 2 or set(stages.values()) == families, "invalid_history")
        key = (team, split_id)
        if key not in self.tallies:
            self.tallies[key] = dict.fromkeys(record["target_shares"], 0)
        counts = self.tallies[key]
        _require(set(record["target_shares"]) == set(counts), "invalid_history")
        if identity not in self.seen:
            _require(record["previous_decision_id"] == self.heads.get(team, ""), _CHAIN_ERROR)
            _require(record["counts_before"] == counts,
                     "invalid_history:counts_before: restore_complete_decision_log")
            self.heads[team] = identity
        outcome = record["outcome"]
        was_active = self.seen.get(identity, False)
        active = was_active if identity in self.seen else record["split_eligible"]
        if type(outcome) is dict and "launch_status" in outcome:
            active = record["split_eligible"] and outcome["launch_status"] == "launched"
        if active != was_active:
            counts[record["choice"]["family"]] += 1 if active else -1
        self.seen[identity] = active


def _counts(history, data, split_id, policy_id):
    _require(isinstance(history, Iterable), "invalid_history")
    replay = _Replay(data["team_id"], split_id, data["target_shares"], data["family_order"])
    size = 0
    try:
        rows = history._rows if type(history) is _HistoryReader else ((_line(row), row) for row in history)
        for count, (line, previous) in enumerate(rows, 1):
            _require(count <= MAX_HISTORY_RECORDS, _HISTORY_LIMIT)
            size += len(line)
            _require(size <= MAX_HISTORY_BYTES, _HISTORY_LIMIT)
            replay.add(previous)
            if previous["team_id"] == data["team_id"]:
                _policy_record(previous, data, policy_id, split_id)
    finally:
        close = getattr(history, "close", None)
        if callable(close):
            close()
    return replay.counts, replay.heads.get(data["team_id"], "")


def _family(data, task, counts, author, lane, stage):
    if task == "T1":
        return data["manager_family"], "manager_family"
    if task == "T3":
        _require(_member(lane, data["family_hosts"]), "invalid_lane_family")
        return lane, "lane_family"
    if task in _REVIEWS:
        _require(_member(author, data["family_hosts"]), "invalid_author_family")
        _require(_member(stage, data["review_families"][task]), "invalid_review_stage")
        family = data["review_families"][task][stage]
        if task == "T8":
            family = next(f for f in data["family_order"] if f != author) if stage == "primary" else author
        return family, "review_policy"
    if task in data["flexible_tasks"]:
        return _split_family(data["target_shares"], data["family_order"], counts), "family_split"
    return data["team_family"], "team_family"


def _policy_record(record, data, policy_id, split_id):
    """Derive same-team history claims from supplied rules, not claimed eligibility."""
    if record["policy_id"] == policy_id:
        _require(record["split_id"] == split_id and record["target_shares"] == data["target_shares"] and
                 record["family_order"] == data["family_order"], "invalid_history")
    # Earlier calibrations have independent, already-validated split snapshots.
    rules = dict(data, target_shares=record["target_shares"], family_order=record["family_order"])
    try:
        family, reason = _family(rules, record["task_kind"], record["counts_before"],
                                 record["author_family"], data["team_family"], record["review_stage"])
    except ModelSelectionError as exc:
        raise ModelSelectionError("invalid_history") from exc
    _require(record["choice"]["reason"] == reason and record["split_eligible"] == (reason == "family_split") and
             record["choice"]["family"] == family, "invalid_history")


def select_model(bindings, policy, task_kind, role_kind, prior_decisions, *, host_kinds, subject=None, intent=None,
                 author_family=None, lane_family=None, review_stage="primary"):
    """Return a choice with admission provenance and a deterministic decision record.

    intent is semantic (light..max), never native effort or ultra. subject is
    required; host_kinds supplies the registry; lane_family is required for T3.
    File inputs have semantic errors.
    Changed family sets require a new team history; T8 second is explicitly opted
    into through review_stage. Use select_and_append when recording a launch.
    """
    _require(_member(task_kind, _TASK_ROLES), "unknown_task_kind")
    _require(_member(role_kind, _ROLES), "unknown_role_kind")
    _require(role_kind in _TASK_ROLES[task_kind], "task_role_mismatch")
    _require(type(subject) is str and _SUBJECT.fullmatch(subject) is not None, "invalid_subject")
    _require(host_kinds is not None, "invalid_bindings")
    roles, hosts = validate_bindings(bindings, host_kinds=host_kinds)
    data = _policy(policy, hosts)
    shares = data["target_shares"]
    _require(author_family is None or _member(author_family, shares), "invalid_author_family")
    if role_kind in ("implementer", "integrator") and lane_family is not None:
        _require(lane_family == data["team_family"], "invalid_request:lane_family")
    _require(lane_family is None or _member(lane_family, shares), "invalid_lane_family")
    _require(role_kind == "reviewer" or review_stage == "primary", "invalid_review_stage")
    policy_id = hashlib.sha256(_encoded(data, MAX_INPUT_BYTES, "invalid_policy")).hexdigest()
    split_id = _split_identity(shares, data["family_order"])
    counts, previous_id = _counts(prior_decisions, data, split_id, policy_id)
    family, reason = _family(data, task_kind, counts, author_family, lane_family, review_stage)
    if task_kind == "T7":
        _require(author_family is None or author_family == family, "invalid_request:author_family")
        author_family = family
    band = roles[role_kind]["band"]
    chosen_intent = intent if intent is not None else data.get("task_intents", {}).get(
        task_kind, {}).get(family, band["default"])
    _require(_member(chosen_intent, _INTENTS), "unknown_intent")
    _require(_INTENTS.index(band["floor"]) <= _INTENTS.index(chosen_intent) <=
             _INTENTS.index(band["ceiling"]), "intent_outside_role_band")
    model_class = roles[role_kind]["model_class"]
    host = data["family_hosts"][family][0]
    binding = hosts.get((host, model_class))
    _require(binding is not None and chosen_intent in binding["levels"] and
             binding["admission"][chosen_intent] != "rejected", "binding_unavailable:" + host + ":" + chosen_intent)
    choice = {"host": host, "class": model_class, "model": binding["model"],
              "level": binding["levels"][chosen_intent], "family": family, "reason": reason,
              "admission": binding["admission"][chosen_intent]}
    record = {"schema": "aegis.model-decision/v1", "team_id": data["team_id"],
              "task_kind": task_kind, "role_kind": role_kind, "intent": chosen_intent,
              "author_family": author_family, "choice": dict(choice),
              "split_eligible": reason == "family_split", "target_shares": dict(shares),
              "counts_before": counts, "outcome": None, "subject": subject, "admission": choice["admission"],
              "review_stage": review_stage if role_kind == "reviewer" else None,
              "family_order": list(data["family_order"]),
              "policy_id": policy_id, "split_id": split_id, "previous_decision_id": previous_id}
    record["decision_id"] = _identity(record)
    _record(record, "invalid_history")
    return choice, record


def _line(record):
    _record(record, "invalid_history")
    return _encoded(record, MAX_LINE_BYTES - 1, "invalid_history", checked=True) + b"\n"


def _safe_path(path, error="unsafe_decision_path"):
    _require(not path.is_symlink(), error)
    for parent in path.parents:
        _require(not parent.is_symlink(), error)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    _require(stat.S_ISREG(mode), error)


def _open_regular(path, error, cap=None):
    path = path.absolute()
    _require(_DIR_FD_SUPPORTED, "anchored_io_unavailable")
    _require(".." not in path.parts, error)
    _safe_path(path, error)
    before = path.lstat()
    cursor, descriptor = None, None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        cursor = os.open(path.anchor, flags)
        for component in path.parent.parts[1:]:
            child = os.open(component, flags, dir_fd=cursor)
            previous, cursor = cursor, child
            os.close(previous)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             getattr(os, "O_CLOEXEC", 0), dir_fd=cursor)
        opened = os.fstat(descriptor)
        visible = os.stat(path.name, dir_fd=cursor, follow_symlinks=False)
        _require(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(visible.st_mode) and
                 (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino) ==
                 (visible.st_dev, visible.st_ino), error)
        if cap is not None:
            _require(opened.st_size <= cap, error)
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        return stream
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if cursor is not None:
            os.close(cursor)


def _history_rows(stream):
    """Yield original bytes and validated records without retaining the log."""
    _require(os.fstat(stream.fileno()).st_size <= MAX_HISTORY_BYTES, _HISTORY_LIMIT)
    size, count = 0, 0
    replay = _Replay()
    while True:
        line = stream.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        size += len(line)
        count += 1
        _require(size <= MAX_HISTORY_BYTES and count <= MAX_HISTORY_RECORDS, _HISTORY_LIMIT)
        _require(len(line) <= MAX_LINE_BYTES and line.endswith(b"\n"), "invalid_history")
        record = _loads(line, "invalid_history")
        _require(line == _line(record), "invalid_history")
        replay.add(record)
        yield line, record


def _path_call(operation, *args, missing=False, **kwargs):
    """Translate filename-operation failures, outside descriptor write/fsync work."""
    try:
        return operation(*args, **kwargs)
    except (ModelSelectionError, LockTimeoutError):
        raise
    except FileNotFoundError as exc:
        if missing:
            raise
        raise ModelSelectionError("unsafe_decision_path") from exc
    except (ValueError, OSError) as exc:
        raise ModelSelectionError("unsafe_decision_path") from exc


@contextmanager
def _decision_path(value):
    path = _path_call(_path_value, value, "unsafe_decision_path")
    _require("\x00" not in str(path), "unsafe_decision_path")
    _require(".." not in path.parts, "unsafe_decision_path")
    _require(not path.name.endswith(".lock"), "invalid_log_path")
    yield _path_call(path.absolute)


class _HistoryReader:
    """An owned disk iterator, never a trust marker attached to caller dictionaries."""
    def __init__(self, path, directory=None, *, capture=False):
        self._snapshot = [] if capture else None
        rows = _read_rows(path, directory)
        self._rows = self._capture(rows) if capture else rows

    def _capture(self, rows):
        try:
            for line, record in rows:
                # _history_rows enforces byte/row caps before yielding immutable bytes.
                self._snapshot.append(line)
                yield line, record
        finally:
            rows.close()

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._rows)[1]

    def close(self):
        self._rows.close()


def read_decisions(path):
    """Return a strict bounded JSONL iterator under .lock; consume or close it.

    Only a missing log file in a valid existing directory means an empty stream.
    Missing directories, .. components and malformed history refuse. Readers
    enforce per-team family sets and formal-pair consistency. No decoded rows accumulate.
    Selection closes streams it consumes, including on a history refusal.
    """
    return _HistoryReader(path)


def _read_rows(path, directory=None):
    if directory is not None:
        try:
            stream = _open_log(path.name, directory)
        except FileNotFoundError:
            return
        with stream:
            yield from _history_rows(stream)
        return
    with _decision_path(path) as target:
        directory = _path_call(_decision_directory, target)
        try:
            # Check before creating the lock: a missing-log read has no side effects.
            try:
                probe = _open_log(target.name, directory)
            except FileNotFoundError:
                return
            probe.close()
            with ExitStack() as stack:
                _path_call(stack.enter_context, file_lock(target.with_name(target.name + ".lock"), dir_fd=directory))
                with _path_call(_open_log, target.name, directory) as stream:
                    yield from _history_rows(stream)
        finally:
            os.close(directory)


def _decision_directory(path):
    _require(_DIR_FD_SUPPORTED, "anchored_io_unavailable")
    _path_call(_safe_path, path)
    given = path.parent
    _require(".." not in given.parts, "unsafe_decision_path")
    expected = _path_call(given.lstat, missing=True)
    try:
        parent = _path_call(given.parent.resolve, strict=True, missing=True)
    except RuntimeError as exc:
        raise ModelSelectionError("unsafe_decision_path") from exc
    _require(parent == given.parent, "unsafe_decision_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    cursor, directory = None, None
    try:
        cursor = _path_call(os.open, parent.anchor, flags, missing=True)
        for component in parent.parts[1:]:
            child = _path_call(os.open, component, flags, dir_fd=cursor)
            previous, cursor = cursor, child
            os.close(previous)
        leaf = given.name or "."
        directory = _path_call(os.open, leaf, flags, dir_fd=cursor)
        info = os.fstat(directory)
        _require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "unsafe_decision_directory")
        visible = _path_call(os.stat, leaf, dir_fd=cursor, follow_symlinks=False)
        _require(stat.S_ISDIR(visible.st_mode) and (visible.st_dev, visible.st_ino) ==
                 (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino), "unsafe_decision_path")
        previous, cursor = cursor, None
        os.close(previous)
        result, directory = directory, None
        return result
    finally:
        if directory is not None:
            os.close(directory)
        if cursor is not None:
            os.close(cursor)


def _open_log(name, directory):
    before = _path_call(os.stat, name, dir_fd=directory, follow_symlinks=False, missing=True)
    _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == os.getuid() and not before.st_mode & 0o022, "unsafe_decision_path")
    descriptor = _path_call(os.open, name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                            getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
    try:
        _same_file(name, descriptor, directory)
        opened = os.fstat(descriptor)
        _require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                 opened.st_uid == os.getuid() and not opened.st_mode & 0o022, "unsafe_decision_path")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _same_file(name, descriptor, directory):
    visible = _path_call(os.stat, name, dir_fd=directory, follow_symlinks=False)
    opened = os.fstat(descriptor)
    _require(stat.S_ISREG(visible.st_mode) and visible.st_nlink == 1 and
             (visible.st_dev, visible.st_ino) == (opened.st_dev, opened.st_ino), "unsafe_decision_path")


def _write_all(descriptor, payload):
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("decision log write made no progress")
        view = view[written:]


def _publish(path, payload, directory, snapshot=None):
    source, replay = None, None
    size, count = 0, 0
    if snapshot is None:
        pending = _loads(payload, "invalid_history")  # frozen validated bytes, not caller-owned data
        replay = _Replay(pending["team_id"], pending["split_id"], pending["target_shares"], pending["family_order"])
        try:
            source = _open_log(path.name, directory)
        except FileNotFoundError:
            pass
    else:
        # Only the locked transaction's fully consumed owned reader supplies these bytes.
        size, count = sum(map(len, snapshot)), len(snapshot)
        _require(size + len(payload) <= MAX_HISTORY_BYTES and count + 1 <= MAX_HISTORY_RECORDS, _HISTORY_LIMIT)
    descriptor, temporary = None, None
    try:
        candidate = ".model-select-" + secrets.token_hex(16)
        descriptor = _path_call(os.open, candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW |
                                getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=directory)
        temporary = candidate
        _same_file(temporary, descriptor, directory)
        if snapshot is not None:
            for line in snapshot:
                _write_all(descriptor, line)
        elif source is not None:
            for line, previous in _history_rows(source):
                replay.add(previous)
                _write_all(descriptor, line)
                size += len(line)
                count += 1
        if replay is not None:
            if pending["decision_id"] not in replay.seen:
                _require(pending["counts_before"] == replay.counts and pending["previous_decision_id"] ==
                         replay.heads.get(pending["team_id"], ""), "stale_decision")
            replay.add(pending)
        _require(size + len(payload) <= MAX_HISTORY_BYTES and count + 1 <= MAX_HISTORY_RECORDS, _HISTORY_LIMIT)
        _write_all(descriptor, payload)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        if source is not None:
            source.close()
        _same_file(temporary, descriptor, directory)
        _path_call(os.rename, temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
    finally:
        primary = sys.exc_info()[1]
        cleanup_error, cleanup = None, []
        if source is not None:
            cleanup.append((source.close, (), {}))
        if descriptor is not None:
            cleanup.append((os.close, (descriptor,), {}))
        if temporary is not None:
            cleanup.append((_path_call, (os.unlink, temporary), {"dir_fd": directory}))
        for operation, args, kwargs in cleanup:
            try:
                operation(*args, **kwargs)
            except (OSError, ModelSelectionError) as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if cleanup_error is not None:
            if primary is not None:
                raise primary from cleanup_error
            raise cleanup_error


def append_decision(path, record):
    """Publish old bytes plus one bounded record atomically under the .lock.

    Any failure before rename leaves old history unchanged. History limits refuse
    with an explicit archive/rotate action. Lock and descriptor I/O errors propagate;
    filename operations refuse unsafe_decision_path. Cleanup errors are chained
    under the primary failure. New decisions with stale counts_before or a stale
    previous_decision_id refuse stale_decision; use select_and_append for launches.
    """
    payload = _line(record)
    with _decision_path(path) as target:
        directory = _path_call(_decision_directory, target)
        try:
            with ExitStack() as stack:
                _path_call(stack.enter_context, file_lock(target.with_name(target.name + ".lock"), dir_fd=directory))
                _publish(target, payload, directory)
        finally:
            os.close(directory)


def select_and_append(path, bindings, policy, task_kind, role_kind, *, host_kinds, subject=None, intent=None,
                      author_family=None, lane_family=None, review_stage="primary"):
    """Atomically read, choose and publish a launch; use this API for concurrent callers.

    The same anchored directory and log lock cover both selection and publication.
    The lock timeout is 60 seconds. History is validated once; bounded immutable
    raw bytes from that pass are reused for publication without parsing again.
    Low-level append_decision refuses stale new decisions. Existing decision IDs
    may receive further outcome observations without counting another launch.
    """
    with _decision_path(path) as target:
        directory = _path_call(_decision_directory, target)
        try:
            with ExitStack() as stack:
                _path_call(stack.enter_context, file_lock(target.with_name(target.name + ".lock"),
                                                        timeout=_LOCK_TIMEOUT_SECONDS, dir_fd=directory))
                history = _HistoryReader(target, directory, capture=True)
                try:
                    choice, record = select_model(bindings, policy, task_kind, role_kind, history,
                                                  host_kinds=host_kinds, subject=subject, intent=intent,
                                                  author_family=author_family, lane_family=lane_family,
                                                  review_stage=review_stage)
                finally:
                    history.close()
                _publish(target, _line(record), directory, history._snapshot)
                return choice, record
        finally:
            os.close(directory)
