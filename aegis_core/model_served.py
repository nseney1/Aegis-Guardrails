"""Tool-supplied served identity observations; contract: docs/model-selection.md."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, nullcontext
import os
import re

from aegis_core import model_select

__all__ = ["admit_probe", "observe_served", "served_of"]

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_DECISION_ID = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_KEYS = ("host", "model", "level", "family")
_SERVED_KEYS = frozenset((*_IDENTITY_KEYS, "fallback_reason"))
_PROBE_KEYS = frozenset((*_IDENTITY_KEYS, "decision_id", "provenance"))
_CONFLICT = "decision_outcome_conflict"
_HISTORY_LIMIT = "history_limit_exceeded: archive_or_rotate_decision_log"


def _token(value, *, model=False):
    # Bound work before regex matching; no normalization can turn a bad receipt valid.
    return (type(value) is str and 1 <= len(value) <= 128 and
            (_IDENTIFIER if model else _TOKEN).fullmatch(value) is not None)


def _decision_id(value):
    return type(value) is str and len(value) == 64 and _DECISION_ID.fullmatch(value) is not None


def _served(value):
    if type(value) is not dict or len(value) != len(_SERVED_KEYS) or value.keys() != _SERVED_KEYS:
        return False
    return (all(_token(value[key], model=key == "model") for key in _IDENTITY_KEYS) and
            (value["fallback_reason"] is None or _token(value["fallback_reason"])))


def _reason_matches(served, choice):
    differs = any(served[key] != choice[key] for key in _IDENTITY_KEYS)
    return differs == (served["fallback_reason"] is not None)


def _anchored_io_supported():
    # Same capabilities as model_select, without importing its private probe.
    return (os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and
            hasattr(os, "fchmod") and hasattr(os, "getuid") and
            {"open", "stat", "rename", "unlink"} <= {fn.__name__ for fn in os.supports_dir_fd})


def admit_probe(path, bindings, decision_id, reported, *, host_kinds):
    """Record readback for a staged attempt and refuse admission.

    The report has decision_id, host, model, level (native effort), family and
    provenance. It must come from the probe runner. Missing, malformed or
    mismatched evidence refuses probe_readback_missing, invalid_probe_readback
    or probe_readback_mismatch. An ordinary decision refuses not_probe_attempt.
    Exact reports and retries refuse decision_outcome_conflict. Evidence belongs
    to the recorded attempt, including when the supplied bindings have changed.
    """
    if not _decision_id(decision_id):
        raise model_select.ModelSelectionError("invalid_decision_id")
    if reported is None:
        raise model_select.ModelSelectionError("probe_readback_missing")
    if type(reported) is not dict or len(reported) != len(_PROBE_KEYS):
        raise model_select.ModelSelectionError("invalid_probe_readback")
    reported = dict(reported)
    if (reported.keys() != _PROBE_KEYS or not _decision_id(reported["decision_id"]) or
            not _token(reported["provenance"]) or
            not all(_token(reported[key], model=key == "model") for key in _IDENTITY_KEYS)):
        raise model_select.ModelSelectionError("invalid_probe_readback")
    if reported["decision_id"] != decision_id:
        raise model_select.ModelSelectionError("probe_readback_mismatch")
    if not _anchored_io_supported():
        raise model_select.ModelSelectionError("anchored_io_unavailable")

    def prepare(original):
        if "probe_id" not in original:
            raise model_select.ModelSelectionError("not_probe_attempt")
        served = {key: reported[key] for key in _IDENTITY_KEYS}
        outcome = {"served": {**served, "fallback_reason": None},
                   "probe_readback": {"decision_id": reported["decision_id"], "provenance": reported["provenance"],
                                      "registry_id": original.get("registry_id")}}
        return {**original, "outcome": outcome}

    try:
        return model_select.append_decision(path, None, known_decision=decision_id, prepare=prepare,
                                            probe_bindings=(bindings, host_kinds))
    except model_select.ProbeIdentityConflict:
        raise model_select.ModelSelectionError("probe_readback_mismatch") from None


def observe_served(path, decision_id, served):
    """Append and return a status-free receipt for an existing decision.

    Refuse invalid_decision_id, invalid_served (including a missing fallback
    reason or a reason for an unchanged identity), or unknown_decision_id.
    Line/history caps and anchored I/O use model_select's existing refusal codes.
    The id is found, checked against this served block and published from one
    locked snapshot. A generation that no longer contains the id refuses
    unknown_decision_id and is never admitted as a launch.
    Read/append failures retain that API's lock and descriptor I/O behavior.
    Every refusal before publication preserves the decision log's bytes.
    """
    if not _decision_id(decision_id):
        raise model_select.ModelSelectionError("invalid_decision_id")
    if not _served(served):
        raise model_select.ModelSelectionError("invalid_served")
    served = dict(served)
    if not _anchored_io_supported():
        raise model_select.ModelSelectionError("anchored_io_unavailable")

    def prepare(original):
        # The choice belongs to the snapshot about to be published.
        if not _reason_matches(served, original["choice"]):
            raise model_select.ModelSelectionError("invalid_served")
        return {**original, "outcome": {"served": served}}

    return model_select.append_decision(path, None, known_decision=decision_id, prepare=prepare)


def served_of(rows, decision_id, *, probe_bindings=None):
    """Return the newest valid served block plus computed cross_family, or None.

    Missing/malformed blocks are absent, never a chosen-identity fallback. Use
    read_decisions for validated disk history; its I/O/history refusals propagate.
    None requires a complete, in-bounds history; exceeding MAX_HISTORY_RECORDS
    refuses the existing history limit even when a valid block was already found.
    Accept a list, tuple, or Iterator. Other histories refuse invalid_history
    before reading any rows. Iterator reads use next() and propagate failures.
    Clean probe histories return None. Contradictions refuse decision_outcome_conflict.
    The optional probe_bindings argument is retained for callers.
    cross_family is false without an author family. Inputs are never modified.
    """
    if not _decision_id(decision_id):
        raise model_select.ModelSelectionError("invalid_decision_id")
    # Traverse list and tuple storage directly, including for subclasses.
    if issubclass(type(rows), list):
        iterator = list.__iter__(rows)
    elif issubclass(type(rows), tuple):
        iterator = tuple.__iter__(rows)
    elif isinstance(rows, Iterator):
        iterator = rows
    else:
        raise model_select.ModelSelectionError("invalid_history")
    with closing(iterator) if type(iterator) is model_select.DecisionHistory else nullcontext():
        return _project_served(iterator, decision_id)


def _project_served(iterator, decision_id):
    replay = model_select.DecisionReplay()
    result, replay_error = None, None
    mentions_probe, size = False, 0
    end = object()
    for count in range(1, model_select.MAX_HISTORY_RECORDS + 2):
        row = next(iterator, end)
        if row is end:
            break
        if count > model_select.MAX_HISTORY_RECORDS:
            raise model_select.ModelSelectionError(_HISTORY_LIMIT)
        matches = type(row) is dict and row.get("decision_id") == decision_id
        if matches:
            mentions_probe |= replay.mentions_probe(row)
        if replay_error is not None and (not matches or mentions_probe):
            continue
        try:
            size += replay.checked_size(row)
        except model_select.ModelSelectionError as error:
            replay_error = replay_error or error
            continue
        if size > model_select.MAX_HISTORY_BYTES:
            raise model_select.ModelSelectionError(_HISTORY_LIMIT)
        if replay_error is None:
            try:
                replay.add(row)
            except model_select.ModelSelectionError as error:
                # Ordinary projection ignores invalid rows. Probe audit uses the full replay.
                replay_error = error
        if not matches or mentions_probe:
            continue
        outcome, choice, author = row["outcome"], row["choice"], row["author_family"]
        served = outcome.get("served") if type(outcome) is dict else None
        if _served(served) and _reason_matches(served, choice):
            result = {**served, "cross_family": author is not None and served["family"] != author}
    if mentions_probe:
        if replay_error is not None:
            raise model_select.ModelSelectionError(_CONFLICT)
        replay.check_probe_audit(decision_id)
        return None
    return result
