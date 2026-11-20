"""Tool-supplied served identity observations; contract: docs/model-selection.md."""
from __future__ import annotations

from collections.abc import Iterator
import json
import os
import re

from aegis_core import model_select

__all__ = ["observe_served", "served_of"]

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_DECISION_ID = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY_KEYS = ("host", "model", "level", "family")
_SERVED_KEYS = frozenset((*_IDENTITY_KEYS, "fallback_reason"))
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


def _choice(row):
    value = row.get("choice")
    if type(value) is not dict or not all(
            _token(value.get(key), model=key == "model") for key in _IDENTITY_KEYS):
        return None
    return {key: value[key] for key in _IDENTITY_KEYS}


def _reason_matches(served, choice):
    differs = any(served[key] != choice[key] for key in _IDENTITY_KEYS)
    return differs == (served["fallback_reason"] is not None)


def _anchored_io_supported():
    # Same capabilities as model_select, without importing its private probe.
    return (os.name == "posix" and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and
            hasattr(os, "fchmod") and hasattr(os, "getuid") and
            {"open", "stat", "rename", "unlink"} <= {fn.__name__ for fn in os.supports_dir_fd})


def _line_size(row):
    # Only bounded, validated read_decisions rows plus a fixed five-token block enter here.
    return len(json.dumps(row, sort_keys=True, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":"))) + 1


def observe_served(path, decision_id, served):
    """Append and return a status-free receipt for an existing decision.

    Refuse invalid_decision_id, invalid_served (including a missing fallback
    reason or a reason for an unchanged identity), or unknown_decision_id.
    Line/history caps and anchored I/O use model_select's existing refusal codes.
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
    original, count, size = None, 0, 0
    rows = model_select.read_decisions(path)
    try:
        for row in rows:
            count += 1
            size += _line_size(row)
            if original is None and row["decision_id"] == decision_id:
                original = row
    finally:
        rows.close()
    if original is None:
        raise model_select.ModelSelectionError("unknown_decision_id")
    if not _reason_matches(served, original["choice"]):
        raise model_select.ModelSelectionError("invalid_served")
    record = {**original, "outcome": {"served": served}}
    length = _line_size(record)
    if length > model_select.MAX_LINE_BYTES:
        raise model_select.ModelSelectionError("decision_line_too_large")
    if count + 1 > model_select.MAX_HISTORY_RECORDS or size + length > model_select.MAX_HISTORY_BYTES:
        raise model_select.ModelSelectionError(_HISTORY_LIMIT)
    # Immutable decision identity survives additive peers between read and append.
    # append_decision revalidates the complete resulting history under its own lock.
    model_select.append_decision(path, record)
    return record


def served_of(rows, decision_id):
    """Return the newest valid served block plus computed cross_family, or None.

    Missing/malformed blocks are absent, never a chosen-identity fallback. Use
    read_decisions for validated disk history; its I/O/history refusals propagate.
    None requires a complete, in-bounds history; exceeding MAX_HISTORY_RECORDS
    refuses the existing history limit even when a valid block was already found.
    Accept a list, tuple, or Iterator. Other histories refuse invalid_history
    before reading any rows. Iterator reads use next() and propagate failures.
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
    result, choice, author = None, None, None
    end = object()
    for count in range(1, model_select.MAX_HISTORY_RECORDS + 2):
        row = next(iterator, end)
        if row is end:
            break
        if count > model_select.MAX_HISTORY_RECORDS:
            raise model_select.ModelSelectionError(_HISTORY_LIMIT)
        if type(row) is not dict or row.get("decision_id") != decision_id:
            continue
        candidate = _choice(row)
        candidate_author = row.get("author_family")
        if candidate is None or (candidate_author is not None and not _token(candidate_author)):
            continue
        if choice is None:
            choice, author = candidate, candidate_author
        if candidate != choice or candidate_author != author:
            continue
        outcome = row.get("outcome")
        served = outcome.get("served") if type(outcome) is dict else None
        if _served(served) and _reason_matches(served, choice):
            result = {**served, "cross_family": author is not None and served["family"] != author}
    return result
