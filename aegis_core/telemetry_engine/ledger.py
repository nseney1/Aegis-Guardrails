"""The outcome ledger (build-sheet D13, ADR 0005 AD-1/AD-5, v4.2 #7).

The ledger is append-only and the only source of rule fitness. In a git repository it is
ONE file for every worktree, ``<git common dir>/aegis/state/<ws-id>/ledger.jsonl``
(aegis_core.storage.ledger_site: ``<ws-id>`` names the workspace by its path below the git
toplevel, so each ``.aegis`` workspace has its own); outside git it is
``.aegis/state/ledger.jsonl``. Every row is versioned::

    {"v": 2, "seq": 7, "ts": "2026-10-15T12:00:00Z", "worktree": "/path/to/worktree",
     "rule": "trap-x", "outcome": "tp", "source": "mcp", "host": "claude-code",
     "session": "…", "key": "report-1", "weight": 0.5, "meta": {…}}

``worktree`` (the top of the work tree that wrote the row) is present in the shared ledger
only. It is attribution, like ``host`` and ``session``: it is not part of a row's payload,
so the same report retried from another worktree is the same row.

- ``outcome`` is ``tp``, ``fp`` or ``trigger``. Every outcome row is also a trigger (#15):
  a rule credited with a tp was, by definition, relevant. ``trigger`` alone says the
  rule was relevant without a verdict.
- ``weight`` (0..1, default 1) scales the tp/fp credit; it never scales the trigger count.
- ``seq`` increases by one per row. ``(key, rule)`` is the idempotency identity: one
  report naming N rules shares one key and writes N rows; a retry writes nothing and
  returns the stored row. Reusing a key for a different payload is an EventConflictError.
- Rows are appended under the ledger lock with one fsync (aegis_core.storage.ledger_locked:
  one lock file next to the shared ledger, taken by every writer of every worktree; the
  workspace lock outside git); nothing ever rewrites a row. A migration appends an epoch
  row instead. A caller that holds the worktree lock takes it first.

Readers accept v1 rows (the ``cell``/``rule_id`` + ``signal`` shape of the v3
``signals.jsonl``) and convert them in memory; see ``normalize_rows``.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import math
import os
from pathlib import Path
import threading
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aegis_core.errors import PathTraversalError
from aegis_core.storage import append_jsonl, ledger_locked, ledger_site, read_jsonl

__all__ = [
    "LEDGER_VERSION",
    "OUTCOMES",
    "SOURCES",
    "EventConflictError",
    "LedgerView",
    "aggregate",
    "aggregate_rows",
    "append",
    "append_epoch",
    "append_rows",
    "incomplete",
    "is_ambient_session_row",
    "ledger_path",
    "merge_rows",
    "normalize_rows",
    "plan_merge",
    "read",
]

LEDGER_VERSION = 2
OUTCOMES = ("tp", "fp", "trigger")
SOURCES = ("ci", "session", "mcp", "manual", "migrate")
_CREDIT_EVENTS = frozenset({
    "exposure",
    "detection",
    "check_confirm",
    "override",
    "human_label",
    "claim",
    "claimed",
    "transition",
    "check",
    "adjudication",
    "report",
    "ci",
    "void",
})
_V1_SIGNALS = {"tp": "tp", "success": "tp", "fp": "fp", "failure": "fp", "trigger": "trigger"}
_MAX_LEGACY_WEIGHT = Decimal("10")


class EventConflictError(ValueError):
    """An idempotency key was already recorded for this rule with a different payload."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ledger_path(workspace: Any) -> Path:
    """The ledger file of ``workspace`` (aegis_core.storage.ledger_site); nothing is created.
    Raises PathTraversalError when the shared state directory is not confined."""
    return ledger_site(workspace, create=False).path


def _weight(row: Dict[str, Any]) -> Optional[Decimal]:
    value = row.get("weight", 1)
    if isinstance(value, bool):
        return None
    try:
        weight = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    if not weight.is_finite() or weight < 0 or weight > _MAX_LEGACY_WEIGHT:
        return None
    return weight


# ── v1 compatibility ─────────────────────────────────────────────────────────

def _v1_rule(row: Dict[str, Any]) -> Optional[str]:
    for key in ("rule_id", "cell", "cell_id"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    used = row.get("cells_used")
    if isinstance(used, list) and used and isinstance(used[0], str) and used[0]:
        return used[0]
    return None


def _v1_to_v2(row: Dict[str, Any], origin: Any = "v1") -> Optional[Dict[str, Any]]:
    rule = _v1_rule(row)
    signal = row.get("signal") or row.get("outcome")
    outcome = _V1_SIGNALS.get(signal) if isinstance(signal, str) else None
    if rule is None or outcome is None:
        return None
    meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    meta = dict(meta)
    out: Dict[str, Any] = {
        "v": LEDGER_VERSION,
        "ts": row.get("timestamp") or row.get("triggered_at") or row.get("ts"),
        "rule": rule,
        "outcome": outcome,
        "source": row.get("source"),
        "host": meta.pop("host", None),
        "session": meta.pop("session", None),
        "key": row.get("event_id"),
        "from": origin,
    }
    if "credit_weight" in meta:
        out["weight"] = meta.pop("credit_weight")
    if meta:
        out["meta"] = meta
    return out


def is_ambient_session_row(row: Mapping[str, Any]) -> bool:
    """A v2 tp/fp row a local ``aegis check`` wrote before 4.4 (``source: "session"``, no ``from``).
    An unwitnessed run is a trigger, never a verdict (spec T1), so readers count it as one; the
    file is not rewritten. Migrated v3 history carries ``from`` and keeps its verdict."""
    return (row.get("v") == LEDGER_VERSION and row.get("source") == "session"
            and row.get("outcome") in ("tp", "fp") and "from" not in row)


def normalize_rows(
    rows: Iterable[Dict[str, Any]], origins: Optional[List[Any]] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Return ``(v2 outcome rows, unusable row count)`` for raw ledger rows of any version.

    v2 rows pass through (``is_ambient_session_row`` rows as triggers); rows without
    ``rule`` and ``outcome`` (an epoch row) are dropped without counting as unusable. v1 rows are converted in memory, never
    rewritten on disk. v1 counted triggers in separate ``trigger`` rows (v3 ``aegis
    check`` wrote one trigger row and one outcome row per rule and run), while a v2
    outcome row is itself a trigger. So per rule, a v1 trigger row is dropped for each
    v1 outcome row it pairs with: the rule ends with max(v1 triggers, v1 outcomes)
    triggers, as v3 readers counted it. The trigger rows kept are the latest ones, so
    the last trigger time survives. v1 MCP rows (``source: "mcp"``) never pair: v3
    wrote a report as one outcome row, and a "partial" as one trigger row.

    ``origins``, parallel to ``rows``, gives each converted row's ``from`` (provenance,
    e.g. the v3 file and line ``aegis migrate`` read it from); the default is "v1".
    """
    out: List[Dict[str, Any]] = []
    unusable = 0
    v1_triggers: Dict[str, List[Dict[str, Any]]] = {}
    v1_outcomes: Dict[str, int] = {}
    for index, row in enumerate(rows):
        if isinstance(row, dict) and row.get("event") in _CREDIT_EVENTS and "outcome" not in row:
            continue
        if row.get("v") == LEDGER_VERSION:
            if "rule" not in row and "outcome" not in row:
                continue  # epoch or other bookkeeping row
            if (
                isinstance(row.get("rule"), str) and row["rule"]
                and row.get("outcome") in OUTCOMES and _weight(row) is not None
            ):
                out.append(dict(row, outcome="trigger") if is_ambient_session_row(row) else row)
            else:
                unusable += 1
            continue
        converted = _v1_to_v2(row, origins[index] if origins is not None else "v1")
        if converted is None or _weight(converted) is None:
            unusable += 1
            continue
        rule = converted["rule"]
        if converted["source"] == "mcp":
            out.append(converted)
        elif converted["outcome"] == "trigger":
            v1_triggers.setdefault(rule, []).append(converted)
        else:
            v1_outcomes[rule] = v1_outcomes.get(rule, 0) + 1
            out.append(converted)
    for rule, triggers in v1_triggers.items():
        paired = min(len(triggers), v1_outcomes.get(rule, 0))
        out.extend(triggers[paired:])
    return out, unusable


# ── Reading ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LedgerView:
    """The ledger as read: normalized v2 outcome rows plus what could not be used."""

    rows: List[Dict[str, Any]]
    skipped_lines: List[int] = field(default_factory=list)
    unusable_rows: int = 0
    torn_tail: bool = False
    error: Optional[str] = None
    path: Optional[Path] = None
    # Every row as read (events included), for the other readers of the same call: one snapshot,
    # one parse. None on a view that never read the file; such a reader reads it and says why not.
    raw_rows: Optional[Tuple[Dict[str, Any], ...]] = field(default=None, repr=False, compare=False)

    def health(self) -> Dict[str, Any]:
        """What the read could not use, as derived.json and ``aegis status`` record it."""
        return {
            "skipped_lines": list(self.skipped_lines),
            "unusable_rows": self.unusable_rows,
            "error": self.error,
            "torn_tail": self.torn_tail,
        }

    @property
    def incomplete(self) -> Optional[str]:
        """Why ``rows`` are known to miss recorded evidence, or None (see ``incomplete``)."""
        return incomplete(self.health())


def incomplete(health: Mapping[str, Any]) -> Optional[str]:
    """Why a ledger read with this ``health`` misses recorded evidence, or None.

    Unreadable lines, unusable rows and a ledger that cannot be read at all each hide
    verdicts, so fitness from such a read is partial: it may still be shown, but nothing
    that moves or rewrites a rule may act on it. A torn last line is not counted: a
    reader racing the one locked append sees it until the write completes.
    """
    reasons = []
    if health.get("error"):
        reasons.append(str(health["error"]))
    skipped = health.get("skipped_lines") or []
    if skipped:
        reasons.append(f"{len(skipped)} unreadable line(s)")
    if health.get("unusable_rows"):
        reasons.append(f"{health['unusable_rows']} unusable row(s)")
    return ", ".join(reasons) or None


def read(workspace: Any) -> LedgerView:
    """Read the ledger. Never raises for its content or for a ledger directory that is not
    confined (``error`` says why, and the view is incomplete); a missing ledger is empty."""
    try:
        path = ledger_path(workspace)
    except PathTraversalError as exc:
        return LedgerView([], error=str(exc))
    except OSError as exc:  # the shared state dir cannot be listed for its confinement check
        return LedgerView([], error=f"cannot read {exc.filename or 'the ledger directory'}: {exc.strerror or exc}")
    raw = read_jsonl(path)
    rows, unusable = normalize_rows(raw.rows)
    return LedgerView(rows, list(raw.skipped_lines), unusable, raw.torn_tail, raw.error, path,
                      None if raw.error else tuple(raw.rows))


def _plain(value: Decimal) -> Any:
    return int(value) if value == value.to_integral_value() else float(value)


def aggregate(workspace: Any, rule: Optional[str] = None) -> Dict[str, Any]:
    """Per-rule totals ``{triggers, tp, fp, last_ts}`` from the ledger.

    With ``rule``, that rule's totals (zeros and ``last_ts: None`` when it has no rows);
    without, a mapping of every rule with rows to its totals. Every outcome row counts
    as one trigger; tp/fp sum the row weights. A row whose weight is not a number in
    [0, 10] (v1 allowed up to 10) is unusable: read() counts it and nothing uses it.
    """
    return aggregate_rows(read(workspace).rows, rule)


def aggregate_rows(rows: Iterable[Dict[str, Any]], rule: Optional[str] = None) -> Dict[str, Any]:
    """aggregate() over rows already read (normalized v2 outcome rows)."""
    sums: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        name = row["rule"]
        if rule is not None and name != rule:
            continue
        entry = sums.setdefault(name, {"triggers": 0, "tp": Decimal(0), "fp": Decimal(0), "last_ts": None})
        entry["triggers"] += 1
        ts = row.get("ts")
        if isinstance(ts, str) and (entry["last_ts"] is None or ts > entry["last_ts"]):
            entry["last_ts"] = ts
        if row["outcome"] in ("tp", "fp"):
            entry[row["outcome"]] += _weight(row) or Decimal(0)
    for entry in sums.values():
        entry["tp"] = _plain(entry["tp"])
        entry["fp"] = _plain(entry["fp"])
    if rule is not None:
        return sums.get(rule, {"triggers": 0, "tp": 0, "fp": 0, "last_ts": None})
    return sums


# ── Writing ──────────────────────────────────────────────────────────────────

def _payload_digest(row: Dict[str, Any]) -> str:
    # Attribution (host, session) and position (seq, ts) are not part of the payload:
    # a retry after a reconnect comes from a new session and must deduplicate.
    payload = {k: row.get(k) for k in ("outcome", "source", "weight", "meta")}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("ascii")).hexdigest()


# How many indexed bytes before the offset are re-read to confirm the cached index still
# describes this file: (device, inode) alone passes a ledger deleted and recreated on a
# reused inode, or rewritten in place, as long as it is at least as large as before.
_TAIL_CHECK_BYTES = 256


@dataclass
class _Index:
    """What appends need from the ledger: the next seq and the (key, rule) identities.

    Cached per ledger file and refreshed from the bytes appended since the last look,
    so an append in a long-lived process reads only the new tail. ``tail`` holds the
    last indexed bytes (up to _TAIL_CHECK_BYTES before ``offset``).
    """

    device: int = -1
    inode: int = -1
    offset: int = 0
    last_seq: int = 0
    keyed: Dict[Tuple[str, str], Dict[str, Any]] = field(default_factory=dict)
    tail: bytes = b""

    def absorb(self, raw_rows: Iterable[Dict[str, Any]]) -> None:
        for raw in raw_rows:
            seq = raw.get("seq")
            if isinstance(seq, int) and not isinstance(seq, bool) and seq > self.last_seq:
                self.last_seq = seq
        rows, _ = normalize_rows(raw_rows)
        for row in rows:
            key = row.get("key")
            if isinstance(key, str) and key:
                self.keyed.setdefault((key, row["rule"]), row)


_INDEX_GUARD = threading.Lock()
_INDEXES: Dict[str, _Index] = {}


def _parse_tail(data: bytes) -> List[Dict[str, Any]]:
    rows = []
    for line in data.split(b"\n"):
        line = line.rstrip(b"\r")
        if not line.strip():
            continue
        try:
            value = json.loads(line.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _unread(path: Path, index: Optional[_Index], st: os.stat_result) -> Tuple[_Index, bytes]:
    """The cached index if it still describes ``path``, else a new one; plus the bytes
    after its offset."""
    with open(path, "rb") as fh:
        if (
            index is not None
            and (index.device, index.inode) == (st.st_dev, st.st_ino)
            and st.st_size >= index.offset
        ):
            fh.seek(index.offset - len(index.tail))
            data = fh.read()
            if data.startswith(index.tail):
                return index, data[len(index.tail):]
            fh.seek(0)
        return _Index(device=st.st_dev, inode=st.st_ino), fh.read()


def _current_index(path: Path) -> _Index:
    """The index of ``path`` as it is on disk now. Call with the workspace lock held.

    A final line without a newline is read on every call and never cached: a torn
    write is skipped, while a complete row (the crash cut only its newline, which
    read_jsonl and aggregate() count as a row) is part of the returned index, so its
    seq and (key, rule) are never written twice. The next append terminates it.
    """
    key = str(path)
    with _INDEX_GUARD:
        index = _INDEXES.get(key)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        index = _Index()
        with _INDEX_GUARD:
            _INDEXES[key] = index
        return index
    index, data = _unread(path, index, st)
    complete = data.rfind(b"\n") + 1
    if complete:
        index.absorb(_parse_tail(data[:complete]))
        index.offset += complete
        index.tail = (index.tail + data[:complete])[-_TAIL_CHECK_BYTES:]
    with _INDEX_GUARD:
        _INDEXES[key] = index
    unterminated = _parse_tail(data[complete:])
    if not unterminated:
        return index
    view = _Index(index.device, index.inode, index.offset, index.last_seq, dict(index.keyed), index.tail)
    view.absorb(unterminated)
    return view


def _write(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Append rows and absorb them into the index. Call with the workspace lock held."""
    try:
        append_jsonl(path, rows)
    except BaseException:
        with _INDEX_GUARD:
            _INDEXES.pop(str(path), None)  # the file may hold part of the write: re-read it next time
        raise
    _current_index(path)


def _validated(event: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("each ledger event must be a mapping")
    rule, outcome, source = event.get("rule"), event.get("outcome"), event.get("source")
    if not isinstance(rule, str) or not rule.strip():
        raise ValueError("rule must be a non-empty string")
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {list(OUTCOMES)}, got {outcome!r}")
    if source not in SOURCES:
        raise ValueError(f"source must be one of {list(SOURCES)}, got {source!r}")
    for name in ("host", "session", "key"):
        value = event.get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{name} must be a string or None")
    row: Dict[str, Any] = {
        "v": LEDGER_VERSION,
        "rule": rule,
        "outcome": outcome,
        "source": source,
        "host": event.get("host"),
        "session": event.get("session"),
        "key": event.get("key") or None,
    }
    weight = event.get("weight")
    if weight is not None:
        if isinstance(weight, bool) or not isinstance(weight, (int, float, Decimal)):
            raise ValueError(f"weight must be a number, got {type(weight).__name__}")
        if not math.isfinite(float(weight)) or not 0 <= weight <= 1:
            raise ValueError(f"weight must be between 0 and 1, got {weight}")
        if weight != 1:
            row["weight"] = float(weight)
    meta = event.get("meta")
    if meta is not None:
        if not isinstance(meta, dict):
            raise ValueError("meta must be a mapping or None")
        try:
            json.dumps(meta, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("meta must be JSON serializable") from exc
        if meta:
            row["meta"] = meta
    return row


def append(workspace: Any, events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Append outcome events; return the row for each event, in order.

    An event is ``{"rule", "outcome", "source"}`` plus optional ``host``, ``session``,
    ``key``, ``weight`` (0..1) and ``meta``. Every event is validated before anything
    is written. An event whose ``(key, rule)`` is already in the ledger writes nothing
    and returns the stored row; with a different payload it raises EventConflictError
    and the call writes nothing.
    """
    if isinstance(events, (str, bytes, dict)):
        raise ValueError("events must be an iterable of mappings")
    planned = [_validated(e) for e in events]
    if not planned:
        return []
    with ledger_locked(workspace) as site:
        path = site.path
        index = _current_index(path)
        seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        new_rows: List[Dict[str, Any]] = []
        seq = index.last_seq
        stamp = _utc_now()
        for row in planned:
            identity = (row["key"], row["rule"]) if row["key"] else None
            existing = None
            if identity is not None:
                existing = seen.get(identity) or index.keyed.get(identity)
            if existing is not None:
                if _payload_digest(existing) != _payload_digest(row):
                    raise EventConflictError(
                        f"key {row['key']!r} is already recorded for rule {row['rule']!r} with a different payload"
                    )
                results.append(existing)
                continue
            seq += 1
            written = {"v": LEDGER_VERSION, "seq": seq, "ts": stamp, **{k: v for k, v in row.items() if k != "v"}}
            if site.worktree is not None:
                written["worktree"] = site.worktree
            new_rows.append(written)
            results.append(written)
            if identity is not None:
                seen[identity] = written
        if new_rows:
            _write(path, new_rows)
        return results


def append_epoch(workspace: Any, note: Dict[str, Any]) -> Dict[str, Any]:
    """Append an epoch row (no rule, no outcome) recording a migration; return it."""
    if not isinstance(note, dict):
        raise ValueError("note must be a mapping")
    with ledger_locked(workspace) as site:
        path = site.path
        index = _current_index(path)
        row = {"v": LEDGER_VERSION, "seq": index.last_seq + 1, "ts": _utc_now(), "epoch": note}
        if site.worktree is not None:
            row["worktree"] = site.worktree
        _write(path, [row])
        return row


def append_rows(workspace: Any, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Append already-formed v2 outcome rows (``aegis migrate``), renumbering their seq.

    Rows whose ``(key, rule)`` is already in the ledger are skipped, so a re-run adds
    nothing. Returns the rows written.
    """
    with ledger_locked(workspace) as site:
        path = site.path
        index = _current_index(path)
        seq = index.last_seq
        seen = set(index.keyed)
        new_rows = []
        for row in rows:
            key = row.get("key")
            identity = (key, row.get("rule")) if isinstance(key, str) and key else None
            if identity is not None and identity in seen:
                continue
            seq += 1
            written = {"v": LEDGER_VERSION, "seq": seq, **{k: v for k, v in row.items() if k not in ("v", "seq")}}
            if site.worktree is not None and "worktree" not in written:
                written["worktree"] = site.worktree
            new_rows.append(written)
            if identity is not None:
                seen.add(identity)
        if new_rows:
            _write(path, new_rows)
        return new_rows


# ── Merging the ledgers of several worktrees (v4.2 #7) ───────────────────────

def _identity(row: Mapping[str, Any]) -> Optional[Tuple[str, Any]]:
    key = row.get("key")
    return (key, row.get("rule")) if isinstance(key, str) and key else None


def _canonical(row: Mapping[str, Any]) -> str:
    """A row as one string, equal for two rows that differ only in ``seq`` (the merge
    renumbers it) or in a field one has with no value and the other lacks."""
    fields = {k: v for k, v in row.items() if k != "seq" and v is not None and v != ""}
    return json.dumps(fields, sort_keys=True, ensure_ascii=True, default=str)


def _order(row: Mapping[str, Any]) -> Tuple[str, str, int]:
    ts, worktree, seq = row.get("ts"), row.get("worktree"), row.get("seq")
    return (
        ts if isinstance(ts, str) else "",
        worktree if isinstance(worktree, str) else "",
        seq if type(seq) is int else 0,
    )


def plan_merge(
    existing: Iterable[Dict[str, Any]], sources: Sequence[Sequence[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], int]:
    """``plan_merge_report`` without the conflict count: ``(rows to add, duplicates)``."""
    added, duplicates, _conflicts = plan_merge_report(existing, sources)
    return added, duplicates


def plan_merge_report(
    existing: Iterable[Dict[str, Any]], sources: Sequence[Sequence[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], int, int]:
    """Which rows of ``sources`` (normalized v2 outcome rows, one list per per-worktree
    ledger) the ledger holding ``existing`` lacks, in the order they are to be appended,
    and how many it already has (``(rows to add, duplicates, conflicts)``). A conflict is a
    keyed row whose ``(key, rule)`` is already held with a DIFFERENT payload: the live
    ``append`` raises ``EventConflictError`` for it, so the merge keeps the first row (the
    earliest, or the one ``existing`` has), does not add the other, and counts it here, not
    as a duplicate.

    - A keyed row is the same row as any other with its ``(key, rule)``: the earliest by
      ``(ts, worktree, seq)`` is kept, and none that ``existing`` has.
    - A keyless row is the same as any other with the same canonical row, that is every
      field but ``seq``. Identical rows that ONE source holds several times are separate
      events (two triggers in one second), so the shared ledger ends with as many copies
      as the source with most has, not fewer: only a copy in another source, or of what
      ``existing`` holds, is dropped. A re-run therefore adds nothing.
    - What is added is sorted by ``(ts, worktree, seq)``, a missing or unusable field
      sorting first; rows equal on all three keep their source order.
    """
    existing_keys: Dict[Tuple[str, Any], str] = {}
    existing_copies: Counter = Counter()
    for row in existing:
        identity = _identity(row)
        if identity is not None:
            existing_keys.setdefault(identity, _payload_digest(row))
        else:
            existing_copies[_canonical(row)] += 1

    ordered: List[Tuple[Tuple[str, str, int], int, int, Dict[str, Any]]] = []
    most_in_a_source: Counter = Counter()
    for source_index, rows in enumerate(sources):
        in_this_source: Counter = Counter()
        for position, row in enumerate(rows):
            ordered.append((_order(row), source_index, position, row))
            if _identity(row) is None:
                in_this_source[_canonical(row)] += 1
        for canonical, count in in_this_source.items():
            most_in_a_source[canonical] = max(most_in_a_source[canonical], count)
    to_add = {canonical: count - existing_copies[canonical]
              for canonical, count in most_in_a_source.items() if count > existing_copies[canonical]}

    ordered.sort(key=lambda entry: entry[:3])
    added: List[Dict[str, Any]] = []
    duplicates = 0
    conflicts = 0
    seen = dict(existing_keys)
    for _sort_key, _source, _position, row in ordered:
        identity = _identity(row)
        if identity is not None:
            if identity in seen:
                if seen[identity] == _payload_digest(row):
                    duplicates += 1
                else:
                    conflicts += 1
                continue
            seen[identity] = _payload_digest(row)
            added.append(row)
            continue
        canonical = _canonical(row)
        if to_add.get(canonical, 0) > 0:
            to_add[canonical] -= 1
            added.append(row)
        else:
            duplicates += 1
    return added, duplicates, conflicts


def merge_rows(
    workspace: Any, sources: Sequence[Sequence[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], int]:
    """``merge_rows_report`` without the conflict count: ``(rows written, duplicates)``."""
    written, duplicates, _conflicts = merge_rows_report(workspace, sources)
    return written, duplicates


def merge_rows_report(
    workspace: Any, sources: Sequence[Sequence[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], int, int]:
    """Append to ``workspace``'s ledger the rows of ``sources`` it lacks (``plan_merge``),
    renumbering ``seq`` after the rows already there; ``(rows written, duplicates, conflicts)``.

    The ledger is read and written under one hold of the ledger lock, so two merges at
    once, or a merge and a writer, never add a row twice. Each row keeps the ``worktree``
    it has; one without gets the asking worktree's, as ``append_rows`` stamps it.
    """
    with ledger_locked(workspace) as site:
        existing, _unusable = normalize_rows(read_jsonl(site.path).rows)
        added, duplicates, conflicts = plan_merge_report(existing, sources)
        return (append_rows(workspace, added) if added else []), duplicates, conflicts
