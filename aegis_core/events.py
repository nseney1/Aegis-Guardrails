"""The events log: what the v4.1/v4.2 prune metrics count (v4.1 spec §1, "Events log").

One row per event in ``<shared_state_dir>/events.jsonl`` (``<git common dir>/aegis``,
shared by every worktree of a repository; ``.aegis/state`` outside git), appended under
its own lock ``events.lock``::

    {"v": 1, "ts": "2026-10-16T12:00:00Z", "event": "lease_denied",
     "worktree": "/path/to/worktree", "host": "claude-code", "result": "refused",
     "detail": {"reason": "overlap"}}

- ``event`` is one of KINDS; an unknown kind is refused at append.
- ``worktree`` is the top of the work tree the event came from (the workspace itself
  outside git), in POSIX spelling. ``host`` is present only when given.
- Readers accept versions N and N-1 (ADR 0005 AD-5) and skip, and count, torn lines,
  rows of another version and malformed rows; they never raise for content.

Fitness and scan compliance never read this log, and it never touches ``ledger.jsonl``
or ``activity.jsonl``. Rows written on a CI runner are lost with it unless uploaded.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from aegis_core import gitsafe
from aegis_core.errors import PathTraversalError
from aegis_core.primitives import parse_utc, utc_stamp
from aegis_core.storage import append_jsonl, read_jsonl, shared_locked, shared_state_dir

__all__ = [
    "EVENTS_FILE",
    "EVENTS_LOCK",
    "EVENTS_VERSION",
    "KINDS",
    "EventsRead",
    "append",
    "events_path",
    "read",
]

EVENTS_VERSION = 1
EVENTS_FILE = "events.jsonl"
EVENTS_LOCK = "events.lock"
KINDS = (
    "lease_claimed",
    "lease_denied",
    "lane_check",
    "scan_gate",
    "guard_match",
    "skills_sync",
    "partition_check",
    "pack_import",
    "init_host",
    "benchmark",
    "baseline_written",
    "baseline_check",
    "package",
)


def _kind(kind: object) -> str:
    if not isinstance(kind, str) or kind not in KINDS:
        raise ValueError(f"event kind must be one of {list(KINDS)}, got {kind!r}")
    return kind


def _readable_versions() -> Tuple[int, ...]:
    # N and N-1 where N-1 exists; read at call time so a version bump is one constant.
    return tuple(v for v in (EVENTS_VERSION, EVENTS_VERSION - 1) if v >= 1)


def events_path(workspace: Any, create: bool = False) -> Path:
    """Where the events log of ``workspace`` lives; nothing is created unless ``create``.
    Raises PathTraversalError when the shared state dir is not confined."""
    return shared_state_dir(workspace, create=create) / EVENTS_FILE


def _worktree(root: Path) -> str:
    top = gitsafe.toplevel(root)
    return (top if top is not None else root).as_posix()


def append(
    workspace: Any,
    kind: str,
    result: str,
    detail: Dict[str, Any],
    host: Optional[str] = None,
) -> Dict[str, Any]:
    """Append one event row under ``events.lock`` and return it.

    Raises ValueError for an unknown ``kind``, an empty or non-string ``result`` or
    ``host``, or a ``detail`` that is not a dict; ValueError/TypeError when ``detail``
    is not JSON serializable (nothing is written then); PathTraversalError when the
    shared state dir is not confined; OSError when it cannot be created, listed or
    written; LockOrderError when called while this thread holds another shared lock;
    LockTimeoutError when the lock stays held. Callers that must not fail on a metric
    catch these.
    """
    _kind(kind)
    if not isinstance(result, str) or not result:
        raise ValueError("result must be a non-empty string")
    if not isinstance(detail, dict):
        raise ValueError("detail must be a JSON object (a dict)")
    if host is not None and (not isinstance(host, str) or not host):
        raise ValueError("host must be a non-empty string when given")
    root = Path(os.fspath(workspace)).resolve()
    # The worktree and the shared state dir are one git question: ask it once (the pre-tool
    # hook appends a row on every edit, and a process start is what Windows makes slowest).
    with gitsafe.memo():
        row: Dict[str, Any] = {
            "v": EVENTS_VERSION,
            "ts": utc_stamp(),
            "event": kind,
            "worktree": _worktree(root),
        }
        if host is not None:
            row["host"] = host
        row["result"] = result
        row["detail"] = detail
        with shared_locked(root, EVENTS_LOCK) as lock:
            append_jsonl(lock.parent / EVENTS_FILE, [row])
    return row


@dataclass(frozen=True)
class EventsRead:
    """The usable rows of the events log, in file order, and what was skipped.

    ``skipped``: complete lines that are not a JSON object (a row torn by a crash,
    terminated by the next append). ``torn_tail``: the last line is incomplete.
    ``unknown_version``: rows whose ``v`` is neither N nor N-1. ``malformed``: rows of a
    readable version with an unknown kind or a missing or mistyped field. ``error``:
    the log could not be read (a confinement refusal, an unreadable file).
    """

    rows: List[Dict[str, Any]]
    skipped: int = 0
    torn_tail: bool = False
    unknown_version: int = 0
    malformed: int = 0
    error: Optional[str] = None


def _is_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _usable(row: Dict[str, Any]) -> bool:
    return (
        parse_utc(row.get("ts")) is not None
        and row.get("event") in KINDS
        and _is_text(row.get("worktree"))
        and _is_text(row.get("result"))
        and isinstance(row.get("detail"), dict)
        and ("host" not in row or _is_text(row["host"]))
    )


def read(workspace: Any, kinds: Union[str, Iterable[str], None] = None) -> EventsRead:
    """The events of ``workspace``'s log, optionally only those of ``kinds`` (one kind or
    an iterable). Creates nothing and never raises for the log's content or an
    unreadable log or shared dir (``error`` says why); ValueError for an unknown kind
    in ``kinds``."""
    wanted = None
    if kinds is not None:
        wanted = {_kind(k) for k in ([kinds] if isinstance(kinds, str) else kinds)}
    try:
        path = events_path(workspace)
    except PathTraversalError as exc:
        return EventsRead([], error=str(exc))
    except OSError as exc:  # the shared dir cannot be listed for its confinement check
        return EventsRead([], error=f"cannot read {exc.filename or 'the shared state dir'}: {exc.strerror or exc}")
    found = read_jsonl(path)
    readable = _readable_versions()
    rows: List[Dict[str, Any]] = []
    unknown_version = malformed = 0
    for row in found.rows:
        version = row.get("v")
        if type(version) is not int or version not in readable:  # True == 1, but is no version
            unknown_version += 1
        elif not _usable(row):
            malformed += 1
        elif wanted is None or row["event"] in wanted:
            rows.append(row)
    return EventsRead(
        rows,
        skipped=found.skipped,
        torn_tail=found.torn_tail,
        unknown_version=unknown_version,
        malformed=malformed,
        error=found.error,
    )
