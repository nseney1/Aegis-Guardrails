"""Immutable merge queue data contracts and owner-authenticated storage port.

Validation and scheduling remain in merge_queue; these records grant no authority
by themselves. Admission-bearing review fields must be supplied explicitly.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Review", "QueueEntry", "Landing", "HostedResult", "IssuedRecord",
           "Completion", "QueueState", "QueueStorage"]


@dataclass(frozen=True)
class Review:
    session: str
    commit: str
    tree: str
    verdict: str
    helpers_off: bool


@dataclass(frozen=True)
class QueueEntry:
    lane: str
    author: str
    head: str
    reviews: tuple
    parents: tuple = ()
    repair: bool = False
    deadline: int = None


@dataclass(frozen=True)
class Landing:
    status: str
    lane: str = None
    tip: str = None
    commit: str = None
    tree: str = None
    missing_legs: tuple = ()
    issuance: int = 0


@dataclass(frozen=True)
class HostedResult:
    """Authenticated target result; attempt is the adapter's monotonic run revision."""
    commit: str
    passed: bool
    attempt: int = 0


@dataclass(frozen=True)
class IssuedRecord:
    entry: QueueEntry
    landing: Landing
    result: HostedResult = None
    resolution: str = None
    ref: str = None
    expected: str = None


@dataclass(frozen=True)
class Completion:
    target: str
    entry: QueueEntry
    landing: Landing
    result: HostedResult = None


@dataclass(frozen=True)
class QueueState:
    target: str
    required_legs: tuple
    entry_legs: tuple
    entries: tuple = ()
    issued: IssuedRecord = None
    results: tuple = ()
    health_commit: str = None
    health_result: HostedResult = None
    health_order: int = 0
    red: bool = False
    red_order: int = 0
    green_order: int = 0
    serial: int = 0
    generation: int = 0
    reconciliation_required: bool = False
    cleanup: IssuedRecord = None


@dataclass(frozen=True)
class QueueStorage:
    """Owner-only, repository-bound durable port; never constructed from model input.

    load(target) returns authenticated QueueState or None. save(target, generation,
    state, completion) atomically settles checkpoint/archive/journal: True after
    durability, False on lost CAS; lost replies raise. Never retry blindly.
    lane(target, lane)/commit(target, oid) read immutable indexed Completions.
    Native adapters bound bytes BEFORE decoding and own descriptor/root custody.
    begin(target, generation, observation, recovering) journals before writes;
    lookup failures retain inputs too. health(target, oid) is revision-keyed:
    RED wins equal attempts; only newer same-oid GREEN clears it. No save erases it.
    Even lost-CAS observations replay into health/effect records/pending rows;
    unsettled load marks reconciliation_required, including above admission limits.
    Pin intents name exact refs. Recovery never treats an unavailable journal as
    empty and requires a marked checkpoint before replacing unsettled intent.
    """
    load: object
    save: object
    lane: object
    commit: object
    begin: object
    health: object
