"""Process-local receipts for guidance returned to a live MCP session."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from hashlib import blake2s
import re
from threading import RLock
from typing import Callable, Dict, List, Optional, Tuple
from uuid import uuid4

from aegis_core.guidance_projection import ScanExposure

__all__ = ["Receipt", "capture", "commit", "discard", "offer", "resolve", "retire", "stdio", "valid_ref"]

_MAX_SCOPES = 256
_MAX_RECEIPTS = 16
_HISTORY_BITS = 1 << 19
_ScopeKey = Tuple[str, str, str]


@dataclass
class _Scope:
    receipts: Dict[str, ScanExposure] = field(default_factory=dict)
    pending: Dict[Optional[str], Tuple[Optional[ScanExposure], int]] = field(default_factory=dict)
    ambiguous: bool = False
    protected: bool = False


@dataclass(frozen=True)
class Receipt:
    key: _ScopeKey
    scope: Optional[_Scope]
    reference: Optional[str]
    snapshot: Optional[ScanExposure]
    protected: bool
    reserved: bool
    delivered: Optional[Callable[[], None]] = None


_SCOPES: Dict[_ScopeKey, _Scope] = {}
# A bounded Bloom filter remembers evicted standalone scopes. False positives
# only withhold implicit attribution; no old reference or snapshot is retained.
_EVICTED = bytearray(_HISTORY_BITS // 8)
_LOCK = RLock()
_CAPTURE: ContextVar[Optional[List[Receipt]]] = ContextVar("scan_receipt_capture", default=None)
stdio: ContextVar[bool] = ContextVar("scan_receipt_stdio", default=False)


@contextmanager
def capture():
    pending: List[Receipt] = []
    reset = _CAPTURE.set(pending)
    try:
        yield pending
    except BaseException:
        for receipt in pending:
            discard(receipt)
        raise
    finally:
        _CAPTURE.reset(reset)


def valid_ref(value: object) -> bool:
    return isinstance(value, str) and len(value) == 32 and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _eviction_bits(key: _ScopeKey):
    digest = blake2s(repr(key).encode("utf-8", "surrogatepass"), digest_size=12).digest()
    for offset in range(0, len(digest), 3):
        index = int.from_bytes(digest[offset:offset + 3], "big") % _HISTORY_BITS
        yield index // 8, 1 << (index % 8)


def _remember_eviction(key: _ScopeKey) -> None:
    for byte, bit in _eviction_bits(key):
        _EVICTED[byte] |= bit


def _new_scope(key: _ScopeKey) -> Optional[_Scope]:
    if len(_SCOPES) >= _MAX_SCOPES:
        old = next((saved for saved, scope in _SCOPES.items() if not (scope.pending or scope.protected)), None)
        if old is None:
            return None
        _remember_eviction(old)
        del _SCOPES[old]
    ambiguous = all(_EVICTED[byte] & bit for byte, bit in _eviction_bits(key))
    scope = _SCOPES[key] = _Scope(ambiguous=ambiguous)
    return scope


def offer(root: str, host: str, session: str, snapshot: Optional[ScanExposure], *,
          delivered: Optional[Callable[[], None]] = None) -> None:
    """Stage a full response, or attest a direct tool result being returned."""
    if not session:
        return
    key = (root, host, session)
    pending = _CAPTURE.get()
    with _LOCK:
        scope = _SCOPES.get(key) or _new_scope(key)
        reference = None
        if scope is not None and snapshot is not None:
            reference = next((ref for ref, saved in scope.receipts.items() if saved == snapshot), None)
            if reference is None:
                reference = next((ref for ref, (saved, _) in scope.pending.items() if saved == snapshot), None)
            reference = reference or uuid4().hex
        reserved = scope is not None and (reference in scope.pending or len(scope.pending) < _MAX_RECEIPTS)
        if reserved:
            count = scope.pending.get(reference, (None, 0))[1]
            scope.pending[reference] = (snapshot, count + 1)
        else:
            reference, snapshot = None, None
    receipt = Receipt(key, scope, reference, snapshot, protected=pending is not None, reserved=reserved, delivered=delivered)
    if pending is None:
        commit(receipt)
    else:
        pending.append(receipt)


def commit(receipt: Receipt) -> None:
    """Publish only after the caller returns or the transport flushes its frame."""
    _commit_receipt(receipt)
    if receipt.delivered is not None:
        receipt.delivered()


def _commit_receipt(receipt: Receipt) -> None:
    with _LOCK:
        scope = _SCOPES.get(receipt.key)
        if not receipt.reserved:
            if scope is None:
                _remember_eviction(receipt.key)
            elif receipt.scope is None or scope is receipt.scope:
                scope.ambiguous = True
            return
        if scope is None or scope is not receipt.scope or receipt.reference not in scope.pending:
            return
        scope.protected |= receipt.protected
        if receipt.reference is None or receipt.snapshot is None:
            scope.ambiguous = True
        elif receipt.reference not in scope.receipts:
            previous = next(reversed(scope.receipts.values()), None)
            if previous is not None and (
                previous.paths != receipt.snapshot.paths or previous.rules != receipt.snapshot.rules
                or previous.attribution_digest != receipt.snapshot.attribution_digest
            ):
                scope.ambiguous = True
            if len(scope.receipts) >= _MAX_RECEIPTS:
                scope.receipts.pop(next(iter(scope.receipts)))
            scope.receipts[receipt.reference] = receipt.snapshot
        discard(receipt)


def discard(receipt: Receipt) -> None:
    if not receipt.reserved:
        return
    with _LOCK:
        scope = _SCOPES.get(receipt.key)
        if scope is None or scope is not receipt.scope or receipt.reference not in scope.pending:
            return
        snapshot, count = scope.pending[receipt.reference]
        if count == 1:
            del scope.pending[receipt.reference]
        else:
            scope.pending[receipt.reference] = (snapshot, count - 1)
        if not (scope.pending or scope.receipts or scope.ambiguous):
            del _SCOPES[receipt.key]


def resolve(root: str, host: str, session: str, reference: Optional[str]) -> Optional[Tuple[str, ScanExposure]]:
    with _LOCK:
        scope = _SCOPES.get((root, host, session))
        if scope is None:
            return None
        if reference is None:
            if scope.ambiguous or not scope.receipts:
                return None
            return next(reversed(scope.receipts.items()))
        snapshot = scope.receipts.get(reference)
        return (reference, snapshot) if snapshot is not None else None


def retire(session: Optional[str]) -> None:
    with _LOCK:
        for key in tuple(_SCOPES):
            if key[2] == session:
                del _SCOPES[key]
