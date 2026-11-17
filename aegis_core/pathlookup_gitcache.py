"""Ordinary-Git cache policy, independent of the path-walk implementation.

The lookup facade supplies fence discovery and program provenance callbacks. Cache
hits are revalidated outside the store lock; each call captures its bound root.
"""
from __future__ import annotations

from contextvars import ContextVar
import threading
from typing import Optional

from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_insight_text

__all__ = ["GitCache", "ordinary_root"]


class _RootCache:
    """``store`` with each key prefixed by the fence captured for this call."""

    __slots__ = ("_store", "fence")

    def __init__(self, store, fence: Optional[str]) -> None:
        self._store = store
        self.fence = fence

    def get(self, key, default=None):
        with self._store._lock:
            found = self._store.get((self.fence, key), default)
        # Revalidate outside the lock: a walk must not run while the lock is held.
        if found and self.fence is not None and self._store._inside_program(found, self.fence):
            return default
        return found

    def __setitem__(self, key, value) -> None:
        with self._store._lock:
            self._store[(self.fence, key)] = value

    def clear(self) -> None:
        """Drop this fence's partition. ``GitCache.clear`` still drops every fence."""
        with self._store._lock:
            fence = self.fence
            keys = [key for key in self._store if isinstance(key, tuple) and key[:1] == (fence,)]
            for key in keys:
                self._store.pop(key, None)

    def error(self, error):
        """Keep the ordinary refusal type/code and name its enclosing fence safely."""
        def refuse(message, **details):
            canonical = sanitize_display(self.fence, max_len=None)
            redacted = redact_insight_text(canonical, max_len=max(1, len(canonical)))
            shown = sanitize_display(redacted, max_len=256)
            return error(message + "; excluding enclosing checkout " + shown, **details)
        return refuse


class _FenceCacheStore(dict):
    """One reentrant lock for cache operations; iterators are stable snapshots."""

    def __init__(self, *args, **kwargs):
        self._lock = threading.RLock()
        super().__init__(*args, **kwargs)

    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)

    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, value)

    def __delitem__(self, key):
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key):
        with self._lock:
            return super().__contains__(key)

    def __len__(self):
        with self._lock:
            return super().__len__()

    def __iter__(self):
        with self._lock:
            return iter(tuple(super().keys()))

    def get(self, key, default=None):
        with self._lock:
            return super().get(key, default)

    def pop(self, key, *default):
        with self._lock:
            return super().pop(key, *default)

    def popitem(self):
        with self._lock:
            return super().popitem()

    def setdefault(self, key, default=None):
        with self._lock:
            return super().setdefault(key, default)

    def clear(self):
        with self._lock:
            super().clear()

    def copy(self):
        with self._lock:
            return super().copy()

    def keys(self):
        with self._lock:
            return tuple(super().keys())

    def items(self):
        with self._lock:
            return tuple(super().items())

    def values(self):
        with self._lock:
            return tuple(super().values())

    def update(self, *args, **kwargs):
        if len(args) == 1 and isinstance(args[0], _FenceCacheStore):
            incoming = args[0].copy()
            incoming.update(kwargs)
        else:
            incoming = dict(*args, **kwargs)
        with self._lock:
            super().update(incoming)

    def __ior__(self, other):
        self.update(other)
        return self


# Only invocation adapters set this, using a canonical root from completed binding.
ordinary_root = ContextVar("aegis_gitsafe_ordinary_root", default=None)


class GitCache(_FenceCacheStore):
    """Ordinary executable cache partitioned by each call's discovered workspace."""

    def __init__(self, fence_for_cwd, inside_program, /, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fence_for_cwd = fence_for_cwd
        self._inside_program = inside_program

    def for_cwd(self, cwd=None) -> _RootCache:
        # Bound root when this invocation set one; else the metadata outermost marker.
        return _RootCache(self, ordinary_root.get() or self._fence_for_cwd(cwd))
