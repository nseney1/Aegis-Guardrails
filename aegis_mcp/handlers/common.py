"""Workspace binding and shared MCP handler constants."""
from __future__ import annotations

from typing import Any, Optional

from aegis_core.workspace.base import Workspace
from aegis_core.workspace import resolve_workspace

__all__ = [
    "DEFAULT_CLIENT_PLATFORM", "NOT_GOVERNED_MESSAGE", "STATUS_FAIL", "VALID_OUTCOMES",
    "get_workspace", "remember_bounded",
]

STATUS_FAIL = "FAIL"
NOT_GOVERNED_MESSAGE = 'not an Aegis workspace: run "aegis init" in your repository'
# A client whose clientInfo names no known host: its ledger rows say "generic" and its
# scans get the generic slot table, never another vendor's (host-matrix §3.5).
DEFAULT_CLIENT_PLATFORM = "generic"
VALID_OUTCOMES = ("success", "partial", "failure", "tp", "fp", "pass", "fail")


def remember_bounded(store: dict, key: Any, value: Any, limit: int) -> None:
    """``store[key] = value`` as its newest entry, then drop the oldest while over ``limit``: a
    process-lifetime map of a long-lived server stays bounded, and a key in use is evicted last."""
    store.pop(key, None)
    store[key] = value
    while len(store) > limit:
        del store[next(iter(store))]


def get_workspace(args: Optional[dict] = None) -> Workspace:
    """The workspace a handler acts on.

    Over stdio the server always injects its own workspace; an in-process caller may
    pass one. Without either, resolve strictly from AEGIS_WORKSPACE or the cwd.
    """
    raw = args.get("workspace") if args else None
    if isinstance(raw, Workspace):
        return raw
    return Workspace.confine(raw or resolve_workspace(strict_env=True))
