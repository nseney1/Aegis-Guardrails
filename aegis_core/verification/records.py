"""Dispositions and outcomes of logged Layer 2 predictions, computed by Aegis from git on read (spec T6:
"Aegis, not the LLM, records the disposition"). Nothing is written: git is the registry, as in T5.

The spec names the vocabulary, not its tests, so this is an inference (w08 8.9 U12):
``landed_unchanged`` when a commit of the protected branch carries the reviewed tree; ``heeded`` when
none does but one changed the prediction's path within its window after the review (the advice changed
the code); ``abandoned`` otherwise (never scored). ``overridden`` has no producer. An outcome resolves
only once the window after the landing commit has closed: ``hit`` when a commit in it reverted
(``Revert "...``) or fixed (a Conventional ``fix`` subject) the path, ``miss`` when none did, ``void``
for any other observable, a missing path, a shallow clone or any git failure. Never a guess.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_core import credit, gitevidence, gitsafe

DAY_S = 86400.0
MAX_ROWS = 500  # the newest logged rows resolved per read, at most 3 git calls each
_FIX = re.compile(r"fix(?:\([^)]*\))?!?:", re.IGNORECASE)
_REVERT = re.compile(r'Revert "')
_OID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def _path(row: Mapping[str, Any]) -> str:
    scope = row.get("scope")
    path = scope.get("path") if isinstance(scope, Mapping) else None
    return path if isinstance(path, str) and path and not path.startswith("-") else ""


def _window(row: Mapping[str, Any]) -> float:
    days = row.get("window_days")
    return float(days if isinstance(days, int) and not isinstance(days, bool) and days > 0 else 14) * DAY_S


def _changes(top: Any, tip: str, path: str, after: Optional[str] = None) -> Optional[List[Tuple[float, str]]]:
    """(commit time, subject) of each commit reachable from ``tip`` (and not from ``after``) that changed
    ``path``; None when git cannot answer. Only object ids reach git's revision arguments."""
    args = ["log", "--format=%ct%x00%s", tip] + (["--not", after] if after else []) + ["--", path]
    res = gitsafe.run(args, top)
    if res.returncode != 0:
        return None
    found = []
    for line in res.stdout.decode("utf-8", "replace").splitlines():
        stamp, _, subject = line.partition("\0")
        if stamp.isdigit():
            found.append((float(stamp), subject))
    return found


def disposition(row: Mapping[str, Any], top: Any, tip: Optional[str], landed: Callable[[str], Optional[str]]) -> str:
    """``landed_unchanged``, ``heeded`` or ``abandoned`` for one logged row (see the module docstring)."""
    tree = row.get("tree")
    if isinstance(tree, str) and tree and landed(tree):
        return "landed_unchanged"
    path, ts = _path(row), row.get("ts")
    if path and tip and isinstance(ts, (int, float)):
        changes = _changes(top, tip, path) or ()
        if any(ts <= when <= ts + _window(row) for when, _subject in changes):
            return "heeded"
    return "abandoned"


def resolve(row: Mapping[str, Any], now: float, top: Any, tip: Optional[str], commit: Optional[str],
            shallow: bool = False) -> Optional[str]:
    """``hit``, ``miss`` or ``void`` for a row whose reviewed tree landed as ``commit``; None while the
    window after it is open. Never raises and never guesses a hit."""
    observable = row.get("observable")
    kind = observable.get("kind") if isinstance(observable, Mapping) else None
    path = _path(row)
    if kind not in ("revert", "fix_attributed") or not path or shallow or not tip or not commit \
            or not _OID.fullmatch(commit) or not _OID.fullmatch(tip):
        return "void"
    try:
        res = gitsafe.run(["log", "-1", "--format=%ct", commit], top)
        landed_at = float(res.stdout.decode("ascii", "replace").strip()) if res.returncode == 0 else None
        if landed_at is None:
            return "void"
        end = landed_at + _window(row)
        if now < end:
            return None
        changes = _changes(top, tip, path, after=commit)
    except (gitsafe.GitError, ValueError, OSError):
        return "void"
    if changes is None:
        return "void"
    pattern = _REVERT if kind == "revert" else _FIX
    return "hit" if any(landed_at <= when <= end and pattern.match(subject) for when, subject in changes) else "miss"


def resolve_rows(root: Any, rows: Sequence[Mapping[str, Any]], now: float) -> List[Dict[str, Any]]:
    """``rows`` with the disposition and outcome of the newest ``MAX_ROWS`` still-logged ones computed from
    git; rows that already carry a resolution, and any row git cannot place, are returned as they are."""
    out = [dict(row) for row in rows]
    facts = gitevidence.repo_facts(root)
    if facts is None or facts.top is None:
        return out
    tips = gitevidence.branch_tips(facts, gitevidence.protected_branch(facts) or "")
    tip = tips[0] if tips else None
    landed = credit.landed_lookup(root)
    logged = [i for i, row in enumerate(out) if row.get("disposition") == "logged" and row.get("outcome") is None]
    newest = sorted(logged, key=lambda i: -float(out[i]["ts"]) if isinstance(out[i].get("ts"), (int, float)) else 0.0)
    for i in newest[:MAX_ROWS]:
        row = out[i]
        try:
            row["disposition"] = disposition(row, facts.top, tip, landed)
            if row["disposition"] == "landed_unchanged":
                row["outcome"] = resolve(row, now, facts.top, tip, landed(row["tree"]), bool(facts.shallow))
        except (gitsafe.GitError, OSError, ValueError, TypeError):
            row["disposition"], row["outcome"] = "logged", None
    return out
