"""Adjudication labels merged at a reviewed BASE, for tests (R-evidence-3).

`aegis rule adjudicate` writes ``.aegis/adjudications/<rule-id>.jsonl``; a label counts only as
git content at the T3 BASE (the merge-base of HEAD and origin/HEAD). ``merge_to_base`` commits
the working tree and points ``origin/main`` and ``origin/HEAD`` at that commit, as a reviewed
merge would leave a clone: real git, no remote, a throwaway HOME. Call it before writing ledger
rows: once the directory is a repository the ledger lives in the git common dir.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from tests import helpers_humangate as hg

ADJUDICATIONS = Path(".aegis") / "adjudications"


def labels(rule_id: str, verdict: str = "tp", count: int = 25, *, sessions: int = 3, repos: int = 2,
           start: int = 0, **fields: Any) -> List[Dict[str, Any]]:
    """``count`` distinct labels spread over ``sessions`` sessions, ``repos`` repos and 30 days."""
    return [
        dict({"example_id": f"{rule_id}-{verdict}-{n}", "verdict": verdict, "session": f"sess-{n % sessions}",
              "repo": f"repo-{n % repos}", "ts": f"2026-09-{1 + n % 30:02d}T00:00:00Z"}, **fields)
        for n in range(start, start + count)
    ]


def write_labels(root: Path, rule_id: str, rows: Iterable[Dict[str, Any]]) -> Path:
    """Append ``rows`` to the rule's label file in the working tree (bytes: LF on every OS)."""
    path = Path(root) / ADJUDICATIONS / f"{rule_id}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as fh:
        fh.write(b"".join(json.dumps(row).encode("utf-8") + b"\n" for row in rows))
    return path


def _git(root: Path, *args: str) -> str:
    env = hg.Home(root.parent / f"{root.name}-git-home").env
    return hg.git(root, "-c", "user.email=dev@example.com", "-c", "user.name=Dev", "-c", "commit.gpgsign=false",
                  *args, env=env)


def merge_to_base(root: Path, message: str = "chore: merge adjudication labels") -> str:
    """Commit the working tree (initialising a repository on ``main`` when needed) and make that
    commit the reviewed base; returns its id."""
    root = Path(root)
    if not (root / ".git").exists():
        _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "--allow-empty", "-m", message)
    head = _git(root, "rev-parse", "HEAD")
    _git(root, "update-ref", "refs/remotes/origin/main", head)
    _git(root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    return head


def commit_on_branch(root: Path, branch: str, message: str = "wip") -> str:
    """Commit the working tree on a new ``branch`` that the base does not contain."""
    root = Path(root)
    _git(root, "checkout", "-q", "-b", branch)
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "--allow-empty", "-m", message)
    return _git(root, "rev-parse", "HEAD")
