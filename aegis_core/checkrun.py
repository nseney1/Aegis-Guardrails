"""``aegis check --record``: the hermetic snapshot run and the ledger ``check`` row (v4.3 spec §3 T1).

One run is bound to one tree (``aegis_core.treeid``). The files of that tree are exported to a
private snapshot and Layer 1 and, with ``tests=True``, the project's tests run *there*, so a file
swapped in the work tree mid-run, or an ignored file the tests quietly import, cannot change what
was verified. A tree holding any symbolic link is refused (``unbindable``, no row): a link can
point the run back at files outside the snapshot. What it records is a **label**: a same-uid
agent can write any row, so a ``check`` row is evidence only once CI on the landing commit
confirms it (``aegis_core.credit``).

The tests run through ``aegis_core.testexec``: the user-scope ``tests.command`` (never the
repository's), a fixed environment and a process-group timeout.

``exit 5`` (no tests collected) and ``passed == 0`` are never evidence, and neither is a run that
timed out or a Layer 1 finding.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aegis_core import primitives
from aegis_core import gitevidence, gitsafe, governance, testexec, treeid
from aegis_core.primitives import utc_stamp
from aegis_core.storage import ledger_locked, read_jsonl
from aegis_core.telemetry_engine import ledger

__all__ = [
    "CheckOutcome",
    "record",
    "rerun_commit_snapshot",
    "verify_commit_trailers",
]


@dataclass
class CheckOutcome:
    """``recorded`` (a row was written; ``row`` holds it), ``unbindable`` (no tree, no row) or
    ``error`` (nothing could be run or written)."""

    status: str
    row: Optional[Dict[str, Any]] = None
    reason: str = ""
    binding: Optional[treeid.TreeBinding] = None
    hint: str = ""


# ── The record ───────────────────────────────────────────────────────────────

def _layer1(snapshot: Path, changed: Sequence[str], git_root: Path, base: str) -> Dict[str, int]:
    from aegis_core import baseline

    # Every changed file, as plain check takes them: the secret scan reads any type.
    targets = [p for p in changed if (snapshot / p).is_file()]
    if not targets:
        return {"findings": 0, "files": 0}
    # The snapshot is a plain directory: git would answer for whatever repository encloses the temp dir,
    # so the snapshot's own rules are enforced (CI's check --ci guards their weakening).
    # git_root and base give the export its history, so the T7 delta judges it as aegis check does.
    pairs, _sources = baseline.run_fast(snapshot, targets, reviewed=False, git_root=os.fspath(git_root), diff_base=base)
    return {"findings": sum(1 for _path, evidence in pairs if not evidence.verdict), "files": len(targets)}


@gitsafe.scrubbed()
def record(root: object, *, tests: bool = False, base: Optional[str] = None, timeout: Optional[float] = None,
           now: Optional[datetime] = None) -> CheckOutcome:
    """Bind the work tree of ``root`` to a tree, run the checks on its snapshot, write one ``check``
    row to the ledger. See the module docstring for what the row is worth."""
    workspace = Path(os.fspath(root)).resolve()
    try:
        with treeid.bind(workspace) as bound:
            binding = bound.binding
            if not binding.bound:
                return CheckOutcome("unbindable", None, binding.reason, binding)
            links = sorted(bound.symlinks())
            if links:
                return CheckOutcome("unbindable", None, f"the tree holds symbolic links, which the snapshot refuses: "
                                    f"{treeid.named_paths(links)}", binding)
            top = bound.top
            head = gitsafe.head_commit(top)
            if not head:
                return CheckOutcome("error", None, "the repository has no commit yet", binding)
            base_ref = base or gitsafe.resolve_base_ref(top)
            if not base_ref:
                return CheckOutcome("error", None, "no base branch found (origin/$GITHUB_BASE_REF, the branch "
                                    "origin/HEAD names, main, develop or master); pass --base", binding)
            base_commit = gitsafe.merge_base(top, base_ref, "HEAD")
            if not base_commit:
                return CheckOutcome("error", None, f"HEAD shares no history with {base_ref}: fetch with "
                                    "fetch-depth 0", binding)
            entries = bound.diff_entries(base_commit)
            changed = [path for status, path in entries if status != "D"]
            protected = governance.touches_governance(changed, [path for status, path in entries if status == "D"])
            layer1, run, logical = _snapshot_check(workspace, bound.export, changed, tests, timeout, top, base_commit)
    except treeid.TreeError as exc:
        return CheckOutcome("error", None, str(exc))
    except gitsafe.GitError as exc:
        return CheckOutcome("error", None, str(exc))

    stamp = utc_stamp(now)  # a naive now is UTC
    layer1_ok = layer1["findings"] == 0
    tests_ok = run is None or run.evidence
    passed = layer1_ok and tests_ok
    exit_code = run.exit if run is not None else 0
    if exit_code == 0 and not layer1_ok:
        exit_code = 1
    digest = testexec.command_digest(logical) if tests else testexec.command_digest(["layer1"])
    row: Dict[str, Any] = {
        "v": ledger.LEDGER_VERSION, "ts": stamp, "event": "check", "witness": "aegis",
        **primitives.envelope("aegis check --record", {"tree": binding.tree, "base": base_commit}, checked_at=stamp),
        "tree": binding.tree, "head": head, "base": base_commit, "tree_algo": treeid.TREE_ALGO,
        "cmd_digest": digest, "layer1": layer1, "tests": run.as_dict() if run is not None else None,
        "env_class": testexec.env_class(), "protected_changed": bool(protected), "protected": protected,
        "partial": binding.status == "partial", "gitlinks": list(binding.gitlinks),
        "passed": passed, "exit": exit_code,
    }
    with ledger_locked(workspace):
        earlier = [r for r in read_jsonl(ledger.ledger_path(workspace)).rows
                   if r.get("event") == "check" and r.get("tree") == binding.tree and r.get("cmd_digest") == digest]
        row["run_ordinal"] = len(earlier) + 1
        # The ordinal keeps two runs of one tree in one second apart; the id is how reports name a check.
        identity = f"{binding.tree}|{digest}|{row['run_ordinal']}|{stamp}|{head}"
        row["id"] = hashlib.sha256(identity.encode("ascii")).hexdigest()[:16]
        ledger.append_rows(workspace, [row])
    hint = ""
    if run is not None and run.collected == 0 and run.pytest_missing:
        hint = ('set "tests.command" in ~/.aegis/config.json to your project\'s Python, for example '
                '["/path/to/.venv/bin/python", "-m", "pytest"]')
    return CheckOutcome("recorded", row, "", binding, hint)


def _snapshot_check(workspace: Path, export_fn: Any, changed: Sequence[str], tests: bool, timeout: Optional[float],
                    top: Path, base_commit: str) -> Tuple[Dict[str, int], Optional[testexec.TestsRun], List[str]]:
    """Export a tree with ``export_fn`` and run Layer 1 and, with ``tests``, the user's test command
    on it: the one recipe ``record`` and the trailer rerun share, so CI falsifies the same check."""
    scratch = Path(tempfile.mkdtemp(prefix="aegis-check-"))
    try:
        snapshot = scratch / "snapshot"
        export_fn(snapshot)
        layer1 = _layer1(snapshot, changed, top, base_commit)
        run: Optional[testexec.TestsRun] = None
        logical = list(testexec.DEFAULT_COMMAND)
        if tests:
            junit = scratch / "junit.xml"
            argv, logical = testexec.plan_command(testexec.user_test_command(workspace), junit)
            home = scratch / "home"
            tmp = scratch / "tmp"
            home.mkdir(mode=0o700)
            tmp.mkdir(mode=0o700)
            run = testexec.run_tests(argv, snapshot, testexec.hermetic_env(home, tmp),
                                     testexec.DEFAULT_TIMEOUT_S if timeout is None else timeout, junit,
                                     scratch / "output.txt")
        return layer1, run, logical
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


@gitsafe.scrubbed()
def rerun_commit_snapshot(
    root: object, commit: str, base_ref: str, *, timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Rerun ``record --tests`` on ``commit``'s tree: ``{"tree", "exit"}``, or ``{"tree",
    "inconclusive": True, "reason"}`` when git could not answer or the run timed out."""
    workspace = Path(os.fspath(root)).resolve()
    top = gitsafe.toplevel(workspace)
    commit = gitsafe.resolve_commit(top, commit) if top is not None else None  # only an oid reaches git argv
    if commit is None:
        return {"tree": "", "exit": 1}
    try:
        commit_tree = gitevidence.commit_tree(top, commit)
        if commit_tree is None:
            return {"tree": "", "inconclusive": True, "reason": f"could not read the tree of {commit[:12]}"}
        base_commit = gitsafe.merge_base(top, base_ref, commit)
        if not base_commit:
            return {"tree": "", "inconclusive": True, "reason": f"found no merge-base with {commit[:12]}"}
        changed = [p for s, _o, _n, p in gitsafe.diff_entries(top, base_commit, commit) if s != "D"]
        layer1, run, _logical = _snapshot_check(
            workspace, lambda dest: gitsafe.export_tree(top, commit, dest), changed, True, timeout, top, base_commit)
    except gitsafe.GitError as exc:
        return {"tree": "", "inconclusive": True, "reason": f"git could not answer: {exc}"}
    if run is not None and run.timed_out:
        return {"tree": commit_tree, "inconclusive": True, "reason": "timed out"}
    if layer1["findings"] == 0 and run is not None and run.evidence:
        return {"tree": commit_tree, "exit": 0}
    return {"tree": commit_tree, "exit": run.exit if run is not None and run.exit != 0 else 1}


@gitsafe.scrubbed()
def verify_commit_trailers(
    root: object, base: str, head: str = "HEAD", *,
    rerun_fn: Optional[ Any ] = None, timeout: Optional[float] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """Verify the ``Aegis-Check`` trailer of the head commit by rerunning its snapshot with the
    ``record --tests`` recipe (``testexec.DEFAULT_TIMEOUT_S`` unless ``timeout`` is given). ``progress`` gets one
    line before and one after each rerun (there are at most two)."""
    from aegis_core import credit

    runner = rerun_fn or (lambda c, _t: rerun_commit_snapshot(root, c, base, timeout=timeout))
    say, done = progress or (lambda _line: None), []  # type: Callable[[str], None], List[Mapping[str, Any]]

    def reported(commit: str, tree: str) -> Mapping[str, Any]:
        say(f"Aegis-Check rerun {len(done) + 1} of up to 2: tests.command on commit {commit[:10]} (the whole tree)")
        started = time.monotonic()
        done.append(runner(commit, tree))
        say(f"Aegis-Check rerun {len(done)} of up to 2: {done[-1].get('reason') or 'exit %s' % done[-1].get('exit')} "
            f"after {time.monotonic() - started:.1f}s")
        return done[-1]

    return credit.verify_commit_trailers(root, base, head, rerun_fn=reported)
