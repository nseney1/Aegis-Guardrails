"""The credit state machine (v4.3 spec §3 T1, T4): what a ``check`` row is worth, derived on read.

Only a passing ``check`` row that ran tests (``aegis check --record --tests``) is a witness: it is
what ``submit_report`` credits and what the commit hook writes a trailer for.

A credit is voided by a CI failure on its landing commit (a later CI success on the same commit
supersedes that) or by a terminal ``void`` row: a trailer divergence in ``check --ci``
(``ci_divergence``), a failed lane or test-integrity gate (``lane_integrity``, ``check --lane``) or
a revert of its landing commit on the protected branch (``reverted``, found by ``confirm``).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import gitevidence, gitsafe, human_gate
from aegis_core.errors import AegisError, PathTraversalError
from aegis_core.storage import ledger_locked, read_jsonl
from aegis_core.telemetry_engine import ledger

__all__ = [
    "EVENTS", "MAX_REPORT_ROWS_PER_SESSION", "CIUnavailable", "Credit", "CreditProjection",
    "GhRestClient", "ReportConflict", "approval_lookup", "check_ci_divergence", "claimed_summary",
    "confirm", "confirmed_outcome_rows", "derive", "exposed_rules", "format_trailer",
    "landed_lookup", "parse_trailer", "passing_check", "project_credits", "read_rows", "required_workflow",
    "record_adjudication", "record_detection", "record_detections", "record_exposure", "record_override",
    "record_void", "resolve_protected_branch", "select_ci_run", "session_exposed_rules", "submit_report",
    "verify_commit_trailers", "void_tree", "witnessed_exposed_rules",
]
EVENTS = ("check", "claimed", "report", "ci", "void", "exposure", "detection", "adjudication", "override")
MAX_REPORT_ROWS_PER_SESSION = 200
CI_EVENTS = ("push", "workflow_dispatch", "release")
CI_FAILED = ("failure", "timed_out", "startup_failure")
DEFAULT_WORKFLOW = "validate.yml"
_RESULT = {"success": "tp", "tp": "tp", "pass": "tp", "failure": "fp", "fp": "fp", "fail": "fp", "partial": "trigger"}
_FULL_SHA = re.compile(r"[0-9a-f]{40,64}")
_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_TRAILER = re.compile(r"\s*Aegis-Check:\s*tree=([0-9a-f]{40,64})\s+exit=(-?\d+)\s*")
_REV_LIMIT = 5000
_VERIFIED_CI: Dict[Tuple[str, str], Dict[str, Any]] = {}
_UNAVAILABLE_CI: Set[Tuple[str, str]] = set()
_SIGNERS_CHANGED: Dict[Tuple[str, str], Optional[str]] = {}
_DEFAULT_BRANCH: Dict[Tuple[str, str], str] = {}


class CIUnavailable(AegisError):
    """CI cannot be read right now (no gh, no network, a refusal): the credit stays where it is."""


class ReportConflict(ValueError):
    """An idempotency key was already used by this server session for a different report."""


def _canon_root(root: Any) -> str:
    try:
        return str(Path(str(root)).resolve())
    except OSError:
        return str(root)


def _normalize_event_row(row: Mapping[str, Any]) -> Dict[str, Any]:
    item = dict(row)
    rule_id = item.get("rule") or item.get("for_rule")
    if isinstance(rule_id, str) and rule_id:
        item["rule"] = rule_id
        item.setdefault("for_rule", rule_id)
    return item


def _event_rows(raw_rows: Iterable[Any]) -> List[Dict[str, Any]]:
    return [_normalize_event_row(r) for r in raw_rows if isinstance(r, dict) and r.get("v") == ledger.LEDGER_VERSION and r.get("event") in EVENTS]


def _read_ledger_events(root: Any, view: Any = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """The event rows and why some could not be read; from ``view``'s snapshot when it holds one."""
    raw = getattr(view, "raw_rows", None)
    if raw is not None:
        skipped = view.skipped_lines
        return _event_rows(raw), view.error or (f"{len(skipped)} unreadable line(s)" if skipped else None)
    try:
        res = read_jsonl(ledger.ledger_path(root))
    except (PathTraversalError, OSError) as exc:
        return [], str(exc)
    err = res.error or (f"{len(res.skipped_lines)} unreadable line(s)" if res.skipped_lines else None)
    return _event_rows(res.rows), err


def read_rows(root: Any) -> List[Dict[str, Any]]:
    return _read_ledger_events(root)[0]


def _of(rows: Iterable[Mapping[str, Any]], event: str) -> List[Mapping[str, Any]]:
    return [r for r in rows if r.get("event") == event]


def flaky_keys(rows: Iterable[Mapping[str, Any]]) -> Set[Tuple[Any, Any, Any]]:
    seen: Dict[Tuple[Any, Any, Any], Set[bool]] = {}
    for row in _of(rows, "check"):
        seen.setdefault((row.get("tree"), row.get("cmd_digest"), row.get("env_class")), set()).add(bool(row.get("passed")))
    return {key for key, outcomes in seen.items() if len(outcomes) == 2}


def _passed(check: Mapping[str, Any]) -> bool:
    return check.get("passed") is True and not check.get("partial")


def _tested(check: Mapping[str, Any]) -> bool:
    """Whether ``check`` holds a tests run that is evidence (TestsRun.evidence: exit 0 in time, a test
    passed). A Layer-1-only row, 4.3.x included, says nothing about the tests and never credits."""
    tests = check.get("tests")
    if not isinstance(tests, dict):
        return False
    exit_code, passed = tests.get("exit"), tests.get("passed")
    return (type(exit_code) is int and exit_code == 0 and not tests.get("timed_out")
            and type(passed) is int and passed > 0)


def _sign(claimed: Any, check: Mapping[str, Any]) -> str:
    """Spec T4: a report confirms a passed check as tp or withdraws to a trigger, never fp. The
    stored ``result`` stays the agent's claim (ReportConflict compares it); only the read is signed."""
    return "tp" if claimed == "tp" and _passed(check) else "trigger"


def passing_check(rows: Iterable[Mapping[str, Any]], tree: Optional[str]) -> Optional[Mapping[str, Any]]:
    """The newest passing ``aegis check --record --tests`` row for ``tree``: a Layer-1-only row (no
    ``tests``) passes ``aegis check --record`` but never earns ``witness: aegis`` or a trailer."""
    if not tree:
        return None
    best = None
    for row in _of(rows, "check"):
        if (row.get("tree") == tree and row.get("witness") == "aegis" and _passed(row)
                and isinstance(row.get("tests"), dict) and isinstance(row.get("id"), str)):
            best = row
    return best


def _workflow_path(run: Mapping[str, Any]) -> str:
    return str(run.get("path") or "").split("@", 1)[0]


def resolve_protected_branch(root: Any) -> Optional[str]:
    return gitevidence.protected_branch(gitevidence.repo_facts(root))


def select_ci_run(
    runs: Iterable[Mapping[str, Any]], commit: str, workflow: str, *, branch: Optional[str] = "main",
) -> Optional[Mapping[str, Any]]:
    if not branch:
        return None
    wanted = f".github/workflows/{workflow}"
    best, best_key = None, None
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        head = (run.get("head_repository") or {}).get("full_name") if isinstance(run.get("head_repository"), Mapping) else None
        home = (run.get("repository") or {}).get("full_name") if isinstance(run.get("repository"), Mapping) else None
        run_branch = run.get("head_branch")
        run_id = run.get("id")
        if (not isinstance(run_branch, str) or not run_branch or run_branch != branch
                or _workflow_path(run) != wanted or run.get("head_sha") != commit or run.get("event") not in CI_EVENTS
                or not head or head != home or run.get("conclusion") == "cancelled"
                or not isinstance(run_id, int) or isinstance(run_id, bool)):
            continue
        started = str(run.get("run_started_at") or run.get("updated_at") or run.get("created_at") or "")
        key = (started, str(run.get("created_at") or ""), int(run.get("run_attempt") or 0), run_id)
        if best_key is None or key > best_key:
            best, best_key = run, key
    return best


def ci_conclusion(run: Optional[Mapping[str, Any]]) -> str:
    if run is None:
        return "none"
    if run.get("status") != "completed":
        return "pending"
    conclusion = run.get("conclusion")
    return conclusion if conclusion == "success" or conclusion in CI_FAILED else "pending"


class GhRestClient:
    def __init__(self, repo: Optional[str] = None, runner: Optional[Callable[..., Any]] = None, cwd: Any = None) -> None:
        self.repo, self.runner, self.cwd = repo, runner or human_gate.default_gh_runner, cwd

    def _api(self, path: str) -> Any:
        result = self.runner(["api", f"repos/{self.repo or '{owner}/{repo}'}{path}"], cwd=self.cwd)
        if result is None:
            raise CIUnavailable("gh is not installed")
        if result.returncode != 0:
            raise CIUnavailable(f"gh api failed (exit {result.returncode})")
        try:
            return json.loads(result.stdout)
        except ValueError as exc:
            raise CIUnavailable("gh printed something that is not JSON") from exc

    def runs_for(self, commit: str) -> List[Dict[str, Any]]:
        if not _FULL_SHA.fullmatch(commit or ""):
            raise CIUnavailable("not a full commit id")
        body = self._api(f"/actions/runs?head_sha={commit}&per_page=100")
        runs = body.get("workflow_runs") if isinstance(body, dict) else None
        if not isinstance(runs, list):
            raise CIUnavailable("gh printed no workflow_runs")
        return [r for r in runs if isinstance(r, dict)]

    def default_branch(self) -> str:
        body = self._api("")
        branch = body.get("default_branch") if isinstance(body, dict) else None
        if not isinstance(branch, str) or not branch or not branch.isprintable() or any(c.isspace() for c in branch):
            raise CIUnavailable("gh printed no usable default_branch")
        return branch


def _protected_branch(root: Any, client: Any) -> Optional[str]:
    """GitHub's default branch (memoised per root and process), never the agent-writable origin/HEAD:
    a failed answer raises CIUnavailable. Only an injected client that cannot ask uses the local ref."""
    ask = getattr(client, "default_branch", None)
    if not callable(ask):
        return resolve_protected_branch(root)
    key = (_canon_root(root), str(getattr(client, "repo", None) or ""))
    if key not in _DEFAULT_BRANCH:
        _DEFAULT_BRANCH[key] = ask()
    return _DEFAULT_BRANCH[key]


def _call_landed(landed: Callable[..., Optional[str]], tree: str, head: Optional[str] = None) -> Optional[str]:
    if isinstance(head, str) and head:
        try:
            return landed(tree, head)
        except TypeError:
            return landed(tree)
    return landed(tree)


def landed_lookup(
    root: Any, refs: Optional[Sequence[str]] = None, limit: int = _REV_LIMIT,
) -> Callable[..., Optional[str]]:
    """``lookup(tree, head=None)``: the newest commit of the protected branch (or ``refs``) with
    ``tree`` that ``head`` is an ancestor of. Git is asked nothing until the first lookup, and each
    (tree, head) once; a ``head`` that is not a full object id (ledger text) lands nowhere."""
    index: List[Any] = []
    answers: Dict[Tuple[str, Optional[str]], Optional[str]] = {}

    def load() -> Tuple[Any, Dict[str, List[str]]]:
        if not index:
            facts = gitevidence.repo_facts(root)
            if facts is None or facts.top is None:
                tips: Sequence[str] = ()
            elif refs is None:
                tips = gitevidence.branch_tips(facts, gitevidence.protected_branch(facts) or "")
            else:
                tips = [oid for oid in (gitsafe.resolve_commit(facts.top, r) for r in refs) if oid]
            by_tree: Dict[str, List[str]] = {}
            for commit, commit_tree in gitevidence.commits(facts, tips, limit):
                by_tree.setdefault(commit_tree, []).append(commit)
            index.append((facts, by_tree))
        return index[0]

    def lookup(tree: str, head: Optional[str] = None) -> Optional[str]:
        key = (tree, head or None)
        if key not in answers:
            facts, by_tree = load()
            if head and not (isinstance(head, str) and _FULL_SHA.fullmatch(head)):
                answers[key] = None
            else:
                answers[key] = next((c for c in by_tree.get(tree, ())
                                     if not head or gitevidence.is_ancestor(facts, head, c)), None)
        return answers[key]

    setattr(lookup, "_aegis_root", _canon_root(root))
    return lookup


_EXPOSED: Dict[Tuple[str, str, str], Set[str]] = {}
_MAX_EXPOSED_SESSIONS = 256
# (root, host, session, rule, scope_basis) this process wrote or found in the ledger: a rescan
# of the same session then takes no lock and reads nothing. Rows are only ever appended.
_PERSISTED: Set[Tuple[str, str, str, str, Optional[str]]] = set()
_MAX_PERSISTED = 50_000


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_exposure(
    root: Any, host: Optional[str], session: Optional[str], rules: Iterable[str], *,
    paths: Optional[Iterable[str]] = None, rev: Optional[str] = None, scope_basis: Optional[str] = None,
    heartbeat: Optional[bool] = None, ts: Optional[str] = None, persist: bool = True,
    revs: Optional[Mapping[str, str]] = None,
) -> List[Dict[str, Any]]:
    """``revs`` names each rule's own revision (``rev`` is the fallback): insight review joins an
    exposure to a correction only at the rule's current revision."""
    rule_list = [r for r in dict.fromkeys(rules) if isinstance(r, str) and r]
    key = (str(root), host or "", session or "")
    if key not in _EXPOSED and len(_EXPOSED) >= _MAX_EXPOSED_SESSIONS:
        _EXPOSED.pop(next(iter(_EXPOSED)))
    _EXPOSED.setdefault(key, set()).update(rule_list)
    if not persist or not rule_list:
        return []
    stamp, s_id, h_id = ts or _now(), session or "", host or ""
    kept = [(str(root), h_id, s_id, rule_id, scope_basis) for rule_id in rule_list]
    if all(k in _PERSISTED for k in kept):
        return []
    path_list = [str(p) for p in (paths or ()) if isinstance(p, str)]
    with ledger_locked(root):
        seen = {(str(r.get("session") or ""), str(r.get("rule") or r.get("for_rule") or ""), r.get("scope_basis")) for r in _of(read_rows(root), "exposure")}
        to_append: List[Dict[str, Any]] = []
        for rule_id in rule_list:
            if (s_id, rule_id, scope_basis) in seen:
                continue
            seen.add((s_id, rule_id, scope_basis))
            row: Dict[str, Any] = {
                "v": ledger.LEDGER_VERSION,
                "ts": stamp,
                "event": "exposure",
                "rule": rule_id,
                "session": s_id,
                "host": h_id,
                "paths": path_list,
                "rev": (revs or {}).get(rule_id, rev),
            }
            if scope_basis is not None:
                row["scope_basis"] = str(scope_basis)
            if heartbeat is not None:
                row["heartbeat"] = bool(heartbeat)
            to_append.append(row)
        written = [_normalize_event_row(r) for r in ledger.append_rows(root, to_append)] if to_append else []
        if len(_PERSISTED) + len(kept) > _MAX_PERSISTED:
            _PERSISTED.clear()
        _PERSISTED.update(kept)
        return written


def exposed_rules(root: Any, host: Optional[str], session: Optional[str] = None) -> Set[str]:
    if session is None:
        s_id = host or ""
        found = {r for (r_root, _h_id, r_sess), rules in _EXPOSED.items() if r_root == str(root) and r_sess == s_id for r in rules}
        if s_id:
            for row in _of(read_rows(root), "exposure"):
                if str(row.get("session") or "") == s_id:
                    rule_id = row.get("rule") or row.get("for_rule")
                    if isinstance(rule_id, str) and rule_id:
                        found.add(rule_id)
        return found
    h_id, s_id = host or "", session or ""
    found = set(_EXPOSED.get((str(root), h_id, s_id), ()))
    if s_id:
        for row in _of(read_rows(root), "exposure"):
            if str(row.get("session") or "") == s_id and str(row.get("host") or "") == h_id:
                rule_id = row.get("rule") or row.get("for_rule")
                if isinstance(rule_id, str) and rule_id:
                    found.add(rule_id)
    return found


session_exposed_rules = exposed_rules


def witnessed_exposed_rules(root: Any, host: Optional[str], session: Optional[str]) -> Set[str]:
    """What this process's scans showed (host, session): the credited set of spec T1. Ledger exposure
    rows are agent-writable, so only ``exposed_rules`` (display, other processes) merges them."""
    return set(_EXPOSED.get((str(root), host or "", session or ""), ()))


def record_detection(
    root: Any, rule: str, file: str, pattern: str, *, disposition: str,
    rev: Optional[str] = None, branch: str = "main", fix_rev: Optional[str] = None,
    weight: Optional[float] = None, ts: Optional[str] = None,
) -> Dict[str, Any]:
    return record_detections(root, [{"rule": rule, "file": file, "pattern": pattern, "disposition": disposition,
                                      "rev": rev, "branch": branch, "fix_rev": fix_rev, "weight": weight, "ts": ts}])[0]


def record_detections(root: Any, findings: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """A ``detection`` row per finding (``rule``, ``file``, ``pattern``, ``disposition``, optional ``rev``,
    ``branch``, ``fix_rev``, ``weight``, ``ts``) under one ledger lock, one read and one append. A
    finding whose unit (rule, file, pattern, rev) already ends in the same disposition, fix and weight
    writes nothing; returns each finding's row, written or existing, in order."""
    with ledger_locked(root):
        latest: Dict[Tuple[Any, ...], Mapping[str, Any]] = {}
        # One unit per introducing commit (rev), as replay and fitness key it: a re-replay supersedes it.
        for ex in _of(read_rows(root), "detection"):
            latest[(ex.get("rule") or ex.get("for_rule"), ex.get("file"), ex.get("pattern"), ex.get("rev"))] = ex
        out: List[Any] = []
        fresh: List[Dict[str, Any]] = []
        for f in findings:
            disposition = f.get("disposition")
            if disposition not in ("caught", "leaked"):
                raise ValueError(f"disposition must be 'caught' or 'leaked', got {disposition!r}")
            weight = float(f["weight"]) if f.get("weight") is not None else (0.5 if disposition == "caught" else 1.0)
            unit = (f["rule"], f["file"], f["pattern"], f.get("rev"))
            prev = latest.get(unit)
            if (prev is not None and prev.get("disposition") == disposition
                    and prev.get("fix_rev") == f.get("fix_rev") and float(prev.get("weight") or 0.0) == weight):
                out.append(prev)
                continue
            row = {"v": ledger.LEDGER_VERSION, "ts": f.get("ts") or _now(), "event": "detection", "rule": f["rule"],
                   "file": f["file"], "pattern": f["pattern"], "disposition": disposition,
                   "branch": f.get("branch") or "main", "rev": f.get("rev"), "fix_rev": f.get("fix_rev"), "weight": weight}
            latest[unit] = row
            out.append(len(fresh))
            fresh.append(row)
        written = ledger.append_rows(root, fresh) if fresh else []
        return [_normalize_event_row(written[r] if isinstance(r, int) else r) for r in out]


def record_adjudication(
    root: Any, rule: str, verdict: str, *, adjudicator: str = "human", ref: Optional[str] = None,
    summary: Optional[str] = None, file: Optional[str] = None, line: Optional[int] = None,
    snippet: Optional[str] = None, session: Optional[str] = None, repo: Optional[str] = None, ts: Optional[str] = None,
) -> Dict[str, Any]:
    """Append a ledger ``adjudication`` row. Fitness reads such rows and never counts them (any
    writer can append one); a label counts only as git content merged at the reviewed BASE
    (``aegis rule adjudicate`` and aegis_core.adjudication)."""
    norm_verdict = _RESULT.get(verdict, verdict)
    if norm_verdict not in ("tp", "fp"):
        raise ValueError(f"adjudication verdict must be 'tp' or 'fp', got {verdict!r}")
    if adjudicator not in ("human", "automated", "ci", "pr", "revert"):
        raise ValueError(f"adjudicator must be 'human', 'automated', 'ci', 'pr', or 'revert', got {adjudicator!r}")
    with ledger_locked(root):
        if ref is not None:
            for ex in _of(read_rows(root), "adjudication"):
                if (ex.get("rule") or ex.get("for_rule")) == rule and ex.get("ref") == ref:
                    return _normalize_event_row(ex)
        row: Dict[str, Any] = {
            "v": ledger.LEDGER_VERSION,
            "ts": ts or _now(),
            "event": "adjudication",
            "rule": rule,
            "verdict": norm_verdict,
            "adjudicator": adjudicator,
        }
        for k, v in (("ref", ref), ("summary", summary), ("file", file), ("snippet", snippet), ("session", session), ("repo", repo)):
            if v is not None:
                row[k] = str(v)
        if line is not None:
            row["line"] = int(line)
        return _normalize_event_row(ledger.append_rows(root, [row])[0])


record_human_label = record_adjudication


def record_override(
    root: Any, rule: str, file: str, line: int, reason: str = "", *, rev: Optional[str] = None, ts: Optional[str] = None,
) -> Dict[str, Any]:
    with ledger_locked(root):
        for ex in _of(read_rows(root), "override"):
            if (ex.get("rule") or ex.get("for_rule")) == rule and ex.get("file") == file and int(ex.get("line") or 0) == int(line) and ex.get("rev") == rev:
                return _normalize_event_row(ex)
        row: Dict[str, Any] = {
            "v": ledger.LEDGER_VERSION,
            "ts": ts or _now(),
            "event": "override",
            "rule": rule,
            "file": str(file),
            "line": int(line),
            "reason": str(reason or ""),
            "status": "contested",
        }
        if rev is not None:
            row["rev"] = str(rev)
        return _normalize_event_row(ledger.append_rows(root, [row])[0])


def record_void(root: Any, check_id: str, reason: str) -> Dict[str, Any]:
    with ledger_locked(root):
        existing = next((r for r in _of(read_rows(root), "void") if r.get("check") == check_id), None)
        if existing is not None:
            return dict(existing)
        return ledger.append_rows(root, [{"v": ledger.LEDGER_VERSION, "ts": _now(), "event": "void", "check": check_id, "reason": reason}])[0]


def void_tree(root: Any, tree: str, reason: str) -> int:
    """Void every ``check`` row of ``tree`` that has no void yet (one ``void`` row per check id, under
    one ledger lock); returns how many were written. ``void`` rows are terminal."""
    with ledger_locked(root):
        rows = read_rows(root)
        done = {r.get("check") for r in _of(rows, "void")}
        ids = [c["id"] for c in _of(rows, "check") if c.get("tree") == tree and isinstance(c.get("id"), str)]
        fresh = [i for i in dict.fromkeys(ids) if i not in done]
        if fresh:
            stamp = _now()
            ledger.append_rows(root, [{"v": ledger.LEDGER_VERSION, "ts": stamp, "event": "void", "check": i,
                                       "reason": reason} for i in fresh])
        return len(fresh)


_REVERTS = re.compile(r"This reverts commit ([0-9a-f]{64}|[0-9a-f]{40})\b")


def _reverted(top: Path, branch: str, commits: Mapping[str, Any]) -> Set[str]:
    """Landed commits a ``This reverts commit <oid>`` line on the protected branch names. The message
    is agent-writable text, which is acceptable here: it can only void credit, never grant it."""
    ref = next((r for r in (f"refs/remotes/origin/{branch}", f"refs/heads/{branch}") if gitsafe.resolve_commit(top, r)), None)
    if ref is None:
        return set()
    # -z: git refuses a NUL in a message, so a message cannot forge a record boundary (PC-3).
    res = gitsafe.run(["log", "-z", "--max-count=500", "--format=%H%n%B", ref], top)
    if res.returncode != 0:
        raise gitsafe.GitError(f"git log {ref} failed (exit {res.returncode})")
    named = set(_REVERTS.findall(res.stdout.decode("utf-8", "replace")))
    return {c for c in commits if c in named}


def required_workflow(root: Any) -> str:
    """The workflow whose runs confirm credit: ``ci.workflow`` of the user-scope config, else
    ``validate.yml``. Never the repository config or a ledger row (SECURITY.md truth table, row 2)."""
    from aegis_core.config import user_ci_workflow

    return user_ci_workflow(root) or DEFAULT_WORKFLOW


def confirm(
    root: Any, *, client: Any, workflow: Optional[str] = None,
    landed: Optional[Callable[..., Optional[str]]] = None, branch: Optional[str] = None,
) -> Dict[str, Any]:
    workflow = required_workflow(root) if workflow is None else workflow
    c_root = _canon_root(root)
    rows, look = read_rows(root), landed or landed_lookup(root)
    if landed is not None:
        try:
            setattr(landed, "_aegis_root", c_root)
        except AttributeError:
            pass
    voided_checks = {r.get("check") for r in _of(rows, "void")}
    latest_ci = {str(r.get("commit")): (str(r.get("ci_conclusion")), r.get("run_id"), r.get("ci_run_attempt")) for r in _of(rows, "ci")}
    by_id = {r["id"]: r for r in _of(rows, "check") if isinstance(r.get("id"), str)}
    summary: Dict[str, Any] = {"asked": 0, "confirmed": 0, "voided": 0, "errors": []}
    commits: Dict[str, List[str]] = {}
    for check_id in sorted({r.get("check") for r in _of(rows, "report")}):
        if check_id not in voided_checks and check_id in by_id:
            chk = by_id[check_id]
            commit = _call_landed(look, str(chk.get("tree")), chk.get("head"))
            if commit:
                commits.setdefault(commit, []).append(check_id)
    target_branch = branch
    if commits and target_branch is None:
        try:
            target_branch = _protected_branch(root, client)
        except CIUnavailable as exc:
            for commit in commits:
                _VERIFIED_CI.pop((c_root, commit), None)
                _UNAVAILABLE_CI.add((c_root, commit))
            summary["errors"].append(str(exc))
            return summary
    top = gitsafe.toplevel(Path(str(root)))
    if commits and target_branch and top is not None:
        try:
            for commit in sorted(_reverted(top, target_branch, commits)):
                for check_id in commits.pop(commit):
                    record_void(root, check_id, "reverted")
                    summary["voided"] += 1
        except gitsafe.GitError as exc:
            summary["errors"].append(f"cannot read the history of {target_branch}: {exc}")
    for commit, checks in commits.items():
        try:
            runs = client.runs_for(commit)
        except CIUnavailable as exc:
            _VERIFIED_CI.pop((c_root, commit), None)
            _UNAVAILABLE_CI.add((c_root, commit))
            summary["errors"].append(str(exc))
            continue
        _UNAVAILABLE_CI.discard((c_root, commit))
        summary["asked"] += 1
        run = select_ci_run(runs, commit, workflow, branch=target_branch)
        conclusion = ci_conclusion(run)
        run_id = run.get("id") if run else None
        run_attempt = run.get("run_attempt") if run else None
        _VERIFIED_CI[(c_root, commit)] = {"conclusion": conclusion, "workflow": workflow, "branch": target_branch, "run_id": run_id, "run_attempt": run_attempt}
        if latest_ci.get(commit) != (conclusion, run_id, run_attempt):
            ledger.append_rows(root, [{"v": ledger.LEDGER_VERSION, "ts": _now(), "event": "ci", "commit": commit, "workflow": workflow, "ci_conclusion": conclusion, "run_id": run_id, "ci_run_attempt": run_attempt}])
        if conclusion == "success":
            summary["confirmed"] += len(checks)
        elif conclusion in CI_FAILED:
            summary["voided"] += len(checks)
    return summary


def _count(rows: Iterable[Mapping[str, Any]], session: Optional[str]) -> int:
    return sum(1 for r in rows if r.get("event") in ("claimed", "report") and r.get("session") == session)


def submit_report(
    root: Any, *, tree: Optional[str], session: Optional[str], host: Optional[str], key: str,
    outcome: str, rules_for: Callable[[Mapping[str, Any]], Sequence[str]],
    cap: Optional[int] = None, source: str = "mcp",
) -> Dict[str, Any]:
    limit = MAX_REPORT_ROWS_PER_SESSION if cap is None else cap
    result, namespaced = _RESULT.get(outcome, "trigger"), (f"{host}/{session}/{key}" if session else key)
    with ledger_locked(root):
        rows = read_rows(root)
        for row in rows:
            if row.get("report_key") == namespaced and row.get("event") in ("claimed", "report") and row.get("result", result) != result:
                raise ReportConflict(namespaced)
        used, check = _count(rows, session), passing_check(rows, tree)
        if check is None:
            if any(r.get("session") == session and r.get("tree") == tree for r in _of(rows, "claimed")):
                return {"status": "claimed", "witness": "self", "credited": [], "tree": tree, "recorded": False}
            if used >= limit:
                return {"status": "rate_limited", "limit": limit, "witness": "self", "credited": []}
            ledger.append_rows(root, [{"v": ledger.LEDGER_VERSION, "ts": _now(), "event": "claimed", "witness": "self", "tree": tree, "source": source, "session": session, "host": host, "key": f"claim:{host}/{session}:{tree}", "report_key": namespaced, "result": result}])
            return {"status": "claimed", "witness": "self", "credited": [], "tree": tree, "recorded": True}
        rules = list(dict.fromkeys(rules_for(check)))
        have = {(r.get("rule") or r.get("for_rule")) for r in _of(rows, "report") if r.get("check") == check["id"]}
        fresh = [r for r in rules if r not in have]
        if used + len(fresh) > limit:
            return {"status": "rate_limited", "limit": limit, "witness": "aegis", "credited": []}
        if fresh:
            stamp = _now()
            ledger.append_rows(root, [{"v": ledger.LEDGER_VERSION, "ts": stamp, "event": "report", "witness": "aegis", "check": check["id"], "tree": tree, "rule": rule, "for_rule": rule, "result": result, "source": source, "session": session, "host": host, "key": f"credit:{check['id']}:{rule}", "report_key": namespaced} for rule in fresh])
        return {"status": "recorded", "witness": "aegis", "credited": rules, "check": check["id"], "tree": tree}


@dataclass(frozen=True)
class Credit:
    check: str
    rule: str
    tree: str
    state: str
    result: str
    commit: Optional[str] = None
    reason: str = ""
    flaky: bool = False
    counts: bool = False
    ts: str = ""
    protected: Tuple[str, ...] = ()


def derive(
    rows: Sequence[Mapping[str, Any]], *, landed: Callable[..., Optional[str]],
    approved: Optional[Callable[[str, Sequence[str]], bool]] = None,
    verified_ci: Optional[Mapping[str, str]] = None,
) -> List[Credit]:
    checks = {r["id"]: r for r in _of(rows, "check") if isinstance(r.get("id"), str)}
    voids = {str(r.get("check")): str(r.get("reason") or "voided") for r in _of(rows, "void")}
    ci_rows = {str(r.get("commit")): r for r in _of(rows, "ci") if r.get("commit")}
    c_root = getattr(landed, "_aegis_root", None)
    flaky, credits, seen = flaky_keys(rows), [], set()
    for report in _of(rows, "report"):
        identity = (str(report.get("check")), str(report.get("rule") or report.get("for_rule")))
        check = checks.get(identity[0])
        if check is None or identity in seen:
            continue
        seen.add(identity)
        tree = str(check.get("tree"))
        commit = _call_landed(landed, tree, check.get("head"))
        ci_row = ci_rows.get(commit) if commit else None
        ledger_conc = str(ci_row.get("ci_conclusion")) if ci_row is not None else None
        unavail = bool(commit and c_root and (c_root, commit) in _UNAVAILABLE_CI)
        v_conc: Optional[str] = None
        if commit and not unavail:
            if verified_ci is not None and commit in verified_ci:
                v_conc = verified_ci[commit]
            elif c_root and (c_root, commit) in _VERIFIED_CI:
                v_entry = _VERIFIED_CI[(c_root, commit)]
                if ci_row is None or (ci_row.get("run_id") == v_entry.get("run_id") and ci_row.get("ci_run_attempt") == v_entry.get("run_attempt")):
                    v_conc = str(v_entry.get("conclusion") or "")
        reason = ""
        if identity[0] in voids:
            state, reason = "voided", voids[identity[0]]
        elif commit and unavail:
            state, reason = "landed", "ci_unavailable"
        elif commit and (v_conc in CI_FAILED or (v_conc is None and ledger_conc in CI_FAILED)):
            state, reason = "voided", "ci_failed"
        elif commit and v_conc == "success" and ledger_conc == "success":
            state = "confirmed"
        elif commit and ledger_conc == "success" and v_conc != "success":
            state, reason = "landed", "unverified_ci"
        else:
            state = "landed" if commit else "witnessed"
        is_flaky = (check.get("tree"), check.get("cmd_digest"), check.get("env_class")) in flaky
        categories = tuple(check.get("protected") or ())
        counts = state == "confirmed" and not is_flaky
        if counts and not _tested(check):
            counts, reason = False, "no_tests"
        elif counts and check.get("protected_changed") and not (approved and approved(identity[0], categories)):
            counts, reason = False, "protected_changed"
        elif is_flaky and not reason:
            reason = "flaky"
        credits.append(Credit(check=identity[0], rule=identity[1], tree=tree, state=state, result=_sign(report.get("result"), check), commit=commit, reason=reason, flaky=is_flaky, counts=counts, ts=str(report.get("ts") or ""), protected=categories))
    return credits


def confirmed_outcome_rows(credits: Iterable[Credit]) -> List[Dict[str, Any]]:
    seen: Set[Tuple[str, str]] = set()
    out: List[Dict[str, Any]] = []
    for c in credits:
        if c.counts and (c.check, c.rule) not in seen:
            seen.add((c.check, c.rule))
            out.append({"v": ledger.LEDGER_VERSION, "ts": c.ts, "rule": c.rule, "outcome": c.result, "source": "ci", "key": f"credit:{c.check}:{c.rule}", "host": None, "session": None})
    return out


def _last_signers_change(top: Path, tip_ref: str) -> Optional[str]:
    """The newest commit in the history of ``tip_ref`` that changed allowed_signers, None when none
    did. Raises GitError when git cannot answer; only an answer is memoised (a tip never changes)."""
    tip = gitsafe.resolve_commit(top, tip_ref)
    if tip is None:
        raise gitsafe.GitError(f"cannot resolve {tip_ref}")
    key = (str(top), tip)
    if key not in _SIGNERS_CHANGED:
        res = gitsafe.run(["log", "-1", "--no-show-signature", "--format=%H", tip, "--", human_gate.ALLOWED_SIGNERS],
                          top)
        if res.returncode != 0:
            raise gitsafe.GitError(f"git log failed: {' '.join(res.stderr.decode('utf-8', 'replace').split())[:200]}")
        found = res.stdout.decode("ascii", "replace").strip()
        _SIGNERS_CHANGED[key] = found if _OID.fullmatch(found) else None
    return _SIGNERS_CHANGED[key]


def approval_lookup(
    root: Any, rows: Sequence[Mapping[str, Any]], landed: Optional[Callable[..., Optional[str]]] = None,
    *, branch: Optional[str] = None,
) -> Callable[[str, Sequence[str]], bool]:
    """Whether a signed approval covers a protected check. The row's ``base`` (the fork point
    ``record`` saw) is only the range anchor: ledger rows are agent-writable, so it must be a full
    oid that is an ancestor of the protected branch (``branch``, else the local one), or allowed_signers
    would be read from a commit the agent chose; and it must not predate the branch's last change to
    allowed_signers, or an older ancestor would revive a key the branch has since removed."""
    top = gitsafe.toplevel(Path(str(root)))
    look = landed or landed_lookup(root)
    checks = {r["id"]: r for r in _of(rows, "check") if isinstance(r.get("id"), str)}
    cache: Dict[str, bool] = {}
    anchor: List[Optional[Tuple[str, str]]] = []

    def protected_tip() -> Optional[Tuple[str, str]]:
        if not anchor:
            p_branch = branch if branch is not None else resolve_protected_branch(root)
            refs = (f"refs/remotes/origin/{p_branch}", f"refs/heads/{p_branch}") if p_branch and top else ()
            anchor.append(next(((p_branch, r) for r in refs if gitsafe.resolve_commit(top, r)), None))
        return anchor[0]

    def is_approved(check_id: str, _categories: Sequence[str] = ()) -> bool:
        if check_id in cache:
            return cache[check_id]
        check = checks.get(check_id)
        base_ref = check.get("base") if check is not None else None
        commit = _call_landed(look, str(check.get("tree") or ""), check.get("head")) if check is not None else None
        tip = protected_tip() if commit and isinstance(base_ref, str) and _OID.fullmatch(base_ref) else None
        ok = False
        if top is not None and tip is not None:
            p_branch, tip_ref = tip
            try:
                signers = _last_signers_change(top, tip_ref)
                if (signers is not None
                        and gitsafe.run(["merge-base", "--is-ancestor", base_ref, tip_ref], top).returncode == 0
                        and gitsafe.run(["merge-base", "--is-ancestor", signers, base_ref], top).returncode == 0):
                    gov_hash = human_gate.governance_tree_hash(top, commit, base=base_ref)
                    tips = [commit, f"refs/heads/{p_branch}", f"refs/remotes/origin/{p_branch}", "HEAD"]
                    ok = any(
                        (app := human_gate.find_approval(top, t, base_ref, governance_hash=gov_hash)) is not None
                        and app.valid for t in dict.fromkeys(tips)
                    )
            except (human_gate.HumanGateError, gitsafe.GitError, OSError):
                ok = False  # git or IO trouble fails closed; a programming error propagates
        cache[check_id] = ok
        return ok

    return is_approved


@dataclass(frozen=True)
class CreditProjection:
    credits: Tuple[Credit, ...]
    outcome_rows: Tuple[Dict[str, Any], ...]
    available: bool = True
    error: Optional[str] = None


def _ci_cache_current(entry: Optional[Mapping[str, Any]], ci_row: Mapping[str, Any]) -> bool:
    """A cached verdict is final only when terminal and for the run the newest ``ci`` row names (B14b)."""
    if not entry or not (entry.get("conclusion") == "success" or entry.get("conclusion") in CI_FAILED):
        return False
    return (entry.get("run_id"), entry.get("run_attempt")) == (ci_row.get("run_id"), ci_row.get("ci_run_attempt"))


def project_credits(
    root: Any, *, view: Any = None, client: Any = None, workflow: Optional[str] = None,
    landed: Optional[Callable[..., Optional[str]]] = None,
    approved: Optional[Callable[[str, Sequence[str]], bool]] = None,
    verify_ci: bool = False,
) -> CreditProjection:
    c_root = _canon_root(root)
    if landed is not None:
        try:
            setattr(landed, "_aegis_root", c_root)
        except AttributeError:
            pass
    # confirm() appends ci rows, so with a client the snapshot is read again after it.
    rows, read_err = _read_ledger_events(root, view if client is None else None)
    view_err = getattr(view, "incomplete", None) if view is not None else None
    err = view_err or read_err
    # Credits derive from report rows only (confirm() iterates them too): without one there is
    # nothing to land, verify or approve, so no git, no gh and no CI.
    if not any(r.get("event") == "report" for r in rows):
        return CreditProjection((), (), available=not err, error=str(err) if err else None)
    workflow = required_workflow(root) if workflow is None else workflow
    look = landed or landed_lookup(root)
    if client is not None:
        confirm(root, client=client, workflow=workflow, landed=look)
        rows, read_err = _read_ledger_events(root)  # confirm() appends ci rows
        err = view_err or read_err
    if err:
        return CreditProjection((), (), available=False, error=str(err))
    stopped: Optional[str] = None
    p_branch: Optional[str] = None
    # Read paths (scan, status, list) pass verify_ci=False and stay offline: a ``ci`` row then counts
    # only when this process verified it, so they can under-credit but never over-credit.
    if verify_ci:
        rest_client = GhRestClient(cwd=str(root)) if client is None else None
        latest = {str(r.get("commit") or ""): r for r in _of(rows, "ci")}
        pending = [(commit, ci_row) for commit, ci_row in latest.items()
                   if commit and (c_root, commit) not in _UNAVAILABLE_CI
                   and not _ci_cache_current(_VERIFIED_CI.get((c_root, commit)), ci_row)]
        # The workflow is the caller's and the branch GitHub's: a ci row's ``workflow`` is display only.
        if any(_FULL_SHA.fullmatch(commit) for commit, _row in pending):
            try:
                p_branch = _protected_branch(root, rest_client or client)
            except CIUnavailable as exc:
                stopped = (f"CI verification stopped: GitHub did not name the default branch ({exc}); "
                           f"{len(pending)} commit(s) were not verified")
        for idx, (commit, ci_row) in enumerate(pending if p_branch else ()):
            if rest_client is not None:
                try:
                    runs = rest_client.runs_for(commit)
                    run = select_ci_run(runs, commit, workflow, branch=p_branch)
                    conc, rid, ratt = ci_conclusion(run), (run.get("id") if run else None), (run.get("run_attempt") if run else None)
                    _VERIFIED_CI[(c_root, commit)] = {"conclusion": conc, "workflow": workflow, "branch": p_branch, "run_id": rid, "run_attempt": ratt}
                    continue
                except CIUnavailable:
                    pass
            # Circuit breaker: a dead gh costs one attempt per projection. Only a well-formed id trips
            # it, so one malformed (never-asked) row cannot switch verification off for the rest.
            # Tripping makes the projection unavailable: verify_ci callers decide (promote, demote,
            # archive), and under-credited fitness must not drive those decisions.
            if rest_client is not None and _FULL_SHA.fullmatch(commit):
                stopped = (f"CI verification stopped after gh failed for {commit[:12]}; "
                           f"{len(pending) - idx} commit(s) were not verified")
                break
    app_fn = approved or approval_lookup(root, rows, landed=look, branch=p_branch)
    derived = derive(rows, landed=look, approved=app_fn)
    if verify_ci and stopped is None:
        # confirm() (sync) parks a landed commit whose CI gh could not read in _UNAVAILABLE_CI, and the
        # loop above never retries it, so its credit stays landed: as cut short as a tripped breaker.
        unread = sorted({c.commit for c in derived
                         if c.commit and c.state == "landed" and (c_root, c.commit) in _UNAVAILABLE_CI})
        if unread:
            stopped = (f"CI verification stopped: gh failed while confirming CI for {unread[0][:12]}; "
                       f"{len(unread)} landed commit(s) were not verified")
    return CreditProjection(tuple(derived), tuple(confirmed_outcome_rows(derived)),
                            available=stopped is None, error=stopped)


def claimed_summary(root: Any, view: Any = None) -> Dict[str, Any]:
    claims = _of(_read_ledger_events(root, view)[0], "claimed")
    return {"label": "claimed (unwitnessed)", "claimed": len(claims), "sessions": len({(c.get("host"), c.get("session")) for c in claims})}


def format_trailer(tree: str, exit_code: int) -> str:
    return f"Aegis-Check: tree={tree} exit={exit_code}"


def parse_trailer(line: str) -> Optional[Dict[str, Any]]:
    found = _TRAILER.fullmatch(line.strip("\r\n")) if isinstance(line, str) else None
    return {"tree": found.group(1), "exit": int(found.group(2))} if found else None


def check_ci_divergence(trailer: Any, rerun: Mapping[str, Any], second: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Spec T1: only an equal tree whose rerun diverges twice from the parsed trailer fails; a tree
    mismatch or an inconclusive rerun (it timed out, git could not answer) is ``unbound``."""
    given = dict(trailer) if isinstance(trailer, Mapping) else None
    if not given or not given.get("tree") or "exit" not in given:
        return {"result": "unbound", "failed": False, "reason": "no usable Aegis-Check trailer"}
    first = dict(rerun) if isinstance(rerun, Mapping) else {}
    if first.get("inconclusive"):
        return {"result": "unbound", "failed": False, "reason": f"CI rerun {first.get('reason') or 'was inconclusive'}"}
    if first.get("tree") != given["tree"]:
        return {"result": "unbound", "failed": False, "reason": "CI ran a different tree"}
    claimed_pass = given["exit"] == 0
    if (first.get("exit") == 0) == claimed_pass:
        return {"result": "agree", "failed": False, "reason": ""}
    if second is None:
        return {"result": "rerun", "failed": False, "reason": "outcomes diverge on the same tree"}
    again = dict(second)
    if again.get("inconclusive"):
        return {"result": "unbound", "failed": False, "reason": f"CI rerun {again.get('reason') or 'was inconclusive'}"}
    if again.get("tree") == given["tree"] and (again.get("exit") == 0) == claimed_pass:
        return {"result": "agree", "failed": False, "reason": "flaky: the re-run agrees with the trailer"}
    return {"result": "void", "failed": True, "reason": "outcomes still diverge on the same tree after a re-run"}


def verify_commit_trailers(
    root: Any, base: str, head: str = "HEAD", *, rerun_fn: Callable[[str, str], Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    """Spec T1: compare the head commit's ``Aegis-Check`` trailer with ``rerun_fn(commit, tree)``;
    earlier commits and a head without a trailer rerun nothing. A divergence fails the CI job and
    writes ``void`` rows to the ledger of the machine that ran ``check --ci``."""
    top = gitsafe.toplevel(Path(str(root)))
    if top is None:
        return []
    mb, tip = gitsafe.merge_base(top, base, head), gitsafe.resolve_commit(top, head)
    if not mb or not tip or tip == mb:
        return []
    msg = gitsafe.run(["log", "-1", "--format=%B", tip], top)
    tree_res = gitsafe.run(["rev-parse", "--verify", "--quiet", f"{tip}^{{tree}}"], top)
    if msg.returncode != 0 or tree_res.returncode != 0:
        return [{"commit": tip, "result": "unbound", "failed": False, "reason": "git could not read the head commit"}]
    commit_tree = tree_res.stdout.decode("ascii", "replace").strip()
    trailers = [t for line in msg.stdout.decode("utf-8", "replace").splitlines() if (t := parse_trailer(line)) is not None]
    reruns: List[Mapping[str, Any]] = []

    def attempt(n: int) -> Mapping[str, Any]:
        while len(reruns) <= n:
            reruns.append(rerun_fn(tip, commit_tree))
        return reruns[n]

    results: List[Dict[str, Any]] = []
    for tr in trailers:
        if commit_tree != tr["tree"]:
            verdict = check_ci_divergence(tr, {"tree": commit_tree, "exit": 1})
        else:
            verdict = check_ci_divergence(tr, attempt(0))
            if verdict["result"] == "rerun":
                verdict = check_ci_divergence(tr, attempt(0), attempt(1))
        if verdict["failed"]:
            for c in _of(read_rows(root), "check"):
                if c.get("tree") == tr["tree"] and isinstance(c.get("id"), str):
                    record_void(root, c["id"], "ci_divergence")
        results.append({"commit": tip, "trailer": tr, **verdict})
    return results
