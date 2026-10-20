"""The credit state machine (v4.3 spec §3 T1, T4): what a ``check`` row is worth, derived on read."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aegis_core import gitsafe, human_gate
from aegis_core.errors import AegisError, PathTraversalError
from aegis_core.storage import ledger_locked, read_jsonl
from aegis_core.telemetry_engine import ledger

__all__ = [
    "EVENTS", "MAX_REPORT_ROWS_PER_SESSION", "CIUnavailable", "Credit", "CreditProjection",
    "GhRestClient", "ReportConflict", "approval_lookup", "check_ci_divergence", "claimed_summary",
    "confirm", "confirmed_outcome_rows", "derive", "exposed_rules", "format_trailer",
    "landed_lookup", "parse_trailer", "passing_check", "project_credits", "read_rows",
    "record_adjudication", "record_detection", "record_exposure", "record_override",
    "record_void", "resolve_protected_branch", "select_ci_run", "session_exposed_rules", "submit_report",
    "verify_commit_trailers", "witnessed_exposed_rules",
]
EVENTS = ("check", "claimed", "report", "ci", "void", "exposure", "detection", "adjudication", "override")
MAX_REPORT_ROWS_PER_SESSION = 200
CI_EVENTS = ("push", "workflow_dispatch", "release")
CI_FAILED = ("failure", "timed_out", "startup_failure")
DEFAULT_WORKFLOW = "validate.yml"
_RESULT = {"success": "tp", "tp": "tp", "pass": "tp", "failure": "fp", "fp": "fp", "fail": "fp", "partial": "trigger"}
_FULL_SHA = re.compile(r"[0-9a-f]{40,64}")
_TRAILER = re.compile(r"\s*Aegis-Check:\s*tree=([0-9a-f]{40,64})\s+exit=(-?\d+)\s*")
_REV_LIMIT = 5000
_VERIFIED_CI: Dict[Tuple[str, str], Dict[str, Any]] = {}
_UNAVAILABLE_CI: Set[Tuple[str, str]] = set()
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


def _read_ledger_events(root: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        res = read_jsonl(ledger.ledger_path(root))
    except (PathTraversalError, OSError) as exc:
        return [], str(exc)
    err = res.error or (f"{len(res.skipped_lines)} unreadable line(s)" if res.skipped_lines else None)
    rows = [_normalize_event_row(r) for r in res.rows if isinstance(r, dict) and r.get("v") == ledger.LEDGER_VERSION and r.get("event") in EVENTS]
    return rows, err


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


def _sign(claimed: Any, check: Mapping[str, Any]) -> str:
    """Spec T4: a report confirms a passed check as tp or withdraws to a trigger, never fp. The
    stored ``result`` stays the agent's claim (ReportConflict compares it); only the read is signed."""
    return "tp" if claimed == "tp" and _passed(check) else "trigger"


def passing_check(rows: Iterable[Mapping[str, Any]], tree: Optional[str]) -> Optional[Mapping[str, Any]]:
    if not tree:
        return None
    best = None
    for row in _of(rows, "check"):
        if row.get("tree") == tree and row.get("witness") == "aegis" and _passed(row) and isinstance(row.get("id"), str):
            best = row
    return best


def _workflow_path(run: Mapping[str, Any]) -> str:
    return str(run.get("path") or "").split("@", 1)[0]


def resolve_protected_branch(root: Any) -> Optional[str]:
    top = gitsafe.toplevel(Path(str(root)))
    if top is None:
        return None
    sym = gitsafe.run(["symbolic-ref", "-q", "refs/remotes/origin/HEAD"], top)
    if sym.returncode == 0:
        target = sym.stdout.decode("utf-8", "replace").strip()
        if target.startswith("refs/remotes/origin/"):
            branch = target[len("refs/remotes/origin/"):].strip()
            if branch and branch != "HEAD":
                return branch
    for cand in ("main", "master"):
        if gitsafe.resolve_commit(top, f"refs/remotes/origin/{cand}") or gitsafe.resolve_commit(top, f"refs/heads/{cand}"):
            return cand
    return None


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
    top = gitsafe.toplevel(Path(str(root)))
    entries: Optional[List[Tuple[str, str]]] = None

    def load() -> List[Tuple[str, str]]:
        if top is None:
            return []
        if refs is None:
            branch = resolve_protected_branch(top)
            target_refs: Sequence[str] = (f"refs/remotes/origin/{branch}", f"refs/heads/{branch}") if branch else ()
        else:
            target_refs = refs
        resolved = [r for r in target_refs if gitsafe.resolve_commit(top, r)]
        if not resolved:
            return []
        res = gitsafe.run(["rev-list", f"--max-count={limit}", "--format=%T", *resolved], top)
        if res.returncode != 0:
            return []
        out: List[Tuple[str, str]] = []
        commit = None
        for line in res.stdout.decode("ascii", "replace").splitlines():
            if line.startswith("commit "):
                commit = line.split()[1]
            elif commit and line.strip():
                out.append((commit, line.strip()))
                commit = None
        return out

    def lookup(tree: str, head: Optional[str] = None) -> Optional[str]:
        nonlocal entries
        if entries is None:
            entries = load()
        for commit, commit_tree in entries:
            if commit_tree != tree:
                continue
            if head and top is not None and gitsafe.run(["merge-base", "--is-ancestor", head, commit], top).returncode != 0:
                continue
            return commit
        return None

    setattr(lookup, "_aegis_root", _canon_root(root))
    return lookup


_EXPOSED: Dict[Tuple[str, str, str], Set[str]] = {}
_MAX_EXPOSED_SESSIONS = 256


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_exposure(
    root: Any, host: Optional[str], session: Optional[str], rules: Iterable[str], *,
    paths: Optional[Iterable[str]] = None, rev: Optional[str] = None, scope_basis: Optional[str] = None,
    heartbeat: Optional[bool] = None, ts: Optional[str] = None, persist: bool = True,
) -> List[Dict[str, Any]]:
    rule_list = [r for r in dict.fromkeys(rules) if isinstance(r, str) and r]
    key = (str(root), host or "", session or "")
    if key not in _EXPOSED and len(_EXPOSED) >= _MAX_EXPOSED_SESSIONS:
        _EXPOSED.pop(next(iter(_EXPOSED)))
    _EXPOSED.setdefault(key, set()).update(rule_list)
    if not persist or not rule_list:
        return []
    stamp, s_id, h_id = ts or _now(), session or "", host or ""
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
                "rev": rev,
            }
            if scope_basis is not None:
                row["scope_basis"] = str(scope_basis)
            if heartbeat is not None:
                row["heartbeat"] = bool(heartbeat)
            to_append.append(row)
        return [_normalize_event_row(r) for r in ledger.append_rows(root, to_append)] if to_append else []


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
    if disposition not in ("caught", "leaked"):
        raise ValueError(f"disposition must be 'caught' or 'leaked', got {disposition!r}")
    eff_weight = float(weight) if weight is not None else (0.5 if disposition == "caught" else 1.0)
    b_name = branch or "main"
    with ledger_locked(root):
        latest = None
        for ex in _of(read_rows(root), "detection"):
            if (ex.get("rule") or ex.get("for_rule")) == rule and ex.get("file") == file and ex.get("pattern") == pattern and (ex.get("branch") or "main") == b_name:
                latest = ex
        if (latest is not None and latest.get("disposition") == disposition and latest.get("rev") == rev
                and latest.get("fix_rev") == fix_rev and float(latest.get("weight") or 0.0) == eff_weight):
            return _normalize_event_row(latest)
        row = {
            "v": ledger.LEDGER_VERSION,
            "ts": ts or _now(),
            "event": "detection",
            "rule": rule,
            "file": file,
            "pattern": pattern,
            "disposition": disposition,
            "branch": b_name,
            "rev": rev,
            "fix_rev": fix_rev,
            "weight": eff_weight,
        }
        return _normalize_event_row(ledger.append_rows(root, [row])[0])


def record_adjudication(
    root: Any, rule: str, verdict: str, *, adjudicator: str = "human", ref: Optional[str] = None,
    summary: Optional[str] = None, file: Optional[str] = None, line: Optional[int] = None,
    snippet: Optional[str] = None, session: Optional[str] = None, repo: Optional[str] = None, ts: Optional[str] = None,
) -> Dict[str, Any]:
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


def confirm(
    root: Any, *, client: Any, workflow: str = DEFAULT_WORKFLOW,
    landed: Optional[Callable[..., Optional[str]]] = None, branch: Optional[str] = None,
) -> Dict[str, Any]:
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
        if counts and check.get("protected_changed") and not (approved and approved(identity[0], categories)):
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


def approval_lookup(
    root: Any, rows: Sequence[Mapping[str, Any]], landed: Optional[Callable[..., Optional[str]]] = None,
) -> Callable[[str, Sequence[str]], bool]:
    top = gitsafe.toplevel(Path(str(root)))
    look = landed or landed_lookup(root)
    checks = {r["id"]: r for r in _of(rows, "check") if isinstance(r.get("id"), str)}
    cache: Dict[str, bool] = {}

    def is_approved(check_id: str, _categories: Sequence[str] = ()) -> bool:
        if check_id in cache:
            return cache[check_id]
        check = checks.get(check_id)
        if top is None or check is None:
            cache[check_id] = False
            return False
        commit = _call_landed(look, str(check.get("tree") or ""), check.get("head"))
        base_ref = str(check.get("base") or "") or gitsafe.resolve_base_ref(top) or "main"
        if not commit:
            cache[check_id] = False
            return False
        try:
            gov_hash = human_gate.governance_tree_hash(top, commit)
            p_branch = resolve_protected_branch(top)
            tips = [commit] + ([f"refs/heads/{p_branch}", f"refs/remotes/origin/{p_branch}"] if p_branch else []) + ["HEAD"]
            ok = any(
                (app := human_gate.find_approval(top, tip, base_ref, governance_hash=gov_hash)) is not None and app.valid
                for tip in dict.fromkeys(tips)
            )
        except Exception:
            ok = False
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


_DEFAULT_SNAPSHOT_RERUN: Optional[Callable[[Any, str, str], Mapping[str, Any]]] = None


def project_credits(
    root: Any, *, view: Any = None, client: Any = None, workflow: str = DEFAULT_WORKFLOW,
    attestation_runner: Optional[Callable[..., Any]] = None,
    landed: Optional[Callable[..., Optional[str]]] = None,
    approved: Optional[Callable[[str, Sequence[str]], bool]] = None,
    verify_ci: bool = False,
) -> CreditProjection:
    from aegis_core import release_verify
    c_root = _canon_root(root)
    look = landed or landed_lookup(root)
    if landed is not None:
        try:
            setattr(landed, "_aegis_root", c_root)
        except AttributeError:
            pass
    if client is not None:
        confirm(root, client=client, workflow=workflow, landed=look)
    rows, read_err = _read_ledger_events(root)
    view_err = getattr(view, "incomplete", None) if view is not None else None
    err = view_err or read_err
    if err:
        return CreditProjection((), (), available=False, error=str(err))
    v_map: Dict[str, str] = {}
    stopped: Optional[str] = None
    # Read paths (scan, status, list) pass verify_ci=False and stay offline: a ``ci`` row then counts
    # only when this process verified it, so they can under-credit but never over-credit.
    if verify_ci:
        rest_client = GhRestClient(cwd=str(root)) if (client is None and attestation_runner is None) else None
        latest = {str(r.get("commit") or ""): r for r in _of(rows, "ci")}
        pending = [(commit, ci_row) for commit, ci_row in latest.items()
                   if commit and (c_root, commit) not in _UNAVAILABLE_CI
                   and not _ci_cache_current(_VERIFIED_CI.get((c_root, commit)), ci_row)]
        # The workflow is the caller's and the branch GitHub's: a ci row's ``workflow`` is display only.
        p_branch: Optional[str] = None
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
            if ci_row.get("ci_conclusion") == "success":
                rid, ratt = ci_row.get("run_id"), ci_row.get("ci_run_attempt")
                exp_run = f"{rid}/{ratt}" if rid is not None and ratt is not None else None
                rep = release_verify.verify_release(
                    root, commit, run=attestation_runner,
                    source_ref=f"refs/heads/{p_branch}", workflow=f".github/workflows/{workflow}", expected_run=exp_run,
                )
                if rep.verified:
                    v_map[commit] = "success"
                    _VERIFIED_CI[(c_root, commit)] = {"conclusion": "success", "workflow": workflow, "branch": p_branch, "run_id": rid, "run_attempt": ratt}
                    continue
            # Circuit breaker: a dead gh costs one attempt per projection. Only a well-formed id trips
            # it, so one malformed (never-asked) row cannot switch verification off for the rest.
            # Tripping makes the projection unavailable: verify_ci callers decide (promote, demote,
            # archive), and under-credited fitness must not drive those decisions.
            if rest_client is not None and _FULL_SHA.fullmatch(commit):
                stopped = (f"CI verification stopped after gh failed for {commit[:12]}; "
                           f"{len(pending) - idx} commit(s) were not verified")
                break
    app_fn = approved or approval_lookup(root, rows, landed=look)
    derived = derive(rows, landed=look, approved=app_fn, verified_ci=v_map or None)
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


def claimed_summary(root: Any) -> Dict[str, Any]:
    claims = _of(read_rows(root), "claimed")
    return {"label": "claimed (unwitnessed)", "claimed": len(claims), "sessions": len({(c.get("host"), c.get("session")) for c in claims})}


def format_trailer(tree: str, exit_code: int) -> str:
    return f"Aegis-Check: tree={tree} exit={exit_code}"


def parse_trailer(line: str) -> Optional[Dict[str, Any]]:
    found = _TRAILER.fullmatch(line.strip("\r\n")) if isinstance(line, str) else None
    return {"tree": found.group(1), "exit": int(found.group(2))} if found else None


def check_ci_divergence(trailer: Any, rerun: Mapping[str, Any], second: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    given = parse_trailer(trailer) if isinstance(trailer, str) else (dict(trailer) if isinstance(trailer, Mapping) else None)
    if not given or not given.get("tree") or "exit" not in given:
        return {"result": "unbound", "failed": False, "reason": "no usable Aegis-Check trailer"}
    first = dict(rerun) if isinstance(rerun, Mapping) else {}
    if first.get("tree") != given["tree"]:
        return {"result": "unbound", "failed": False, "reason": "CI ran a different tree"}
    claimed_pass = given["exit"] == 0
    if (first.get("exit") == 0) == claimed_pass:
        return {"result": "agree", "failed": False, "reason": ""}
    if second is None:
        return {"result": "rerun", "failed": False, "reason": "outcomes diverge on the same tree"}
    again = dict(second)
    if again.get("tree") == given["tree"] and (again.get("exit") == 0) == claimed_pass:
        return {"result": "agree", "failed": False, "reason": "flaky: the re-run agrees with the trailer"}
    return {"result": "void", "failed": True, "reason": "outcomes still diverge on the same tree after a re-run"}


def verify_commit_trailers(
    root: Any, base: str, head: str = "HEAD", *, rerun_fn: Callable[[str, str], Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    top = gitsafe.toplevel(Path(str(root)))
    if top is None:
        return []
    mb, tip = gitsafe.merge_base(top, base, head), gitsafe.resolve_commit(top, head)
    if not mb or not tip:
        return []
    rev = gitsafe.run(["rev-list", "--reverse", f"{mb}..{tip}"], top)
    if rev.returncode != 0:
        return []
    rows = read_rows(root)
    checks_by_tree: Dict[str, List[Mapping[str, Any]]] = {}
    for chk in _of(rows, "check"):
        if isinstance(chk.get("tree"), str):
            checks_by_tree.setdefault(chk["tree"], []).append(chk)
    results: List[Dict[str, Any]] = []
    for oid in rev.stdout.decode("ascii", "replace").split():
        msg = gitsafe.run(["log", "-1", "--format=%B", oid], top).stdout.decode("utf-8", "replace")
        commit_tree = gitsafe.run(["rev-parse", f"{oid}^{{tree}}"], top).stdout.decode("ascii", "replace").strip()
        trailers = [t for line in msg.splitlines() if (t := parse_trailer(line)) is not None]
        for tr in trailers:
            t_checks = checks_by_tree.get(tr["tree"], [])
            if commit_tree != tr["tree"]:
                verdict = check_ci_divergence(tr, {"tree": commit_tree, "exit": 1})
            else:
                first = rerun_fn(oid, commit_tree)
                verdict = check_ci_divergence(tr, first)
                if verdict["result"] == "rerun":
                    verdict = check_ci_divergence(tr, first, rerun_fn(oid, commit_tree))
            if verdict["failed"]:
                for c in t_checks:
                    if isinstance(c.get("id"), str):
                        record_void(root, c["id"], "ci_divergence")
            results.append({"commit": oid, "trailer": tr, **verdict})
    return results
