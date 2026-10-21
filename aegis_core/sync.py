"""``aegis sync``: the one writer of derived state (ADR 0005 AD-1, D1, D3)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from aegis_core.fitness import for_rules
from aegis_core.rules import RuleSet, load_rules
from aegis_core.storage import atomic_write_bytes, atomic_write_text, locked, read_json_dict, state_dir
from aegis_core.telemetry_engine import ledger
from aegis_core.workspace import literal_workspace
from aegis_core.workspace.layout import AEGIS_DIRNAME, RULES_RELDIR, WorkspaceLayout

__all__ = ["DERIVED_VERSION", "MOVED_STATUSES", "SyncResult", "build", "format_pr_body", "read_derived", "replay_lines", "stale_rules", "sync"]
DERIVED_VERSION = 1


def _now_iso(now: Optional[datetime]) -> str:
    cur = now or datetime.now(timezone.utc)
    return (cur if cur.tzinfo else cur.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(
    workspace: Any, ruleset: Optional[RuleSet] = None, now: Optional[datetime] = None, view: Any = None,
    *, verify_ci: bool = False,
) -> Dict[str, Any]:
    """The derived document for ``workspace`` (written by ``sync``)."""
    from aegis_core.lifecycle.promotion import suggest
    rules = ruleset if ruleset is not None else load_rules(workspace)
    view = view if view is not None else ledger.read(workspace)
    loaded = [r for r in rules.rules if r.ok]
    fits = for_rules(workspace, loaded, now, view=view, verify_ci=verify_ci)
    entries: Dict[str, Any] = {}
    for rule in loaded:
        fit = fits[rule.id]
        entry: Dict[str, Any] = {
            "path": rule.path, "sha256": rule.digest, "type": rule.type, "fitness": fit.score,
            "reported_score": fit.reported_score, "status": fit.status_label,
            "triggers": fit.triggers, "tp": fit.tp, "fp": fit.fp, "last_ts": fit.last_ts,
            "suggestion": None if not fit.evidence_available else suggest(rule, fit, now), "state": fit.state,
            "evidence_available": fit.evidence_available,
            "effective_weight": fit.effective_weight, "decay_factor": fit.decay_factor,
            "eligible_sessions": fit.eligible_sessions, "contested": fit.contested,
            "override_rate": fit.override_rate, "flagged_for_review": fit.flagged_for_review,
            "archive_candidate": fit.archive_candidate, "caught": fit.caught, "leaked": fit.leaked,
            "adjudicated_n": fit.adjudicated_n, "precision_lo": fit.precision_lo,
            "precision_hi": fit.precision_hi, "sessions_count": fit.sessions_count,
            "repos_count": fit.repos_count, "n": fit.adjudicated_n or int(fit.verdicts),
            "p_below_demote": fit.p_below_demote,
            # Kept empty for an N-1 reader until v4.5: nothing samples labelled rows any more (R-evidence-14).
            "samples": [],
        }
        if fit.evidence_error:
            entry["evidence_error"] = fit.evidence_error
        if fit.prior_disclosure:
            entry["prior_disclosure"] = fit.prior_disclosure
        if rule.expired:
            entry["expired"] = True
        entries[rule.id] = entry
    return {
        "v": DERIVED_VERSION, "norm": "lf", "synced_at": _now_iso(now), "rules": entries,
        "errors": [{"path": r.path, "error": r.error} for r in rules.errors],
        "ignored": [{"path": i.path, "reason": i.reason} for i in rules.ignored],
        "untargeted": [{"id": r.id, "path": r.path} for r in sorted(rules.served, key=lambda r: r.id) if not r.target_paths],
        "ledger": view.health(),
    }


def read_derived(workspace: Any) -> Optional[Dict[str, Any]]:
    """The last derived document, or None when there is none or it cannot be used."""
    path = WorkspaceLayout(Path(literal_workspace(workspace).root)).derived_file
    doc = read_json_dict(path)
    if isinstance(doc, dict) and doc.get("v") == DERIVED_VERSION and isinstance(doc.get("rules"), dict):
        return doc
    return None


def stale_rules(ruleset: RuleSet, derived: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rules edited, added or removed since the last sync: ``[{id, path, change}]``."""
    if derived is None:
        return []
    recorded = derived.get("rules") or {}
    out, current, broken = [], set(), {}
    for rule in ruleset.rules:
        if not rule.ok:
            broken.setdefault(rule.id, rule)
            continue
        current.add(rule.id)
        entry = recorded.get(rule.id)
        if not isinstance(entry, dict):
            out.append({"id": rule.id, "path": rule.path, "change": "new"})
        elif entry.get("path") != rule.path or entry.get("sha256") != rule.digest:
            out.append({"id": rule.id, "path": rule.path, "change": "edited"})
    for rule_id in sorted(set(recorded) - current):
        if rule_id in broken:
            out.append({"id": rule_id, "path": broken[rule_id].path, "change": "unloadable", "error": broken[rule_id].error})
        else:
            entry = recorded[rule_id]
            out.append({"id": rule_id, "path": entry.get("path") if isinstance(entry, dict) else None, "change": "removed"})
    return out


@dataclass
class SyncResult:
    derived: Dict[str, Any]
    path: Path
    applied: List[Dict[str, Any]] = field(default_factory=list)
    refused: Optional[str] = None
    pr: Optional[Dict[str, Any]] = None
    replay: Any = None  # fitness.ReplayReport: what detector replay walked and could not read


def _apply(workspace: Any, derived: Dict[str, Any]) -> List[Dict[str, Any]]:
    from aegis_core.lifecycle.promotion import demote_rule, promote_rule
    from aegis_core.lifecycle.selection import archive_rule
    actions = {
        "promote": lambda rid: promote_rule(workspace, rid, force=True),
        "demote": lambda rid: demote_rule(workspace, rid),
        "archive": lambda rid: archive_rule(workspace, rid),
    }
    applied = []
    for rule_id, entry in sorted(derived["rules"].items()):
        action = entry.get("suggestion")
        if action in actions:
            res = actions[action](rule_id)
            rec = {"rule": rule_id, "action": action, "status": res.get("status")}
            rec.update({k: res[k] for k in ("from_type", "to_type", "target_path", "message") if res.get(k) is not None})
            applied.append(rec)
    return applied


MOVED_STATUSES = frozenset({"promoted", "demoted", "archived"})
_EXAMPLES = 3


def _number_line(e: Mapping[str, Any]) -> List[str]:
    """The numbers a reviewer may weigh: none below the sample minimum (spec T4)."""
    lines = []
    if e.get("reported_score") is not None:
        lines.append(f"- **Score**: {e['reported_score']:.2f}")
    if e.get("state") in ("decided", "inconclusive"):
        lines.append(f"- **P(precision < 0.7)**: {e.get('p_below_demote', 0.0):.2f}; precision 90% interval "
                     f"[{e.get('precision_lo', 0.0):.2f}, {e.get('precision_hi', 1.0):.2f}]")
    return lines


def replay_lines(replay: Any) -> List[str]:
    """What detector replay covered, for the sync output and the PR body."""
    if replay is None or (not replay.branch and not replay.errors and not replay.skipped_reason):
        return []
    if replay.errors:
        return [f"replay UNVERIFIED: {replay.errors[0]}"]
    if replay.skipped_reason and not replay.commits:
        return [] if replay.skipped_reason == "no forbid_ast rule" else [f"replay skipped: {replay.skipped_reason}"]
    walked = f"replay: {replay.commits} commit(s) of {replay.branch} walked"
    if replay.files_skipped:
        walked += f"; {len(replay.files_skipped)} file(s) skipped (replay UNVERIFIED)"
    return [walked, f"commits reachable from {replay.branch} are covered; CI runs are not evaluated"]


def format_pr_body(pre_rules: Dict[str, Dict[str, Any]], applied: List[Dict[str, Any]], *,
                   base: Optional[str] = None, examples: Optional[Mapping[str, List[Dict[str, Any]]]] = None,
                   replay: Any = None) -> str:
    """The evidence for each decided transition: state, n, weight, the numbers the sample size
    allows, the BASE the labels were read at and the examples left for a human to label."""
    lines = [
        "## Aegis Rule Lifecycle Transitions", "",
        "Evidence-backed rule transitions generated by `aegis sync --pr` (human review required; never auto-merged).",
        "score = Wilson lower bound x weight; below the sample minimum no number is shown.",
        *(f"{line[0].upper()}{line[1:]}." for line in replay_lines(replay)), "",
    ]
    for item in applied:
        rid, action = str(item.get("rule", "")), str(item.get("action", ""))
        from_t, to_t = item.get("from_type"), item.get("to_type")
        tier_str = f" (`{from_t}` -> `{to_t}`)" if from_t and to_t else (f" (from `{from_t}`)" if from_t else "")
        e = pre_rules.get(rid, {})
        caught, leaked = int(e.get("caught", 0) or 0), int(e.get("leaked", 0) or 0)
        compliance = f"{caught / (caught + leaked):.2f} ({caught} caught, {leaked} leaked)" if caught + leaked else "n/a"
        lines.extend([
            f"### `{rid}` — **{action}**{tier_str}",
            f"- **State**: {e.get('status') or e.get('state', 'unknown')}; n = {e.get('n', 0)}; "
            f"weight {float(e.get('effective_weight', 1.0)):.2f}",
            *_number_line(e),
            f"- **Breadth**: {e.get('sessions_count', 0)} session(s), {e.get('repos_count', 0)} repo(s)",
            f"- **Contested overrides**: {e.get('contested', 0)} (override rate: {e.get('override_rate', 0.0):.1%})",
            f"- **Compliance** caught / (caught + leaked): {compliance}",
            "- **Censored**: n/a",
            f"- **Labels read at BASE**: {f'`{base}`' if base else 'no BASE'}",
        ])
        if e.get("prior_disclosure"):
            lines.append(f"- **Prior disclosure**: {e['prior_disclosure']}")
        shown = list((examples or {}).get(rid) or [])
        if not shown:
            lines.append("- **Examples to label**: no replay examples")
        else:
            lines.append(f"- **Examples to label** (`verdict: null` in `.aegis/adjudications/{rid}.jsonl`; "
                         "they count for nothing until a human labels them and the label is merged):")
            lines.extend(f"  {idx}. `{x['example_id']}`: `{x.get('pattern')}` in `{x.get('file')}` at `{x.get('rev')}`"
                         for idx, x in enumerate(shown, start=1))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _example_rows(ws: Any, rule_id: str) -> List[Dict[str, Any]]:
    """Up to three of the rule's replay detections, newest first, one per (file, pattern, rev)."""
    from aegis_core import credit

    found: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for row in reversed(credit.read_rows(ws)):
        if row.get("event") != "detection" or row.get("rule") != rule_id:
            continue
        key = (str(row.get("file") or ""), str(row.get("pattern") or ""), str(row.get("rev") or ""))
        if key not in found and len(found) < _EXAMPLES:
            digest = hashlib.sha256("\0".join((rule_id, *key)).encode("utf-8", "surrogatepass")).hexdigest()[:12]
            found[key] = {"example_id": digest, "verdict": None, "file": key[0], "pattern": key[1], "rev": key[2]}
    return list(found.values())


def _write_examples(root: Path, rule_id: str, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Append the rows whose example_id the rule's label file does not hold yet; returns them all."""
    from aegis_core.adjudication import ADJUDICATIONS_DIR, RULE_ID
    from aegis_core.errors import PathTraversalError

    if not rows or not RULE_ID.fullmatch(rule_id):
        return []
    directory = root.joinpath(*ADJUDICATIONS_DIR.split("/"))
    path = directory / f"{rule_id}.jsonl"
    if directory.is_symlink() or directory.parent.is_symlink() or path.is_symlink():
        raise PathTraversalError(f"{ADJUDICATIONS_DIR} is a symlink; refusing to write examples through it")
    existing = path.read_bytes() if path.is_file() else b""
    held = set()
    for line in existing.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            held.add(row.get("example_id"))
    fresh = [r for r in rows if r["example_id"] not in held]
    if fresh:
        directory.mkdir(parents=True, exist_ok=True)
        tail = b"" if not existing or existing.endswith(b"\n") else b"\n"
        added = b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in fresh)
        atomic_write_bytes(path, existing + tail + added)
    return rows


def _default_gh_runner(argv: List[str], cwd: Optional[str] = None) -> Any:
    from aegis_core.human_gate import default_gh_runner
    res = default_gh_runner(argv, None, cwd)
    return res if res is not None else SimpleNamespace(returncode=127, stdout="", stderr="gh is not installed")


# ── sync --pr: one branch, one commit, one push (R-evidence-13) ──────────────

_PR_DIRS = (RULES_RELDIR, f"{AEGIS_DIRNAME}/adjudications")  # the second is adjudication.ADJUDICATIONS_DIR
# The push is the one git call that runs without gitsafe's network fences (it needs the user's
# transport and credentials), so repository config that would make it run a program of the
# repository's choosing, or reach another remote helper, refuses the PR instead.
_PUSH_PROGRAMS = (r"^(core\.(sshcommand|askpass|gitproxy)|credential\..*|protocol\..*|url\..*"
                  r"|remote\..*\.(receivepack|uploadpack|vcs))$")
_PUSH_HARDENING = ("-c", f"core.hooksPath={os.devnull}", "-c", "core.fsmonitor=false", "-c", "core.askPass=",
                   "-c", "protocol.ext.allow=never", "-c", f"gpg.program={os.devnull}")
_PUSH_TIMEOUT = 60.0
_REMOTE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class _Refused(Exception):
    pass


def _lifecycle_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _git(top: str, args: List[str], **kwargs: Any) -> str:
    from aegis_core import gitsafe

    res = gitsafe.run(args, top, **kwargs)
    if res.returncode != 0:
        detail = " ".join((res.stderr or res.stdout).decode("utf-8", "replace").split())[:300]
        raise gitsafe.GitError(f"git {args[0]} failed: {detail}")
    return os.fsdecode(res.stdout.strip())


def _files(root: Path) -> Dict[str, bytes]:
    """Every regular file under .aegis/rules and .aegis/adjudications, by workspace-relative path."""
    found: Dict[str, bytes] = {}
    for rel_dir in _PR_DIRS:
        for folder, dirs, names in os.walk(root / rel_dir):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(folder, d))]
            for name in names:
                path = Path(folder) / name
                if path.is_file() and not path.is_symlink():
                    found[path.relative_to(root).as_posix()] = path.read_bytes()
    return found


def _pr_plan(root: Path) -> Dict[str, Any]:
    """What the PR is cut from; raises _Refused, naming why, before anything moves."""
    from aegis_core import gitevidence, gitsafe

    facts = gitevidence.repo_facts(root)
    if facts is None or facts.top is None or not facts.head:
        raise _Refused("not in a git work tree with a commit")
    top = facts.top
    res = gitsafe.run(["symbolic-ref", "-q", "--short", "HEAD"], top)
    current = os.fsdecode(res.stdout.strip()) if res.returncode == 0 else ""
    protected = gitevidence.protected_branch(facts)
    if not current:
        raise _Refused("HEAD is detached; check out the protected branch first")
    if current != protected:
        raise _Refused(f"HEAD is on {current}, not on the protected branch {protected or '(none found)'}; "
                       "the PR would carry its other commits")
    tree = {path[len(facts.prefix):]: entry for path, entry in gitsafe.tree_blobs(
        top, facts.head, paths=tuple(facts.prefix + d for d in _PR_DIRS)).items()}
    work = _files(root)
    crlf = {rel for rel, data in work.items() if rel in tree and gitsafe.blob_id(data, len(tree[rel][1])) != tree[rel][1]
            and gitsafe.blob_id(data.replace(b"\r\n", b"\n"), len(tree[rel][1])) == tree[rel][1]}
    dirty = sorted(set(work) ^ set(tree) | {r for r in work if r in tree and r not in crlf
                                             and gitsafe.blob_id(work[r], len(tree[r][1])) != tree[r][1]})
    if dirty:
        raise _Refused(f"{' and '.join(_PR_DIRS)} hold uncommitted changes ({dirty[0]}); commit or remove them first")
    remote = os.fsdecode(gitsafe.run(["config", "--get", f"branch.{current}.remote"], top).stdout.strip()) or "origin"
    # The name reaches push argv (repository config chose it): never an option, never this repository.
    url = gitsafe.run(["remote", "get-url", "--push", remote], top) if _REMOTE_NAME.fullmatch(remote) else None
    if url is None or url.returncode != 0 or b"::" in url.stdout:
        raise _Refused(f"no usable remote named {remote!r} to push the branch to")
    programs = gitsafe.run(["config", "--show-scope", "--null", "--name-only", "--get-regexp", _PUSH_PROGRAMS], top)
    if programs.returncode not in (0, 1):
        raise _Refused("git cannot say which config scope sets the push settings (git 2.26 or newer needed)")
    fields = programs.stdout.split(b"\0")
    local = [os.fsdecode(k) for scope, k in zip(fields[0::2], fields[1::2]) if k and scope not in (b"system", b"global", b"command")]
    if local:
        raise _Refused(f"the repository's own config sets {local[0]}, which git push would use; "
                       "remove it or push the branch yourself")
    if gitsafe.run(["var", "GIT_COMMITTER_IDENT"], top).returncode != 0:
        raise _Refused("git has no committer identity (user.name and user.email)")
    return {"top": top, "prefix": facts.prefix, "head": facts.head, "protected": protected, "remote": remote,
            "tree": tree, "crlf": crlf, "files": work}


def _restore(root: Path, before: Dict[str, bytes]) -> None:
    """Put .aegis/rules and .aegis/adjudications back to ``before``, byte for byte."""
    for rel, data in _files(root).items():
        if rel not in before:
            (root / rel).unlink()
            parent = (root / rel).parent
            while parent != root and not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent
        elif data != before[rel]:
            atomic_write_bytes(root / rel, before[rel])
    for rel, data in before.items():
        if not (root / rel).exists():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(root / rel, data)


def _commit(plan: Dict[str, Any], after: Dict[str, bytes], title: str) -> Tuple[str, str]:
    """A branch holding one commit on HEAD: ``after`` against the HEAD tree. Built in a scratch index
    with plumbing, so the user's index, HEAD and work tree are never used and no hook or filter runs."""
    from aegis_core import gitsafe

    top, prefix, head, tree = plan["top"], plan["prefix"], plan["head"], plan["tree"]
    records = []
    for rel in sorted(set(tree) | set(after)):
        if rel not in after:
            records.append(f"0 {'0' * len(head)}\t{prefix}{rel}")
        elif plan["files"].get(rel) != after[rel]:
            data = after[rel].replace(b"\r\n", b"\n") if rel in plan["crlf"] else after[rel]
            mode = tree[rel][0] if rel in tree else "100644"
            records.append(f"{mode} {gitsafe.write_blob(top, data)}\t{prefix}{rel}")
    with tempfile.TemporaryDirectory(prefix="aegis-lifecycle-") as scratch:
        env = {"GIT_INDEX_FILE": os.path.join(scratch, "index")}
        _git(top, ["read-tree", head], _env=env)
        _git(top, ["update-index", "-z", "--index-info"], _env=env,
             stdin=b"".join(os.fsencode(r) + b"\0" for r in records))
        new_tree = _git(top, ["write-tree"], _env=env)
    commit = _git(top, ["commit-tree", new_tree, "-p", head, "--no-gpg-sign", "-m", title])
    base, n = f"aegis/lifecycle-{_lifecycle_stamp()}", 1
    while gitsafe.resolve_commit(top, f"refs/heads/{base if n == 1 else f'{base}-{n}'}"):
        n += 1
    branch = base if n == 1 else f"{base}-{n}"
    _git(top, ["update-ref", f"refs/heads/{branch}", commit, "0" * len(head)])
    return branch, commit


def _open_pr(plan: Dict[str, Any], branch: str, commit: str, title: str, body: str,
             gh_runner: Callable[..., Any], cwd: str) -> Dict[str, Any]:
    from aegis_core import gitsafe

    info: Dict[str, Any] = {"url": None, "branch": branch, "title": title, "body": body}
    top, remote = plan["top"], plan["remote"]
    try:
        _git(top, ["push", "--porcelain", "--no-verify", remote, f"refs/heads/{branch}:refs/heads/{branch}"],
             timeout=_PUSH_TIMEOUT, _hardening=_PUSH_HARDENING)
    except gitsafe.GitError as exc:
        gitsafe.run(["update-ref", "-d", f"refs/heads/{branch}", commit], top)
        return dict(info, status="failed", branch=None, error=f"push to {remote} failed: {exc}")
    res = gh_runner(["pr", "create", "--head", branch, "--base", plan["protected"], "--title", title, "--body", body],
                    cwd=cwd)
    rc = getattr(res, "returncode", 0)
    raw_out, raw_err = getattr(res, "stdout", ""), getattr(res, "stderr", "")
    out_s = (raw_out.decode("utf-8", "replace") if isinstance(raw_out, bytes) else str(raw_out or "")).strip()
    err_s = (raw_err.decode("utf-8", "replace") if isinstance(raw_err, bytes) else str(raw_err or "")).strip()
    if rc == 0:
        return dict(info, status="opened", url=out_s or None)
    return dict(info, status="failed", error=f"{err_s or f'gh exited with status {rc}'} (the branch {branch} was "
                                             f"pushed to {remote} and is kept)")


def sync(
    workspace: Any, apply: bool = False, now: Optional[datetime] = None, *,
    pr: bool = False, gh_runner: Optional[Callable[..., Any]] = None,
    ci_client: Any = None, workflow: Optional[str] = None,
) -> SyncResult:
    """Rebuild derived state under the workspace lock; optionally apply transitions or open a PR.

    ``pr`` never moves a rule in the work tree: the moves and the examples to label go to a new
    ``aegis/lifecycle-*`` branch that is pushed and proposed; nothing is ever merged."""
    from aegis_core import credit, gitsafe
    from aegis_core.fitness import ReplayReport, replay_detector_history_report
    ws = literal_workspace(workspace)
    root = Path(ws.root)
    path = WorkspaceLayout(ws.root).derived_file
    pr_info: Optional[Dict[str, Any]] = None
    examples: Dict[str, List[Dict[str, Any]]] = {}
    moved: List[Dict[str, Any]] = []
    branch = commit = title = None
    plan: Dict[str, Any] = {}
    with locked(ws.root):
        ruleset = load_rules(ws)
        loaded_ok = [r for r in ruleset.rules if r.ok]
        try:
            replay = replay_detector_history_report(ws.root, loaded_ok)
        except (gitsafe.GitError, OSError, ValueError) as exc:  # partial evidence is said, never fatal
            replay = ReplayReport([], errors=(str(exc) or type(exc).__name__,))
        if ci_client is not None or any(r.get("event") == "report" for r in credit.read_rows(ws.root)):
            credit.confirm(
                ws.root,
                client=ci_client if ci_client is not None else credit.GhRestClient(cwd=str(ws.root)),
                workflow=workflow,
            )
        derived = build(ws, ruleset, now, ledger.read(ws), verify_ci=True)
        missing = ledger.incomplete(derived["ledger"])
        applied, refused = [], None
        pre_rules = {rid: dict(entry) for rid, entry in derived["rules"].items()}
        pending = any(e.get("suggestion") in ("promote", "demote", "archive") for e in derived["rules"].values())
        if (apply or pr) and ruleset.errors:
            refused = "not applied: rule files cannot be loaded: " + ", ".join(r.path for r in ruleset.errors)
        elif (apply or pr) and missing:
            refused = f"not applied: the ledger is incomplete ({missing}); fitness and suggestions are computed over partial evidence"
        elif pr and pending:
            try:
                plan = _pr_plan(root)
            except (_Refused, gitsafe.GitError, OSError) as exc:
                refused = f"no pull request opened: {exc}"
            else:
                try:
                    applied = _apply(ws, derived)
                    moved = [a for a in applied if a.get("status") in MOVED_STATUSES]
                    examples = {a["rule"]: _write_examples(root, a["rule"], _example_rows(ws.root, a["rule"]))
                                for a in moved}
                    after = _files(root)
                finally:
                    _restore(root, plan["files"])  # the user's tree holds exactly what it held
                if moved:
                    title_rules = ", ".join(a["rule"] for a in moved[:3]) + (f" (+{len(moved) - 3} more)" if len(moved) > 3 else "")
                    title = f"chore(aegis): lifecycle transitions for {title_rules}"
                    try:
                        branch, commit = _commit(plan, after, title)
                    except (gitsafe.GitError, OSError) as exc:
                        pr_info = {"status": "failed", "url": None, "branch": None, "error": f"cannot make the branch: {exc}",
                                   "transitions": moved}
        elif apply:
            applied = _apply(ws, derived)
            if applied:
                derived = build(ws, load_rules(ws), now, verify_ci=True)
        state_dir(ws.root)
        atomic_write_text(path, json.dumps(derived, indent=2, sort_keys=True) + "\n")
    if pr and pr_info is None:
        if refused:
            pr_info = {"status": "refused", "url": None, "reason": refused, "transitions": []}
        elif branch is None:
            pr_info = {"status": "no_transitions", "url": None, "body": "", "transitions": []}
        else:
            from aegis_core.rule_integrity import resolve_base

            anchor = resolve_base(ws.root)
            # Labels count only at a review-witnessed BASE (aegis_core.adjudication).
            reviewed = anchor.commit if anchor is not None and anchor.witnessed else None
            body = format_pr_body(pre_rules, moved, base=reviewed, examples=examples, replay=replay)
            pr_info = dict(_open_pr(plan, branch, commit, title, body, gh_runner or _default_gh_runner, str(ws.root)),
                           transitions=moved)
    return SyncResult(derived=derived, path=path, applied=applied, refused=refused, pr=pr_info, replay=replay)
