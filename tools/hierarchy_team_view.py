"""ROOT's read model of a team: what ROOT owes a decision on, where the team stands, and a draft of a new request.

ROOT's MCP tools (team_pending, team_status and team_request in hierarchy_mailbox_mcp.py) and the team CLI call
these functions, so both read one JSON contract. The journal is read under its own lock with
hierarchy_router.locked_load, because the unlocked Lifecycle.load can meet a half-published entry and fail. The
loop's status.json is read with hierarchy_loop.read_status and the evidence folder is listed. Nothing here writes a
file or starts a process: a draft is text for the coordinator to publish.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import hierarchy_lifecycle  # noqa: E402
import hierarchy_router  # noqa: E402
from hierarchy_mailbox import SLUG, digest, encoded, parse_time, require, safe_path, timestamp  # noqa: E402


PENDING = "aegis.team-pending/v1"
STATUS = "aegis.team-status/v1"
DRAFT = "aegis.team-request/v1"
WAIT_SECONDS = 2.0
ACTS = ("root", "owner", "router")
OWED = ("awaiting_decision", "escalated")
# The loop's own rule for a stale status file: no pass finished and no step began within three intervals.
STALE_FACTOR = 3


def event_id(prefix, request_id, sha256, suffix=None):
    """<prefix>-<request id>[-<suffix>]. An event id is a slug of at most 80 characters, so a request id too long
    for that takes the request hash's first 32 characters instead."""
    identifier = "-".join(part for part in (prefix, request_id, suffix) if part)
    return identifier if SLUG.fullmatch(identifier) else "-".join(part for part in (prefix, sha256[:32], suffix) if part)


def standing(state, key, row, at):
    """Where one request stands on the journal alone.

    A Decider's escalation leaves the request without a ROOT decision, which the Router reads as awaiting_decision,
    so the delegated decision is read before that. The journal refuses a delegated decision once ROOT has decided,
    so a ROOT decision on an escalated request always came after the escalation."""
    value = row["request"]
    if value["authority"] != key:
        # A continuation member is named in its authority's bytes and never takes a decision of its own.
        return "continuation_member"
    if row["routed"] is not None:
        return "routed"
    if row["resolution"] and row["resolution"]["kind"] in {"complete", "next"}:
        return "closed"
    decision = hierarchy_router.last_decision(state, key)
    if decision is None:
        delegated = [entry["decision"] for entry in state.get("delegated_decisions", []) if entry["request_id"] == key]
        if delegated:
            return "escalated" if delegated[-1] == "escalate" else "delegated_approved"
        return "awaiting_decision"
    if decision == "deny":
        return "denied"
    if value["operation"] == "delegate-merge":
        return "delegation"
    if parse_time(at) >= parse_time(value["continuation"]["expires_at"]):
        return "approval_expired"
    return "approved"


def owed_row(key, row, escalation):
    value, sha256 = row["request"], row["raw"]["sha256"]
    entry = {"request_id": key, "request_sha256": sha256, "team": value["team"], "operation": value["operation"],
             "phase": value["phase"], "owner": value["owner"], "paths": value["paths"], "source": value["source"],
             "why": "escalated" if escalation else "awaiting_decision",
             "root_decide": {"request_id": key, "request_sha256": sha256,
                             "event_id_approve": event_id("root", key, sha256, "approve"),
                             "event_id_deny": event_id("root", key, sha256, "deny")}}
    if escalation:
        entry.update(delegation_id=escalation["delegation_id"], escalation_reason=escalation["reason"])
    return entry


def owed(state, at):
    escalations = {row["request_id"]: row for row in hierarchy_router.escalations(state)}
    rows = []
    for key, row in sorted(state["requests"].items()):
        stage = standing(state, key, row, at)
        if stage in OWED:
            rows.append(owed_row(key, row, escalations[key] if stage == "escalated" else None))
    return rows


def pending(lifecycle, wait=WAIT_SECONDS):
    """aegis.team-pending/v1: one row per request ROOT owes a decision on, with the root_decide arguments for it.
    lifecycle is a hierarchy_lifecycle.Lifecycle."""
    _policy, state = hierarchy_router.locked_load(lifecycle, wait)
    return {"schema": PENDING, "pending": owed(state, timestamp()), "execution_enabled": False}


def loop_view(state_dir):
    """The loop's last report and its hold rows.

    A status file shows what the loop last wrote, not that it still runs (`hierarchy_loop.py status` checks the
    instance lock). A step that outlasts three intervals reads stale here too, so the step and its start are given.
    A single pass has no interval and is never stale."""
    # Imported only when a loop folder is configured: the loop module loads the job tool's modules with it, and
    # ROOT's decisions and pending reads need none of them.
    import hierarchy_loop
    last = hierarchy_loop.read_status(safe_path(state_dir))
    if last is None:
        return {"state": "absent", "pass_id": None, "finished_at": None, "current_step": None, "step_started_at": None,
                "interval": None}, []
    beats = [parse_time(last[field]) for field in ("finished_at", "step_started_at") if last.get(field)]
    interval = last.get("interval")
    stale = bool(interval) and (not beats or datetime.now(timezone.utc) - max(beats) >
                                timedelta(seconds=STALE_FACTOR * interval))
    return {"state": "stale" if stale else "fresh", "pass_id": last["pass_id"], "finished_at": last.get("finished_at"),
            "current_step": last.get("current_step"), "step_started_at": last.get("step_started_at"),
            "interval": interval}, last["holds"]


def evidence_view(folder):
    """How many files the evidence folder holds and how many its SHA256SUMS lists. `down` writes SHA256SUMS last, so
    a running team usually has none. Symbolic links are neither counted nor followed."""
    folder = safe_path(folder)
    view = {"directory": str(folder), "present": folder.is_dir(), "files": 0, "sha256sums": None, "listed": None}
    if not view["present"]:
        return view
    for directory, _folders, names in os.walk(folder):
        paths = [Path(directory) / name for name in names]
        view["files"] += sum(1 for path in paths if path.is_file() and not path.is_symlink())
    sums = folder / "SHA256SUMS"
    if sums.is_file() and not sums.is_symlink():
        with sums.open("rb") as stream:
            view["listed"] = sum(1 for line in stream if line.strip())
        view["sha256sums"] = str(sums)
    return view


def status(lifecycle, loop_state=None, evidence=None, wait=WAIT_SECONDS):
    """aegis.team-status/v1. loop and evidence are null when no folder is given; the rest is the journal's."""
    _policy, state = hierarchy_router.locked_load(lifecycle, wait)
    at = timestamp()
    loop, holds = loop_view(loop_state) if loop_state is not None else (None, [])
    holds_by_act = {act: [] for act in ACTS}
    for row in holds:
        holds_by_act.setdefault(row["act"], []).append(row)
    delegated = [{"request_id": entry["request_id"], "request_sha256": entry["request_sha256"],
                  "delegation_id": entry["delegation_id"], "decision": entry["decision"], "reason": entry["reason"],
                  "actor": entry["actor"], "at": entry["at"],
                  "root_decision": hierarchy_router.last_decision(state, entry["request_id"])}
                 for entry in state.get("delegated_decisions", [])]
    return {"schema": STATUS, "loop": loop, "holds_by_act": holds_by_act,
            "pending": [row["request_id"] for row in owed(state, at)],
            "requests": [{"request_id": key, "state": standing(state, key, row, at)}
                         for key, row in sorted(state["requests"].items())],
            "delegated_decisions": delegated, "evidence": None if evidence is None else evidence_view(evidence),
            "execution_enabled": False}


def draft_request(lifecycle, request, coordinator=None, wait=WAIT_SECONDS):
    """aegis.team-request/v1: the canonical request text, its sha256 and the exact publish event for the coordinator
    to record. request is the request's fields; the schema is added. coordinator defaults to the journal's current one.

    The journal's own reduction runs on a copy of its state, so a draft meets every check a publish meets (the
    request rules, the coordinator's role, custody and cap, an id already used for other bytes) and nothing is
    written."""
    require(isinstance(request, dict), "expected a JSON object")
    value = {"schema": hierarchy_lifecycle.REQUEST, **request}
    raw = encoded(value).decode("utf-8")
    sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    body = {"raw": raw, "sha256": sha256}
    hierarchy_lifecycle.validate_request(body)
    policy, state = hierarchy_router.locked_load(lifecycle, wait)
    cid = state["current"]["coordinator"] if coordinator is None else coordinator
    actor = policy["actors"].get(cid) if isinstance(cid, str) else None
    require(actor is not None and actor["role"] == "coordinator",
            "actor %s is not a coordinator actor in the lifecycle policy" % str(cid)[:64])
    root = state["current"]["root"]
    envelope = {"id": event_id("publish", value["id"], sha256), "actor": cid, "generation": actor["generation"],
                "custody": {"cid": root, "generation": policy["actors"][root]["generation"]},
                "event": {"type": "publish", "request": body}}
    previous = state["receipts"].get(envelope["id"])
    if previous is None:
        hierarchy_lifecycle.reduce_event(policy, copy.deepcopy(state), envelope, timestamp())
    else:
        # As the journal answers a repeated event: the same bytes return the receipt, other bytes are refused.
        require(previous["event_sha256"] == digest(envelope), "event id conflicts with different bytes")
    return {"schema": DRAFT, "request_id": value["id"], "raw": raw, "sha256": sha256, "event": envelope,
            "published": value["id"] in state["requests"]}
