#!/usr/bin/env python3
"""Route ROOT-approved canonical requests from the lifecycle journal to the team's orchestrator.

The Router routes and reports; it never approves or executes. This code is the model-free half: it reads
the journal, finds authority requests whose last ROOT decision is an unexpired approve and that have not
been routed, and delivers each to `<team>/orchestrator` in that team's mailbox. The Router role session is
the voice: it reads `status` and tells ROOT about anything held.

The team registry is the workspace initiative ledger. A request's `team` names an active initiative, and
that initiative's `mailbox_root` holds the team's endpoints. The message goes out under the current
binding of `<team>/router`, borrowed the way the job runner borrows ROOT's, so the item-2 fence applies.

Deduplication is by request hash. The message ID and the journal event ID are both `route-<sha256>`, so a
second run finds the earlier message and records nothing new, and a run that delivered but lost its journal
write is finished by the next run without a second message. A routed request is never routed again, even
if ROOT later denies it; status reports that as `revoked_after_route` for the Router to raise.

The journal accepts a `route` event from the router actor without checking approval. This code is where
that check lives at this tier. The router actor and the borrowed binding are configuration, not
authenticated identities, so mutation needs --evidence-only, as the journal's own CLI does.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_lifecycle import Lifecycle  # noqa: E402
from hierarchy_mailbox import (Mailbox, cli_path, encoded, matching, parse_time, require, SLUG,  # noqa: E402
                               timestamp, writer_lock)
from hierarchy_workspace import Store  # noqa: E402


STATUS = "aegis.router-status/v1"
RUN = "aegis.router-run/v1"
ROUTED = "aegis.routed-request/v1"
MAX_BODY = 65536
EVIDENCE_ONLY = "routing requires --evidence-only; the router is configuration-bound and unauthenticated"


def route_id(sha256):
    return "route-" + sha256


def route_body(request_id, raw):
    """The orchestrator gets the exact canonical bytes and their hash, so it can check what was approved."""
    return encoded({"schema": ROUTED, "request_id": request_id, "request_sha256": raw["sha256"],
                    "request": {"raw": raw["raw"], "sha256": raw["sha256"]}}).decode("utf-8")


def patient(action, wait):
    """Both writer locks fail fast by design. A moment's contention should not hold a request."""
    deadline = time.monotonic() + wait
    while True:
        try:
            return action()
        except ValueError as exc:
            if "busy" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def locked_load(lifecycle, wait):
    """Read under the journal's lock. A lock-free read can meet a half-published entry and fail."""
    def attempt():
        with writer_lock(lifecycle.root):
            return lifecycle.load()
    return patient(attempt, wait)


def last_decision(state, identifier):
    decisions = [d for d in state["decisions"] if d["request_id"] == identifier]
    return decisions[-1]["decision"] if decisions else None


def decision_state(state, row, at):
    """Where a request stands on the journal alone: None means approved, live and not yet routed."""
    value = row["request"]
    decision = last_decision(state, value["id"])
    if row["routed"] is not None:
        return "routed", None
    resolution = row["resolution"]
    if resolution and resolution["kind"] in {"complete", "next"}:
        return "closed", None
    if decision is None:
        return "awaiting_decision", None
    if decision == "deny":
        return "denied", None
    if parse_time(at) >= parse_time(value["continuation"]["expires_at"]):
        return "held", "approval_expired"
    return None, None


def team_mailbox(ledger, team):
    """Return (mailbox_root, reason). The initiative ledger is the team registry."""
    initiative = ledger.initiatives.get(team)
    if initiative is None:
        return None, "team_unregistered"
    if initiative["state"] != "active":
        return None, "team_inactive"
    if "mailbox_root" not in initiative:
        return None, "team_has_no_mailbox"
    return initiative["mailbox_root"], None


def endpoint_reason(mailbox, team):
    """Why the team mailbox cannot take a routed request now, or None. Every write re-checks under the lock."""
    endpoints = mailbox.manifest["endpoints"]
    sender, recipient = team + "/router", team + "/orchestrator"
    if sender not in endpoints:
        return "router_endpoint_missing"
    if recipient not in endpoints:
        return "orchestrator_endpoint_missing"
    if not mailbox.bindings(sender):
        return "router_unbound"
    if not mailbox.bindings(recipient):
        return "orchestrator_unbound"
    if not mailbox.ready(mailbox.current_binding(sender)):
        return "router_handoff_unacknowledged"
    return None


def expected_message(team, key, raw):
    return {"from": team + "/router", "to": team + "/orchestrator", "type": "info", "body": route_body(key, raw)}


def same_delivery(prior, expected):
    """A stable ID alone is not this delivery. A successor router binding may have sent the original."""
    return all(prior.get(key) == value for key, value in expected.items())


def message_reason(mailbox, team, key, raw):
    """A message already under this request's route ID must be this exact delivery."""
    prior = mailbox.messages().get(route_id(raw["sha256"]))
    if prior is not None and not same_delivery(prior["message"], expected_message(team, key, raw)):
        return "route_message_conflict"
    return None


def authority_rows(state):
    # Continuation members travel inside their authority request; only the authority gets a ROOT decision.
    return sorted((key, row) for key, row in state["requests"].items() if row["request"]["authority"] == key)


def row_view(state, key, row, ledger, at):
    value = row["request"]
    view = {"request_id": key, "request_sha256": row["raw"]["sha256"], "team": value["team"],
            "orchestrator": value["team"] + "/orchestrator"}
    stage, reason = decision_state(state, row, at)
    if stage == "routed":
        view.update(state="routed", to=row["routed"]["to"], routed=row["routed"],
                    revoked_after_route=last_decision(state, key) == "deny")
        return view
    if stage is None:
        root, reason = team_mailbox(ledger, value["team"])
        if reason is None:
            try:
                mailbox = Mailbox(root)
                reason = endpoint_reason(mailbox, value["team"]) or message_reason(mailbox, value["team"], key, row["raw"])
            except (ValueError, OSError, UnicodeError) as exc:
                reason, view["detail"] = "team_mailbox_unreadable", str(exc)[:1024]
        stage = "ready" if reason is None else "held"
    view["state"] = stage
    if reason is not None:
        view["reason"] = reason
    return view


def report(lifecycle, store, wait, held=None):
    _policy, state = locked_load(lifecycle, wait)
    ledger = store.load()
    at = timestamp()
    rows = []
    for key, row in authority_rows(state):
        view = row_view(state, key, row, ledger, at)
        if held and key in held and view["state"] == "ready":
            # A delivery attempt this run failed after the checks passed; say so instead of "ready".
            view.update(state="held", **held[key])
        rows.append(view)
    return rows


def status(lifecycle, store, wait):
    return {"schema": STATUS, "execution_enabled": False, "identity": "configured", "authenticated": False,
            "requests": report(lifecycle, store, wait)}


def router_actor(policy, state, actor):
    require(actor in policy["actors"], "router actor is not in the lifecycle policy: " + actor)
    role = policy["actors"][actor]["role"]
    require(role == "router", "actor %s is a %s, not a router" % (actor, role))
    current = state["current"]["router"]
    require(current == actor, "router actor %s is not the current router (%s)" % (actor, current))
    return policy["actors"][actor]


def deliver(lifecycle, ledger, actor, key, wait):
    """Deliver one request and record the route. Lock order is mailbox, then journal, as ROOT's adapter takes them."""
    _policy, state = locked_load(lifecycle, wait)
    row = state["requests"][key]
    team = row["request"]["team"]
    root, reason = team_mailbox(ledger, team)
    if reason is not None:
        return None, {"reason": reason}
    raw = row["raw"]
    identifier = route_id(raw["sha256"])
    expected = expected_message(team, key, raw)
    if len(expected["body"].encode("utf-8")) > MAX_BODY:
        return None, {"reason": "request_too_large"}

    def attempt():
        with writer_lock(Path(root)):
            mailbox = Mailbox(root)
            policy, state = locked_load(lifecycle, wait)
            entry = router_actor(policy, state, actor)
            row = state["requests"][key]
            stage, why = decision_state(state, row, timestamp())
            if stage is not None:
                return None, {"reason": why or stage}
            why = endpoint_reason(mailbox, team)
            if why is not None:
                return None, {"reason": why}
            prior = mailbox.messages().get(identifier)
            if prior is None:
                binding = mailbox.current_binding(expected["from"])
                mailbox.publish({"message_id": identifier, "host": binding["host"], "session": binding["session"],
                                 "binding_generation": binding["generation"], **expected})
            elif not same_delivery(prior["message"], expected):
                return None, {"reason": "route_message_conflict"}
            root_actor = state["current"]["root"]
            envelope = {"id": identifier, "actor": actor, "generation": entry["generation"],
                        "custody": {"cid": root_actor, "generation": policy["actors"][root_actor]["generation"]},
                        "event": {"type": "route", "request_id": key, "request_sha256": raw["sha256"], "to": expected["to"]}}
            receipt = patient(lambda: lifecycle.record(envelope), wait)
            return {"request_id": key, "request_sha256": raw["sha256"], "to": expected["to"], "message_id": identifier,
                    "receipt": receipt}, None

    try:
        return patient(attempt, wait)
    except (ValueError, OSError, UnicodeError) as exc:
        return None, {"reason": "delivery_error", "detail": str(exc)[:1024]}


def route(lifecycle, store, actor, wait, only=None):
    matching(actor, SLUG, "router actor")
    policy, state = locked_load(lifecycle, wait)
    router_actor(policy, state, actor)
    if only is not None:
        require(only in state["requests"], "unknown request id: " + only)
    ledger = store.load()
    at = timestamp()
    routed, held = [], {}
    for key, row in authority_rows(state):
        if only is not None and key != only:
            continue
        if row_view(state, key, row, ledger, at)["state"] != "ready":
            continue
        result, failure = deliver(lifecycle, ledger, actor, key, wait)
        if result is not None:
            routed.append(result)
        else:
            held[key] = failure
    return {"schema": RUN, "actor": actor, "execution_enabled": False, "identity": "configured",
            "authenticated": False, "routed": routed, "requests": report(lifecycle, store, wait, held)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lifecycle", required=True, help="Absolute path to the lifecycle journal")
    parser.add_argument("--store", required=True, help="Absolute path to the workspace store (the team registry)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Where each authority request stands; changes nothing")
    runner = commands.add_parser("route", help="Deliver every approved, unrouted request and record the route")
    runner.add_argument("--actor", required=True, help="The configured router actor CID; not authenticated")
    runner.add_argument("--evidence-only", action="store_true")
    runner.add_argument("--request", default=None, help="Route only this request ID")
    runner.add_argument("--wait", type=float, default=5.0, help="Seconds to wait out a busy writer lock")
    args = parser.parse_args(argv)
    try:
        lifecycle = Lifecycle(cli_path(args.lifecycle, "--lifecycle"))
        store = Store(cli_path(args.store, "--store"))
        if args.command == "status":
            result = status(lifecycle, store, 5.0)
        else:
            require(args.evidence_only, EVIDENCE_ONLY)
            require(0 <= args.wait <= 60, "--wait must be between 0 and 60 seconds")
            result = route(lifecycle, store, args.actor, args.wait, args.request)
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        sys.stdout.buffer.write(encoded({"state": "hold", "execution_enabled": False, "error": str(exc)[:1024]}) + b"\n")
        return 2
    sys.stdout.buffer.write(encoded(result) + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
