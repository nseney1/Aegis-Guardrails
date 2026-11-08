#!/usr/bin/env python3
"""Route ROOT-approved canonical requests from the lifecycle journal to the team's orchestrator.

The Router routes and reports; it never approves or executes. This code is the model-free half: it reads
the journal, finds authority requests whose last ROOT decision is an unexpired approve and that have not
been routed, and delivers each to `<team>/orchestrator` in that team's mailbox. The Router role session is
the voice: it reads `status` and tells ROOT about anything held, and about each request the team
Decider escalated (option A: the Decider's `delegated_decision` approves only inside a delegation).

The team registry is the workspace initiative ledger. A request's `team` names an active initiative, and
that initiative's `mailbox_root` holds the team's endpoints. The message goes out under the current
binding of `<team>/router`, borrowed the way the job runner borrows ROOT's, so the item-2 fence applies.

Deduplication is by request hash. The message ID and the journal event ID are both `route-<sha256>`, so a
second run finds the earlier message and records nothing new, and a run that delivered but lost its journal
write is finished by the next run without a second message, even after a deny or an expiry. Before sending,
the route event is replayed on a copy of the journal state, so a delivery the journal would refuse to record
is never sent. A routed request is never routed again, even if ROOT later denies it; status reports that as
`revoked_after_route` for the Router to raise.

The journal accepts a `route` event from the router actor without checking approval. This code is where
that check lives at this tier. The router actor and the borrowed binding are configuration, not
authenticated identities, so mutation needs --evidence-only, as the journal's own CLI does.
"""
from __future__ import annotations

import argparse
import copy
import os
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_lifecycle import MAX_EVENTS, Lifecycle, reduce_event  # noqa: E402
from hierarchy_mailbox import (Mailbox, cli_path, encoded, matching, parse_time, require, SLUG,  # noqa: E402
                               timestamp, writer_lock)
from hierarchy_workspace import Store  # noqa: E402


STATUS = "aegis.router-status/v1"
RUN = "aegis.router-run/v1"
ROUTED = "aegis.routed-request/v1"
MAX_BODY = 65536
EVIDENCE_ONLY = "routing requires --evidence-only; the router is configuration-bound and unauthenticated"


def preflight_paths(*paths):
    """Refuse owner-private roots lexically, before even filesystem path discovery."""
    if os.name == "posix":
        import pwd

        def lexical_path(value):
            path = Path(value)
            if path.anchor == "//":
                return Path("/", *path.parts[1:])
            return path

        home = lexical_path(pwd.getpwuid(os.getuid()).pw_dir)
        for value in paths:
            path = lexical_path(value)
            for name in (".claude", ".codex"):
                private = home / name
                require(path != private and private not in path.parents,
                        "owner-private host directory is not an input")


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
    if "small_change" in row:
        return "held", "small_change_dispatch_unavailable"
    if decision is None:
        return "awaiting_decision", None
    if decision == "deny":
        return "denied", None
    if value["operation"] == "delegate-merge":
        # An approved delegation is the team Decider's scope, not work for the orchestrator.
        return "delegation", None
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
    # Every manifest has <team>/orchestrator (validate_manifest), but a router endpoint is optional.
    sender, recipient = team + "/router", team + "/orchestrator"
    if sender not in endpoints:
        return "router_endpoint_missing"
    if not mailbox.bindings(sender):
        return "router_unbound"
    if not mailbox.bindings(recipient):
        return "orchestrator_unbound"
    if not mailbox.ready(mailbox.current_binding(sender)):
        return "router_handoff_unacknowledged"
    return None


def expected_message(team, key, raw):
    return {"from": team + "/router", "to": team + "/orchestrator", "type": "info", "body": route_body(key, raw)}


def prior_delivery(mailbox, team, key, raw):
    """'same' if this request's route ID already names this exact delivery, 'conflict' if it names anything else.

    A stable ID alone is not this delivery. A successor router binding may have sent the original, so the
    sender's binding fields are not compared."""
    prior = mailbox.messages().get(route_id(raw["sha256"]))
    if prior is None:
        return None
    expected = expected_message(team, key, raw)
    return "same" if all(prior["message"].get(k) == v for k, v in expected.items()) else "conflict"


def authority_rows(state):
    # Continuation members are named, by ID and hash, inside their authority request's bytes; only the
    # authority gets a ROOT decision, so only the authority is routed.
    return sorted((key, row) for key, row in state["requests"].items() if row["request"]["authority"] == key)


def oversized(key, raw):
    return len(route_body(key, raw).encode("utf-8")) > MAX_BODY


def row_view(state, key, row, ledger, at):
    value = row["request"]
    team = value["team"]
    view = {"request_id": key, "request_sha256": row["raw"]["sha256"], "team": team,
            "orchestrator": team + "/orchestrator"}
    revoked = last_decision(state, key) == "deny"
    stage, reason = decision_state(state, row, at)
    if stage == "routed":
        view.update(state="routed", to=row["routed"]["to"], routed=row["routed"], revoked_after_route=revoked)
        return view
    # A delivery whose journal write was lost is still a delivery, whatever ROOT decided since.
    initiative = ledger.initiatives.get(team)
    if initiative is not None and "mailbox_root" in initiative:
        try:
            prior = prior_delivery(Mailbox(initiative["mailbox_root"]), team, key, row["raw"])
        except (ValueError, OSError, UnicodeError) as exc:
            prior = None
            if stage is None:
                stage, reason, view["detail"] = "held", "team_mailbox_unreadable", str(exc)[:1024]
        if prior == "same":
            view.update(state="delivered_unrecorded", to=team + "/orchestrator", revoked_after_route=revoked)
            return view
        if prior == "conflict" and stage is None:
            stage, reason = "held", "route_message_conflict"
    if stage is None:
        root, reason = team_mailbox(ledger, team)
        if reason is None and oversized(key, row["raw"]):
            reason = "request_too_large"
        if reason is None:
            try:
                reason = endpoint_reason(Mailbox(root), team)
            except (ValueError, OSError, UnicodeError) as exc:
                reason, view["detail"] = "team_mailbox_unreadable", str(exc)[:1024]
        stage = "ready" if reason is None else "held"
    view["state"] = stage
    if reason is not None:
        view["reason"] = reason
    return view


def report(lifecycle, store, wait, held=None):
    _policy, state = locked_load(lifecycle, wait)
    return request_rows(state, store.load(), held)


def request_rows(state, ledger, held=None):
    at = timestamp()
    rows = []
    from hierarchy_small_change_dispatch import mixed_teams
    mixed = mixed_teams(state)
    for key, row in authority_rows(state):
        if "small_change" in row:
            continue
        view = row_view(state, key, row, ledger, at)
        if row["request"]["team"] in mixed and view["state"] == "ready":
            view.update(state="held", reason="small_change_mixed_queue")
        if held and key in held:
            # A delivery attempt this run failed after the checks passed; say why instead of "ready".
            if view["state"] == "ready":
                view["state"] = "held"
            if view["state"] in {"held", "delivered_unrecorded"}:
                view.update(held[key])
        rows.append(view)
    return rows


def escalations(state):
    """What the Decider handed to ROOT. ROOT decides on a canonical request; until then the Router voices it."""
    rows = []
    for entry in state.get("delegated_decisions", []):
        if entry["decision"] != "escalate":
            continue
        rows.append({"request_id": entry["request_id"], "request_sha256": entry["request_sha256"],
                     "team": state["requests"][entry["request_id"]]["request"]["team"],
                     "delegation_id": entry["delegation_id"], "actor": entry["actor"], "at": entry["at"],
                     "reason": entry["reason"], "root_decision": last_decision(state, entry["request_id"])})
    return rows


ERRORS = (ValueError, OSError, UnicodeError, RecursionError)


def blamed(source, action):
    """Run action and tag a refusal with the component that failed.

    A status caller (the loop) escalates only a journal it cannot read to the owner's journal lock; a broken
    workspace store or a bad argument is a different fix, and an untagged exit 2 cannot say which."""
    try:
        return action()
    except ERRORS as exc:
        if not hasattr(exc, "source"):
            exc.source = source
        raise


def status(lifecycle, store, wait, recipes=None):
    preflight_paths(lifecycle.root, store.path)
    _policy, state = blamed("journal", lambda: locked_load(lifecycle, wait))
    ledger = blamed("store", store.load)
    # The current router comes from journal custody, so a caller that routes as it follows a succession without
    # its own record of who the router is.
    result = {"schema": STATUS, "execution_enabled": False, "identity": "configured", "authenticated": False,
            "router": state["current"]["router"], "requests": request_rows(state, ledger),
            "escalations": escalations(state)}
    if any("small_change" in row for row in state["requests"].values()):
        from hierarchy_small_change_dispatch import project
        result.update(project(lifecycle, store, wait, recipes))
    return result


def router_actor(policy, state, actor):
    require(actor in policy["actors"], "router actor is not in the lifecycle policy: " + actor)
    role = policy["actors"][actor]["role"]
    require(role == "router", "actor %s is a %s, not a router" % (actor, role))
    current = state["current"]["router"]
    require(current == actor, "router actor %s is not the current router (%s)" % (actor, current))
    return policy["actors"][actor]


def route_envelope(policy, state, actor, key, raw, to):
    root_actor = state["current"]["root"]
    return {"id": route_id(raw["sha256"]), "actor": actor, "generation": policy["actors"][actor]["generation"],
            "custody": {"cid": root_actor, "generation": policy["actors"][root_actor]["generation"]},
            "event": {"type": "route", "request_id": key, "request_sha256": raw["sha256"], "to": to}}


def journal_accepts(policy, state, envelope):
    """Replay the route event on a copy, so a message goes out only when the journal will record it.

    Without this, a capped or full journal would leave a delivery the journal never records."""
    trial = copy.deepcopy(state)
    require(trial["sequence"] < MAX_EVENTS, "lifecycle event limit reached")
    reduce_event(policy, trial, envelope, timestamp())


def deliver(lifecycle, ledger, actor, key, wait):
    """Deliver one request, or finish one whose journal write was lost, and record the route.

    Lock order is mailbox, then journal, as ROOT's adapter takes them. The journal lock is not held from
    the check to the record, so a ROOT deny can land between them; the route is then recorded and status
    shows it as revoked_after_route, the same as a deny that comes later."""
    try:
        _policy, state = locked_load(lifecycle, wait)
        team = state["requests"][key]["request"]["team"]
        initiative = ledger.initiatives.get(team)
        if initiative is None or "mailbox_root" not in initiative:
            return None, {"reason": team_mailbox(ledger, team)[1]}
        root = initiative["mailbox_root"]

        def attempt():
            with writer_lock(Path(root)):
                mailbox = Mailbox(root)
                policy, state = locked_load(lifecycle, wait)
                router_actor(policy, state, actor)
                row = state["requests"][key]
                raw = row["raw"]
                if row["routed"] is not None:
                    return None, {"reason": "already_routed"}
                expected = expected_message(team, key, raw)
                envelope = route_envelope(policy, state, actor, key, raw, expected["to"])
                prior = prior_delivery(mailbox, team, key, raw)
                if prior == "conflict":
                    return None, {"reason": "route_message_conflict"}
                if prior is None:
                    from hierarchy_small_change_dispatch import mixed_teams
                    if team in mixed_teams(state):
                        return None, {"reason": "small_change_mixed_queue"}
                    stage, why = decision_state(state, row, timestamp())
                    if stage is not None:
                        return None, {"reason": why or stage}
                    why = team_mailbox(ledger, team)[1] or ("request_too_large" if oversized(key, raw) else None)
                    why = why or endpoint_reason(mailbox, team)
                    if why is not None:
                        return None, {"reason": why}
                    journal_accepts(policy, state, envelope)
                    binding = mailbox.current_binding(expected["from"])
                    mailbox.publish({"message_id": envelope["id"], "host": binding["host"], "session": binding["session"],
                                     "binding_generation": binding["generation"], **expected})
                receipt = patient(lambda: lifecycle.record(envelope), wait)
                return {"request_id": key, "request_sha256": raw["sha256"], "to": expected["to"],
                        "message_id": envelope["id"], "delivered": prior is None, "receipt": receipt}, None

        return patient(attempt, wait)
    except (ValueError, OSError, UnicodeError) as exc:
        return None, {"reason": "delivery_error", "detail": str(exc)[:1024]}


def route(lifecycle, store, actor, wait, only=None):
    matching(actor, SLUG, "router actor")
    policy, state = locked_load(lifecycle, wait)
    router_actor(policy, state, actor)
    if only is not None:
        require(only in state["requests"], "unknown request id: " + only)
        authority = state["requests"][only]["request"]["authority"]
        require(authority == only, "only an authority request is routed; %s travels inside %s" % (only, authority))
    ledger = store.load()
    at = timestamp()
    routed, held = [], {}
    from hierarchy_small_change_dispatch import mixed_teams
    mixed = mixed_teams(state)
    for key, row in authority_rows(state):
        if "small_change" in row:
            continue
        if only is not None and key != only:
            continue
        view = row_view(state, key, row, ledger, at)
        if row["request"]["team"] in mixed and view["state"] != "delivered_unrecorded":
            continue
        if view["state"] not in {"ready", "delivered_unrecorded"}:
            continue
        result, failure = deliver(lifecycle, ledger, actor, key, wait)
        if result is not None:
            routed.append(result)
        else:
            held[key] = failure
    result = {"schema": RUN, "actor": actor, "execution_enabled": False, "identity": "configured",
              "authenticated": False, "routed": routed}
    try:
        result["requests"] = report(lifecycle, store, wait, held)
    except (ValueError, OSError, UnicodeError) as exc:
        # The routes above are recorded; losing the closing report must not hide them.
        result.update(requests=None, held=held, report_error=str(exc)[:1024])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lifecycle", required=True, help="Absolute path to the lifecycle journal")
    parser.add_argument("--store", required=True, help="Absolute path to the workspace store (the team registry)")
    commands = parser.add_subparsers(dest="command", required=True)
    reader = commands.add_parser("status", help="Where each authority request stands; changes nothing")
    reader.add_argument("--recipes", help="Configured recipes for read-only small-change preflight")
    reader.add_argument("--wait", type=float, default=5.0)
    runner = commands.add_parser("route", help="Deliver every approved, unrouted request and record the route")
    runner.add_argument("--actor", required=True, help="The configured router actor CID; not authenticated")
    runner.add_argument("--evidence-only", action="store_true")
    runner.add_argument("--request", default=None, help="Route only this request ID")
    runner.add_argument("--wait", type=float, default=5.0, help="Seconds to wait out a busy writer lock")
    dispatch = commands.add_parser("dispatch", help="Progress admitted small changes without planning model turns")
    dispatch.add_argument("--recipes", required=True)
    dispatch.add_argument("--evidence-only", action="store_true")
    dispatch.add_argument("--wait", type=float, default=5.0)
    args = parser.parse_args(argv)
    try:
        preflight_paths(args.lifecycle, args.store)
        lifecycle_path, store_path = cli_path(args.lifecycle, "--lifecycle"), cli_path(args.store, "--store")
        lifecycle = blamed("journal", lambda: Lifecycle(lifecycle_path))
        store = blamed("store", lambda: Store(store_path))
        if args.command == "status":
            require(0 <= args.wait <= 60, "--wait must be between 0 and 60 seconds")
            result = status(lifecycle, store, args.wait, cli_path(args.recipes, "--recipes") if args.recipes else None)
        elif args.command == "dispatch":
            require(args.evidence_only, EVIDENCE_ONLY)
            require(0 <= args.wait <= 60, "wait must be between 0 and 60 seconds")
            from hierarchy_small_change_dispatch import project
            result = {"schema": "aegis.small-change-dispatch-run/v1", "execution_enabled": False,
                      "identity": "configured", "authenticated": False,
                      **project(lifecycle, store, args.wait, cli_path(args.recipes, "--recipes"), mutate=True)}
        else:
            require(args.evidence_only, EVIDENCE_ONLY)
            require(0 <= args.wait <= 60, "--wait must be between 0 and 60 seconds")
            result = route(lifecycle, store, args.actor, args.wait, args.request)
    except ERRORS as exc:
        refused = {"state": "hold", "execution_enabled": False, "error": str(exc)[:1024]}
        if args.command == "status":
            # journal: the lifecycle read failed; store: the workspace store did; arguments: anything else.
            refused["source"] = getattr(exc, "source", "arguments")
        sys.stdout.buffer.write(encoded(refused) + b"\n")
        return 2
    sys.stdout.buffer.write(encoded(result) + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
