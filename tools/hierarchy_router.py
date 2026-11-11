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
from hierarchy_mailbox import (Mailbox, cli_path, digest, encoded, matching, parse_time, require, SLUG,  # noqa: E402
                               timestamp, writer_lock)
from hierarchy_workspace import Store  # noqa: E402
import hierarchy_hosts  # noqa: E402


STATUS = "aegis.router-status/v1"
RUN = "aegis.router-run/v1"
ROUTED = "aegis.routed-request/v1"
MAX_BODY = 65536
EVIDENCE_ONLY = "routing requires --evidence-only; the router is configuration-bound and unauthenticated"


class PrivatePathError(ValueError):
    """A lexical privacy refusal, distinguishable from malformed configuration."""
    def __init__(self, path, detail="owner-private host directory is not an input"):
        super().__init__(detail)
        self.path = Path(path)


def _lexical_path(value):
    path = Path(value)
    return Path("/", *path.parts[1:]) if path.anchor == "//" else path


def _inside(path, root, *, folded=False):
    left, right = path.parts, root.parts
    if folded:
        left, right = tuple(p.casefold() for p in left), tuple(p.casefold() for p in right)
    return len(left) >= len(right) and left[:len(right)] == right


def _case_insensitive(directory, roots):
    """Read-only probe of public sibling entries, never a private root or its contents.

    An unobservable/empty directory is ambiguous: keep the conservative privacy refusal.
    Each differing path component is probed in its own parent, including across mounts.
    """
    if any(_inside(directory, root, folded=True) for root in roots):
        return True
    descriptor = listing = None
    try:
        from hierarchy_fresh_brief import _reference_descriptors, _reference_parent
        if not _reference_descriptors():
            return True
        descriptor, _ancestors = _reference_parent(directory)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        listing = os.open(".", flags, dir_fd=descriptor)
        with os.scandir(listing) as entries:
            for number, entry in enumerate(entries):
                if number >= 64:
                    return True
                name = entry.name
                alternate = name.swapcase()
                if alternate == name or any(_inside(directory/name, root, folded=True) for root in roots):
                    continue
                original = os.stat(name, dir_fd=listing, follow_symlinks=False)
                try:
                    changed = os.stat(alternate, dir_fd=listing, follow_symlinks=False)
                except FileNotFoundError:
                    return False
                if not original.st_ino or not changed.st_ino:
                    return True
                return (original.st_dev, original.st_ino) == (changed.st_dev, changed.st_ino)
    except (ValueError, OSError):
        return True
    finally:
        if listing is not None: os.close(listing)
        if descriptor is not None: os.close(descriptor)
    return True


def preflight_paths(*paths):
    # Preserve the public API's exact ValueError refusal; row replay uses the
    # typed private seam below without broad/message-based exception matching.
    try:
        _preflight_private_paths(*paths)
    except PrivatePathError as exc:
        raise ValueError(str(exc)) from exc


def _owner_home():
    if os.name == "posix":
        import pwd
        try:
            value = pwd.getpwuid(os.getuid()).pw_dir
        except (KeyError, OSError) as exc:
            raise ValueError("cannot determine owner's home folder") from exc
    elif os.name == "nt":
        # CSIDL_PROFILE asks Windows for this user's default profile; HOME and
        # USERPROFILE may name a run's temporary home and are not owner identity.
        import ctypes
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            result = ctypes.windll.shell32.SHGetFolderPathW(None, 0x28, None, 0, buffer)
        except (AttributeError, OSError) as exc:
            raise ValueError("cannot determine owner's home folder") from exc
        require(result == 0 and bool(buffer.value), "cannot determine owner's home folder")
        value = buffer.value
    else:
        raise ValueError("cannot determine owner's home folder")
    home = _lexical_path(value)
    require(home.is_absolute() and ".." not in home.parts, "invalid owner home directory")
    return home


def _home_declarations():
    declarations = set()
    for host in hierarchy_hosts.describe()["hosts"].values():
        declaration = host.get("home")
        if declaration is None:
            continue
        variable, folder = declaration["variable"], declaration["owner_folder"]
        require(isinstance(variable, str) and isinstance(folder, str), "invalid host home declaration")
        declarations.add((variable, folder))
    return tuple(sorted(declarations))


def _private_roots(home, declarations):
    roots = set()
    for variable, folder in declarations:
        if variable in os.environ:
            configured = _lexical_path(os.environ[variable])
            require(configured.is_absolute() and ".." not in configured.parts, "configured host home must be absolute without traversal")
            roots.add(configured)
        if home is not None:
            roots.add(home/folder)
    return roots


def _refuse_private_paths(paths, roots):
    for value in paths:
        path = _lexical_path(value)
        for private in roots:
            if _inside(path, private):
                raise PrivatePathError(path)
        for private in roots:
            if _inside(path, private, folded=True):
                differences = [i for i, part in enumerate(private.parts) if path.parts[i] != part]
                if all(_case_insensitive(Path(*private.parts[:i]), roots) for i in differences):
                    raise PrivatePathError(path)


def _preflight_private_paths(*paths):
    """Registry-derived private roots; refuse before discovery of any supplied input."""
    _refuse_private_paths(paths, _private_roots(_owner_home(), _home_declarations()))


class _CapturedPathGuard:
    """One operation's privacy policy, never an authority or a persistent cache."""
    def __init__(self):
        self.home, self.declarations = _owner_home(), _home_declarations()
        self.uid = os.getuid() if os.name == "posix" else None
        self.environment = tuple((name, os.environ.get(name)) for name, _folder in self.declarations)
        self.roots = _private_roots(self.home, self.declarations)

    def current(self):
        uid = os.getuid() if os.name == "posix" else None
        require(uid == self.uid and self.environment == tuple((name, os.environ.get(name))
                for name, _folder in self.declarations), "host-home configuration changed during capture")

    def __call__(self, *paths):
        try:
            self.refuse(*paths)
        except PrivatePathError as exc:
            raise ValueError(str(exc)) from exc

    def refuse(self, *paths):
        self.current()
        _refuse_private_paths(paths, self.roots)

    def verify(self):
        self.current()
        require(self.home == _owner_home() and self.declarations == _home_declarations(),
                "owner-home policy changed during capture")


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
    mailbox = None
    if initiative is not None and "mailbox_root" in initiative:
        try:
            from hierarchy_fresh_brief import _CapturedMailbox
            mailbox = _CapturedMailbox(initiative["mailbox_root"])
            prior = prior_delivery(mailbox, team, key, row["raw"])
            mailbox.operation.verify()
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
                from hierarchy_fresh_brief import _CapturedMailbox
                mailbox = mailbox if mailbox is not None else _CapturedMailbox(root)
                reason = endpoint_reason(mailbox, team)
                mailbox.operation.verify()
            except (ValueError, OSError, UnicodeError) as exc:
                reason, view["detail"] = "team_mailbox_unreadable", str(exc)[:1024]
        stage = "ready" if reason is None else "held"
    view["state"] = stage
    if reason is not None:
        view["reason"] = reason
    return view


def report(lifecycle, store, wait, held=None):
    _policy, state = locked_load(lifecycle, wait)
    from hierarchy_fresh_brief import _Operation
    from hierarchy_small_change_dispatch import _CapturedStore
    operation = lifecycle.operation if hasattr(lifecycle, "operation") else _Operation()
    ledger = _CapturedStore(store.path, operation).load()
    operation.verify()
    return request_rows(state, ledger, held, getattr(lifecycle, "refusals_for", None))


def request_rows(state, ledger, held=None, references=None):
    at = timestamp()
    rows = []
    from hierarchy_small_change_dispatch import mixed_teams
    mixed = mixed_teams(state)
    for key, row in authority_rows(state):
        if "small_change" in row:
            continue
        view = row_view(state, key, row, ledger, at)
        failures = references(key) if references is not None else []
        if failures and view["state"] not in {"delivered_unrecorded", "routed", "closed", "denied"}:
            view.update(state="held", reason="reference_unavailable", detail=failures[0][1])
        if row["request"]["team"] in mixed and view["state"] == "ready":
            view.update(state="held", reason="small_change_mixed_queue")
        if held and key in held:
            # A delivery attempt this run failed after the checks passed; say why instead of "ready".
            if "partial_publication" in held[key]:
                # The event exists, but its post-commit durability/witness check
                # failed. Report that known effect on this pass, without replay.
                view.update(state="held", **held[key])
            elif view["state"] == "ready":
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
    preflight_paths(lifecycle.root, store.path, *([recipes] if recipes is not None else []))
    from hierarchy_fresh_brief import _Operation
    operation = _Operation()
    captured = operation.lifecycle(lifecycle.root)
    _policy, state = blamed("journal", lambda: locked_load(captured, wait))
    operation.verify()
    from hierarchy_small_change_dispatch import _CapturedStore
    ledger = blamed("store", lambda: _CapturedStore(store.path, operation).load())
    operation.verify()
    # The current router comes from journal custody, so a caller that routes as it follows a succession without
    # its own record of who the router is.
    result = {"schema": STATUS, "execution_enabled": False, "identity": "configured", "authenticated": False,
            "router": state["current"]["router"], "requests": request_rows(state, ledger, references=captured.refusals_for),
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
    require(envelope["id"] not in trial.get("_refused_event_ids", []), "event id belongs to refused journal input")
    previous = trial["receipts"].get(envelope["id"])
    require(previous is None or previous["event_sha256"] == digest(envelope), "event id conflicts with different bytes")
    reduce_event(policy, trial, envelope, timestamp())


def deliver(lifecycle, ledger, actor, key, wait):
    """Deliver one request, or finish one whose journal write was lost, and record the route.

    Lock order is mailbox, then journal, as ROOT's adapter takes them. The journal lock is not held from
    the check to the record, so a ROOT deny can land between them; the route is then recorded and status
    shows it as revoked_after_route, the same as a deny that comes later."""
    from hierarchy_fresh_brief import _CapturedLifecycle, _CommittedEvent, _Operation
    try:
        preflight_paths(lifecycle.root)
        if not isinstance(lifecycle, _CapturedLifecycle):
            lifecycle = _Operation().lifecycle(lifecycle.root)
        _policy, state = locked_load(lifecycle, wait)
        team = state["requests"][key]["request"]["team"]
        initiative = ledger.initiatives.get(team)
        if initiative is None or "mailbox_root" not in initiative:
            return None, {"reason": team_mailbox(ledger, team)[1]}
        root = initiative["mailbox_root"]

        def attempt():
            with writer_lock(Path(root)):
                from hierarchy_fresh_brief import _CapturedMailbox
                mailbox = _CapturedMailbox(root)
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
                    failures = lifecycle.refusals_for(key)
                    if failures:
                        return None, {"reason": "reference_unavailable", "detail": failures[0][1]}
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
                    lifecycle.operation.verify()
                    mailbox.operation.verify()
                    # Keep the canonical Router publication API/authority. The
                    # captured dispatcher's publish override accepts only scw/j/r.
                    published = Mailbox.publish(mailbox, {"message_id": envelope["id"], "host": binding["host"], "session": binding["session"],
                                                         "binding_generation": binding["generation"], **expected})
                    mailbox.operation.accept(published["path"], published["sha256"])
                    mailbox.operation.verify()
                receipt = patient(lambda: lifecycle.record(envelope), wait)
                return {"request_id": key, "request_sha256": raw["sha256"], "to": expected["to"],
                        "message_id": envelope["id"], "delivered": prior is None, "receipt": receipt}, None

        return patient(attempt, wait)
    except _CommittedEvent as exc:
        return None, {"reason": "delivery_error", "detail": str(exc)[:1024], "partial_publication": exc.record}
    except (ValueError, OSError, UnicodeError) as exc:
        return None, {"reason": "delivery_error", "detail": str(exc)[:1024]}


def route(lifecycle, store, actor, wait, only=None):
    from hierarchy_fresh_brief import _Operation
    operation = _Operation()
    lifecycle = operation.lifecycle(lifecycle.root)
    matching(actor, SLUG, "router actor")
    policy, state = locked_load(lifecycle, wait)
    router_actor(policy, state, actor)
    if only is not None:
        require(only in state["requests"], "unknown request id: " + only)
        authority = state["requests"][only]["request"]["authority"]
        require(authority == only, "only an authority request is routed; %s travels inside %s" % (only, authority))
    from hierarchy_small_change_dispatch import _CapturedStore
    ledger = _CapturedStore(store.path, operation).load()
    operation.verify()
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
        preflight_paths(args.lifecycle, args.store, *([args.recipes] if getattr(args, "recipes", None) is not None else []))
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
