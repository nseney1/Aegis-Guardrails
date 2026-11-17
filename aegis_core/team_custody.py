"""Trusted, tested-bytes commit custodian; no CLI or model-facing activation.

The adapter owns the active GitStore, matching GitOpsJournal, fixed identity,
required legs, read callbacks and governance_check(commit, tree). Governance
returns exactly True for approval and may inspect private scratch objects; real
rule_integrity wiring belongs to the host adapter. Children receive none of these
capabilities. Read callback contracts are those of check_preconditions.

Commit construction writes private scratch only. Preconditions and governance
must pass before a durable intent permits the sole CAS attempt. A reused request
observes that intent, never repeats its effect or reevaluates changed worktree
bytes. The journal's own lock serializes binding admission across processes;
identical ref/parent/commit bindings share the original intent even when callers
supply different request IDs. Effects run after admission releases that lock.
Custodian intents retain a bounded fingerprint of every immutable input in the
journal's existing state field; known IDs compare it before reconstruction.
The existing journal owns result
deduplication and crash checkpoints. Its terminal status stays done; the public
recovery outcome is committed_recovered. An unavailable observation remains open.
No existing Codex/host flow imports or activates this boundary.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import time

from aegis_core import gitops_rows, team_git, team_gitops, team_qualify
from aegis_core import team_custody_checks as checks
from aegis_core.errors import AegisError
from aegis_core.team_custody_checks import CustodyRefused

__all__ = ["CommitRefused", "CommitResult", "CustodyRefused", "REFUSALS", "commit"]

REFUSALS = {
    "unsupported_platform": "commit custody requires descriptor-relative support",
    "governance_refused": "commit governance did not approve the tested bytes",
    "invalid_request": "commit request identity is invalid",
    "request_conflict": "commit request is already bound to different inputs",
    "request_closed": "commit request did not publish its intended commit; never retry its effect",
    "journal_failed": "commit journal is unavailable; reconcile before further action",
    "git_failed": "commit Git operation failed",
    "cas_mismatch": "lane ref no longer matches the expected tip",
    "ref_update_unknown": "commit outcome is unavailable; reconcile before further action",
    "invalid_identity": "commit identity is invalid",
    "invalid_message": "commit message is invalid",
    "invalid_oid": "commit object identity is invalid",
    "invalid_parent": "commit parent is invalid",
    "store_closed": "commit requires an active private store",
}
_UNKNOWN = frozenset(("ref_update_unknown", "git_cleanup_failed", "git_timeout", "git_output_limit"))
_ERRORS = (AegisError, OSError, ValueError, TypeError, RecursionError)
# A code proves the refused gate, not the absence of a concurrent or saved intent.
# Construction failures therefore retain observation-only advice for any intent.
_ACTIONS = {
    "unsupported_platform": "use a host with descriptor-relative commit custody support",
    "governance_refused": "obtain governance approval for the tested bytes before retrying commit custody",
    "invalid_request": "provide valid commit request and actor identifiers",
    "request_conflict": "inspect the recorded request binding and restore its original inputs; never repeat its effect",
    "request_closed": "inspect the terminal commit result; never retry this request's effect",
    "journal_failed": "restore journal access and reconcile by observation; never repeat an existing intent's effect",
    "git_failed": "inspect the Git failure and commit journal; reconcile any existing intent by observation; never repeat its effect",
    "cas_mismatch": "inspect the lane ref and terminal commit result; never repeat this request's effect",
    "ref_update_unknown": "inspect the commit intent and reconcile by observation; never repeat its effect",
    "invalid_identity": "provide a valid commit identity and reconcile any existing intent by observation; never repeat its effect",
    "invalid_message": "provide a bounded commit message without forbidden trailers and reconcile any existing intent by observation; never repeat its effect",
    "invalid_oid": "provide valid commit object identities and reconcile any existing intent by observation; never repeat its effect",
    "invalid_parent": "provide a valid commit parent and reconcile any existing intent by observation; never repeat its effect",
    "store_closed": "open an active private Git store and reconcile any existing intent by observation; never repeat its effect",
}


class CommitRefused(ValueError):
    """Fixed input-free refusal and conservative recovery instruction."""

    def __init__(self, code):
        super().__init__(REFUSALS[code])
        self.code = code
        self.next_action = {"actor": "custodian", "command": _ACTIONS[code]}


@dataclass(frozen=True)
class CommitResult:
    status: str
    commit: str
    tree: str


# Immediate first read. Later polls double until the cap and never run past the window.
# Tests replace this module's time binding so the window does not call the process sleeper.
OBSERVATION_SECONDS = 5.0
OBSERVATION_POLL_SECONDS = 0.01
OBSERVATION_POLL_MAX_SECONDS = 0.1


def _terminal(store, journal, lane, request_id, ref, *, wait=False):
    def observe(intent):
        oid = team_git.ref_oid(store, ref)
        if oid == intent["expected_new"]["head"]:
            # The immutable commit ID witnesses the saved request annotation;
            # the annotation itself is not a separately observed ref value.
            state = dict(intent["expected_new"])
        else:
            state = None if oid is None else {"ref": ref, "head": oid}
        return team_gitops.Observation(state)
    deadline = time.monotonic() + OBSERVATION_SECONDS if wait else None
    delay = OBSERVATION_POLL_SECONDS
    while True:
        rows = journal.reconcile(lane, observe, request_id=request_id)
        terminal = next((row for row in (rows or journal.read().rows)
                         if row["kind"] in ("result", "tombstone") and row["request_id"] == request_id), None)
        if terminal is not None or deadline is None:
            return terminal
        now = time.monotonic()
        if now >= deadline:
            return terminal
        # Bound the wait before sleeping: poll cap and the time still inside the window.
        step = min(delay, OBSERVATION_POLL_MAX_SECONDS, deadline - now)
        if step <= 0:
            return terminal
        time.sleep(step)
        delay = min(delay * 2.0, OBSERVATION_POLL_MAX_SECONDS)


def _recover(store, journal, binding, tree, *, wait=False):
    # Distinct-ID attachments wait only for observation, never for an effect
    # retry. Same-ID in-flight retries retain their immediate unknown refusal.
    terminal = _terminal(store, journal, binding["lane"], binding["request_id"],
                         binding["expected_new"]["ref"], wait=wait)
    if terminal is None:
        raise CommitRefused("ref_update_unknown")
    if terminal["status"] != "done":
        raise CommitRefused("request_closed")
    return CommitResult("committed_recovered", binding["expected_new"]["head"], tree)


def _governance(callback, oid, tree):
    try:
        approved = callable(callback) and callback(oid, tree) is True
    except Exception:
        # This injected trusted adapter may fail with any ordinary exception;
        # its diagnostics must not become output or a permission to publish.
        approved = False
    if not approved:
        raise CommitRefused("governance_refused")


def _fingerprint(lane, actor, parent, tree, message, identity):
    """Bound capture only; public custody/Git boundaries own input grammars."""
    if not isinstance(identity, team_git.CommitIdentity):
        raise CommitRefused("request_conflict")
    fields = (lane, actor, parent, tree, message, identity.name, identity.email, identity.date)
    digest = hashlib.sha256(b"aegis-custody-inputs-v1\0")
    for value in fields:
        # This generous capture cap includes every publicly valid identity,
        # OID and label. It is not a second commit-message/identity grammar.
        if type(value) is not str or len(value) > team_git.MAX_MESSAGE_BYTES:
            raise CommitRefused("request_conflict")
        try:
            data = value.encode("utf-8")
        except UnicodeError:
            raise CommitRefused("request_conflict") from None
        if len(data) > team_git.MAX_MESSAGE_BYTES:
            raise CommitRefused("request_conflict")
        digest.update(len(data).to_bytes(4, "big"))
        digest.update(data)
    return digest.hexdigest()


def _binding(lane, request_id, actor, ref, old, new, fingerprint):
    return gitops_rows.intent("commit", lane, request_id, {"ref": ref, "head": old},
                             {"ref": ref, "head": new, "state": fingerprint}, actor)


def _same_request(existing, binding):
    if any(existing[key] != binding[key] for key in
           ("op", "lane", "request_id", "expected_old", "expected_new", "actor")):
        raise CommitRefused("request_conflict")


def _recovery_ref(existing):
    # The shared journal accepts several closed state shapes for other adapters.
    # A valid generic commit row is not necessarily this custodian's binding.
    if not _commit_shape(existing):
        raise CommitRefused("request_conflict")
    return existing["expected_new"]["ref"]


def _bound_ref(existing, lane, actor, expected_head, tested_tree, message, identity):
    # Compare persisted input fields before construction, grammar validation or
    # observation can turn a conflicting request into an unrelated refusal.
    if (existing["op"] != "commit" or existing["lane"] != lane
            or existing["actor"] != actor):
        raise CommitRefused("request_conflict")
    ref = _recovery_ref(existing)
    if (existing["expected_old"]["head"] != expected_head
            or existing["expected_new"]["state"] != _fingerprint(
                lane, actor, expected_head, tested_tree, message, identity)):
        raise CommitRefused("request_conflict")
    return ref


def _commit_shape(row):
    old, new = row["expected_old"], row["expected_new"]
    return (row["op"] == "commit" and type(old) is dict and type(new) is dict
            and old.keys() == {"ref", "head"} and new.keys() == {"ref", "head", "state"}
            and old["ref"] == new["ref"])


def _known_commit(store, rows, *, lane, expected_head, tested_tree, message, identity, read_branch):
    """Find a recorded binding before requiring the pre-publication HEAD again."""
    new = None
    for row in rows:
        if not _commit_shape(row) or row["lane"] != lane or row["expected_old"]["head"] != expected_head:
            continue
        if new is None:
            new = team_git.commit_tested(store, tested_tree, expected_head, message, identity)
        if row["expected_new"]["head"] != new:
            continue
        try:
            branch = read_branch()
        except _ERRORS:
            raise CustodyRefused("branch_mismatch", lane=lane) from None
        ref = row["expected_new"]["ref"]
        # Compare bounded journal text rather than allocating from reader input.
        if ref.startswith("refs/heads/") and ref[len("refs/heads/"):] == branch:
            return row
    return None


def _attach(store, journal, recorded, tree):
    with journal.admission():
        fresh = next((row for row in journal.read().rows
                      if row["request_id"] == recorded["request_id"]), None)
        if fresh is None:
            raise CommitRefused("request_closed")
        _same_request(fresh, recorded)
    return _recover(store, journal, fresh, tree, wait=True)


def _refresh_recovery(store, journal, *, lane, actor, expected_head, tested_tree,
                      message, identity, read_branch, request_id):
    """Refresh under admission before preserving a stale precondition refusal."""
    with journal.admission():
        rows = journal.read().rows
        existing = next((row for row in rows if row["request_id"] == request_id), None)
        if existing is not None:
            _bound_ref(existing, lane, actor, expected_head, tested_tree, message, identity)
    if existing is not None:
        return _recover(store, journal, existing, tested_tree)
    recorded = _known_commit(store, rows, lane=lane, expected_head=expected_head,
        tested_tree=tested_tree, message=message, identity=identity, read_branch=read_branch)
    return None if recorded is None else _attach(store, journal, recorded, tested_tree)


def _publish(store, journal, binding, tree):
    with ExitStack() as ownership:
        with journal.admission():
            rows = journal.read().rows
            existing = next((row for row in rows if row["request_id"] == binding["request_id"]), None)
            if existing is not None:
                _same_request(existing, binding)
            duplicate = next((row for row in rows if _commit_shape(row)
                              and row["expected_old"] == binding["expected_old"]
                              and all(row["expected_new"][key] == binding["expected_new"][key]
                                      for key in ("ref", "head"))), None)
            if duplicate is None:
                receipt = ownership.enter_context(journal.record_intent(**{key: binding[key] for key in
                    ("op", "lane", "request_id", "expected_old", "expected_new", "actor")}))
        if duplicate is not None:
            return _recover(store, journal, duplicate, tree,
                            wait=duplicate["request_id"] != binding["request_id"])
        return _publish_owned(store, journal, binding, tree, receipt)


def _publish_owned(store, journal, binding, tree, receipt):
    if not receipt.created:
        return _recover(store, journal, binding, tree)
    failure = None
    try:
        status = team_git.cas_fast_forward(store, binding["expected_new"]["ref"],
                                           binding["expected_old"]["head"], binding["expected_new"]["head"],
                                           effect_fds=receipt.inheritable_fds())
    except AegisError as exc:
        if exc.code in _UNKNOWN:
            # Surviving transport holders may still act. Only a fresh-lock
            # observation on a later call can finish this intent.
            raise CommitRefused("ref_update_unknown") from None
        failure = exc.code if exc.code in REFUSALS else "git_failed"
    # A return does not prove inherited effect holders exited. Release only
    # our receipt; reconcile must independently acquire its effect lock.
    receipt.close()
    terminal = _terminal(store, journal, binding["lane"], binding["request_id"],
                         binding["expected_new"]["ref"], wait=True)
    if terminal is None:
        raise CommitRefused("ref_update_unknown")
    if terminal["status"] != "done":
        raise CommitRefused(failure or "cas_mismatch")
    return CommitResult("committed_recovered" if failure or status == "already" else "committed",
                        binding["expected_new"]["head"], tree)


def commit(store, *, lane, owner, expected_head, tested_tree, required_legs, message,
           identity, journal, request_id, actor, read_branch, read_head, read_paths,
           read_policy, governance_check, now=None):
    """Commit exactly tested_tree or raise a fixed custody/commit refusal.

    Fresh publication requires ordered preconditions and governance before its
    durable intent and CAS. Private construction also identifies recorded
    bindings. Recovery requires the original immutable
    commit inputs and journal identity, but deliberately does not demand a still
    dirty worktree, live lease or old HEAD after successful publication. Each
    immutable ref/parent/commit binding has one terminal journal row, across
    request IDs and concurrent retries. Failed
    and foreign observations close the request without another effect attempt.
    """
    if not team_git.descriptor_support() or not team_qualify.descriptor_supported():
        raise CommitRefused("unsupported_platform")
    valid_actor = gitops_rows.identifier(actor)
    if (not gitops_rows.identifier(request_id)
            or (not valid_actor and type(journal) is not team_gitops.GitOpsJournal)):
        raise CommitRefused("invalid_request")
    if type(journal) is not team_gitops.GitOpsJournal:
        raise CommitRefused("journal_failed")
    try:
        rows = journal.read().rows
        existing = next((row for row in rows if row["request_id"] == request_id), None)
        if existing is not None:
            ref = _bound_ref(existing, lane, actor, expected_head, tested_tree, message, identity)
        elif not valid_actor:
            raise CommitRefused("invalid_request")
        branch = []
        if existing is None:
            recorded = _known_commit(store, rows, lane=lane, expected_head=expected_head,
                tested_tree=tested_tree, message=message, identity=identity, read_branch=read_branch)
            if recorded is not None:
                return _attach(store, journal, recorded, tested_tree)
            def capture_branch():
                value = read_branch()
                branch.append(value)
                return value
            try:
                checks.check_preconditions(store, lane=lane, owner=owner, expected_head=expected_head,
                    tested_tree=tested_tree, required_legs=required_legs, message=message,
                    read_branch=capture_branch, read_head=read_head, read_paths=read_paths,
                    read_policy=read_policy, now=now)
            except CustodyRefused:
                recovered = _refresh_recovery(store, journal, lane=lane, actor=actor,
                    expected_head=expected_head, tested_tree=tested_tree, message=message,
                    identity=identity, read_branch=read_branch, request_id=request_id)
                if recovered is not None:
                    return recovered
                raise
            ref = "refs/heads/" + branch[0]
        new = team_git.commit_tested(store, tested_tree, expected_head, message, identity)
        fingerprint = _fingerprint(lane, actor, expected_head, tested_tree, message, identity)
        binding = _binding(lane, request_id, actor, ref, expected_head, new, fingerprint)
        if existing is not None:
            _same_request(existing, binding)
            return _recover(store, journal, binding, tested_tree)
        _governance(governance_check, new, tested_tree)
        return _publish(store, journal, binding, tested_tree)
    except (CustodyRefused, CommitRefused):
        raise
    except team_gitops.GitOpsError as exc:
        code = "request_conflict" if exc.code == "request_conflict" else "journal_failed"
        raise CommitRefused(code) from None
    except AegisError as exc:
        raise CommitRefused(exc.code if exc.code in REFUSALS else "git_failed") from None
    except _ERRORS:
        raise CommitRefused("git_failed") from None
