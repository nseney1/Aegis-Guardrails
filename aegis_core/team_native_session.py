"""Process-local LIVE sessions over the installed host binding and canonical API."""
from __future__ import annotations

import copy
import threading
import time
from contextlib import contextmanager, nullcontext, suppress

from aegis_core.team_mailbox_primitives import SLUG
from aegis_core.team_native_authority import HostAuthority, LIVE_SCHEMA, fields, require, same_data, sha, uint
from aegis_core.team_native_keys import LIVE_KEY, NATIVE_IDENTITIES as native_identities
from aegis_core.team_native_wire import HostAuthorityError, MAX_CALLS, MAX_WAIT_SECONDS, ProtocolClient

__all__ = ["AppserverIO", "HostInvocation", "HostSession"]

_NS = 10**9
_ACTOR_FIELDS = ("role", "generation", "profile_sha256", "runtime_profile_sha256",
                 "actor_started_monotonic_ns", "actor_deadline_monotonic_ns")
_CORRELATION = ("actor_cid", "rpc_id", "thread_id", "turn_id", "call_id", "namespace", "tool", "event_id")
_TARGET = ("event_id", "request_id", "request_sha256")
_COMMAND_FIELDS = frozenset((*_TARGET, "decision", "reason"))
_RESULT_FIELDS = frozenset((*_TARGET, "schema", "state", "effect", "code", "reason", "receipt", "native_qualified"))
_EFFECTS = {"recorded": "canonical_decision", "recovered": "none", "refused": "none", "unknown": "possible"}
_NEXT_ACTION = "Reconcile original canonical evidence before retrying."
_UNKNOWN = "canonical decision outcome is unresolved"
_BAD_FRAME = "invalid host protocol frame"
_ADMISSION_TIMEOUT = "original appserver deadline expired"


def _remaining(deadline_ns):
    return max(0, (deadline_ns - time.monotonic_ns()) / _NS)


def _close_after_failure(owner):
    # The binding fences its streams even if stream cleanup fails. Preserve the
    # operation's typed refusal over any secondary descriptor-close error.
    with suppress(OSError, ValueError):
        owner.close()


def _fence(owner):
    """Publish revocation under the binding's descriptor gate, before cleanup."""
    with owner.io_gate:
        if owner.fenced:
            return False
        owner.fenced = True
        return True


@contextmanager
def _terminal_operation(owner, *, validating=False):
    # Validation of already received data shares the descriptor gate. Neither
    # a pipe wait nor a control exchange holds it.
    fenced_here = False
    try:
        with owner.io_gate if validating else nullcontext():
            try:
                yield
            except BaseException:
                fenced_here = _fence(owner)
                raise
    except HostAuthorityError:
        raise
    except (OSError, ValueError):
        raise HostAuthorityError("HOST_PROTOCOL_ERROR", _BAD_FRAME) from None
    finally:
        if fenced_here:
            _close_after_failure(owner)


class AppserverIO(ProtocolClient):
    """Appserver pipes protected by their binding's one descriptor gate."""

    def __init__(self, owner):
        require(native_identities.owns_binding(owner), "ROLE_OPERATION_FORBIDDEN",
                "appserver requires an owned binding")
        owner.require_owner_process()
        self._owner = owner
        self._deadline = threading.local()
        self._opening = True
        try:
            with _terminal_operation(owner, validating=True):
                require(not owner.fenced, "STALE_INVOCATION", "runtime binding is closed")
                super().__init__(owner.reader, owner.writer)
        finally:
            self._opening = False

    @contextmanager
    def operation(self, deadline_ns):
        """Bind a deadline to this caller without holding a gate across waits."""
        self._owner.require_owner_process()
        require(not hasattr(self._deadline, "seconds"), "ROLE_OPERATION_FORBIDDEN",
                "appserver operation is already active")
        require(not self._revoked(), "STALE_INVOCATION", "runtime binding is closed")
        require(_remaining(deadline_ns) > 0, "HOST_PROTOCOL_TIMEOUT", _ADMISSION_TIMEOUT)
        self._deadline.seconds = deadline_ns / _NS
        try:
            yield
        finally:
            del self._deadline.seconds

    def _transport_gate(self):
        return self._owner.io_gate

    def _revoked(self):
        return self._closed or self._owner.fenced

    def _live(self, *, initialized=True):
        require(not self._owner.fenced, "STALE_INVOCATION", "runtime binding is closed")
        super()._live(initialized=initialized)

    def _operation_deadline(self):
        return min(super()._operation_deadline(), getattr(self._deadline, "seconds", 0))

    def _fail(self, code="HOST_PROTOCOL_ERROR", reason=_BAD_FRAME):
        if _fence(self._owner):
            _close_after_failure(self._owner)
        raise HostAuthorityError(code, reason) from None

    def close(self):
        if self._opening:
            # The construction handler fences and cleans up after gate exit.
            self._closed = True
            return
        self._owner.require_owner_process()
        try:
            _fence(self._owner)
            self._owner.close()
        except HostAuthorityError:
            raise
        except (OSError, ValueError):
            raise HostAuthorityError("HOST_PROTOCOL_ERROR", _BAD_FRAME) from None


class _NonTransferable:
    def __copy__(self):
        raise TypeError("owned LIVE objects cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("owned LIVE objects cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("owned LIVE objects cannot be serialized")


class HostInvocation(_NonTransferable):
    """One actual received frame, interned only after owned pending readback."""

    def __init__(self, key, session, frame, projection):
        require(key is LIVE_KEY and type(session) is HostSession,
                "ROLE_OPERATION_FORBIDDEN", "invocation requires an owned pending call")
        self._session = session
        self._frame, self._projection = copy.deepcopy(frame), copy.deepcopy(projection)
        self.stage = "pending"
        self.scope_depth = 0
        self.scope_entered = False
        self._completion = None
        self._writer_entered = False
        self._dispatching = self._dispatch_issued = self._reply_issued = False

    @property
    def session(self):
        return self._session

    @property
    def owner(self):
        # TA-3c checks prior scope history even after the binding closes.
        return self._session._owner

    @property
    def actor_cid(self):
        return self._session.actor_cid

    @property
    def rpc_id(self):
        return self._frame["id"]

    @property
    def event_id(self):
        return self._projection["event_id"]

    @property
    def decision_recovery_event_id(self):
        return self._projection["original_event_id"]

    @property
    def deadline_ns(self):
        return self._projection["call_deadline_monotonic_ns"]

    @property
    def arguments(self):
        return copy.deepcopy(self._frame["params"]["arguments"])

    def require_current(self):
        self._session.require_current()
        require(self in self._session._pending and self.stage == "pending"
                and time.monotonic_ns() < self.deadline_ns,
                "STALE_INVOCATION", "pending invocation is no longer current")


native_identities.bind_type("invocation", HostInvocation)


class _DecisionHost:
    """Identity port for the TA-2 canonical decision producer."""

    HostInvocation = HostInvocation
    HostAuthority = HostAuthority
    HostAuthorityError = HostAuthorityError


class HostSession(_NonTransferable):
    """A current LIVE enrollment. The binding owns proof, I/O, fencing and close."""

    def __init__(self, key, owner, actor, initial):
        require(key is LIVE_KEY and native_identities.owns_binding(owner),
                "ROLE_OPERATION_FORBIDDEN", "session requires an owned LIVE enrollment")
        owner.require_owner_process()
        self._owner = owner
        self._actor, self._initial = copy.deepcopy(actor), copy.deepcopy(initial)
        self._epoch, self._nonce = owner.epoch, owner.nonce
        self._pending, self._writer = set(), None

    @property
    def actor_cid(self):
        return self._actor["actor_cid"]

    @property
    def actor_data(self):
        return copy.deepcopy(self._actor)

    @property
    def initial_data(self):
        return copy.deepcopy(self._initial)

    @property
    def owned_runtime(self):
        self.require_current()
        return self._owner

    @property
    def authority(self):
        return self.owned_runtime.authority

    def _require_open(self):
        self._owner.require_owner_process()
        require(native_identities.owns_binding(self._owner) and not self._owner.fenced,
                "STALE_INVOCATION", "runtime binding is closed")

    def require_current(self):
        self._require_open()
        owner = self._owner
        require(owner.live_sessions.get(self.actor_cid) is self
                and owner.epoch == self._epoch and owner.nonce == self._nonce
                and time.monotonic_ns() < self._actor["actor_deadline_monotonic_ns"],
                "STALE_INVOCATION", "LIVE session is no longer current")

    @contextmanager
    def _state_lock(self, deadline_ns):
        lock = self._owner.lock
        require(lock.acquire(timeout=_remaining(deadline_ns)), "HOST_PROTOCOL_TIMEOUT",
                "original initial deadline expired")
        try:
            yield
        finally:
            lock.release()

    def invalidate(self):
        """Retire pending state under the binding's lock after fencing I/O."""
        for invocation in self._pending:
            if invocation.scope_entered or invocation._dispatching or invocation.stage == "unknown":
                invocation.stage = "unknown"
            else:
                invocation.stage = "retired"

    @contextmanager
    def _owned_operation(self, deadline, fence_reason):
        owner = self._owner
        with owner.appserver.operation(deadline):
            self.require_current()
            require(owner.active_guard is None, "ROLE_OPERATION_FORBIDDEN", fence_reason)
            with _terminal_operation(owner):
                owner.prove_current()
            self.require_current()
            require(owner.active_guard is None, "ROLE_OPERATION_FORBIDDEN", fence_reason)
            require(_remaining(deadline) > 0, "HOST_PROTOCOL_TIMEOUT", _ADMISSION_TIMEOUT)
            yield

    def receive_invocation(self):
        owner = self._owner
        self.require_current()
        fence_reason = "appserver IPC is forbidden inside a host fence"
        require(owner.active_guard is None, "ROLE_OPERATION_FORBIDDEN", fence_reason)
        deadline = min(time.monotonic_ns() + MAX_WAIT_SECONDS * _NS,
                       self._actor["actor_deadline_monotonic_ns"])
        with self._owned_operation(deadline, fence_reason), _terminal_operation(owner):
            frame = owner.appserver.receive_call()
            received = time.monotonic_ns()
            with _terminal_operation(owner, validating=True):
                self.require_current()
                correlation = _call_correlation(frame, self.actor_cid)
            projection = owner.exchange("pending_call", {
                **correlation, "deadline_monotonic_ns": deadline}, deadline / _NS, schema=LIVE_SCHEMA)
            with _terminal_operation(owner, validating=True):
                self.require_current()
                self._check_pending(projection, correlation, received, deadline)
                require(len(self._pending) < MAX_CALLS, "HOST_CALL_CONFLICT",
                        "host call correlation capacity exhausted")
                invocation = HostInvocation(LIVE_KEY, self, frame, projection)
                self._pending.add(invocation)
                return invocation

    def _check_pending(self, projection, correlation, received, deadline):
        fields(projection, set(_CORRELATION) | set(_ACTOR_FIELDS) | {
            "epoch", "call_started_monotonic_ns", "call_deadline_monotonic_ns",
            "mode", "original_event_id", "recovery_of"}, "HOST_PROTOCOL_ERROR")
        expected = {**correlation, "epoch": self._epoch, **{key: self._actor[key] for key in _ACTOR_FIELDS}}
        require(all(same_data(projection[key], value) for key, value in expected.items()),
                "CANONICAL_CORRELATION_MISMATCH", "pending call does not match received frame")
        start, end = projection["call_started_monotonic_ns"], projection["call_deadline_monotonic_ns"]
        require(uint(start) and uint(end) and self._actor["actor_started_monotonic_ns"] <= start <= received
                and time.monotonic_ns() < end <= min(deadline, start + MAX_WAIT_SECONDS * _NS),
                "STALE_INVOCATION", "original call budget is unavailable")
        if projection["mode"] == "normal":
            require(projection["original_event_id"] is None and projection["recovery_of"] is None,
                    "CANONICAL_CORRELATION_MISMATCH")
            return
        require(projection["mode"] == "original_only"
                and projection["original_event_id"] == correlation["event_id"],
                "CANONICAL_CORRELATION_MISMATCH")
        originals = [old for old in self._pending if old.stage == "unknown"
                     and same_data(projection["recovery_of"], {
                         **{key: old._projection[key] for key in _CORRELATION}, "epoch": self._epoch})]
        require(len(originals) == 1, "STALE_INVOCATION",
                "recovery has no actual owned original unknown call")

    def dispatch_decision(self, invocation, command):
        """Call the source-owned writer once and retain its result independently."""
        self.require_current()
        self._require_invocation(invocation)
        invocation.require_current()
        owner = self._owner
        require(owner.active_guard is None and not invocation._dispatching,
                "ROLE_OPERATION_FORBIDDEN", "decision dispatch is already active")
        with self._state_lock(invocation.deadline_ns):
            invocation.require_current()
            require(owner.active_guard is None and not invocation._dispatch_issued,
                    "HOST_CALL_CONFLICT", "decision dispatch was already issued")
            invocation._dispatch_issued = True
            prior_scope_entered = invocation.scope_entered
            if prior_scope_entered:
                invocation.stage = "unknown"
        if prior_scope_entered:
            if _fence(owner):
                _close_after_failure(owner)
            raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN", _UNKNOWN)
        writer, original = self._prepare_writer(invocation, command)
        return self._commit(invocation, writer, original)

    def _require_invocation(self, invocation):
        require(type(invocation) is HostInvocation and invocation.session is self,
                "ROLE_OPERATION_FORBIDDEN", "decision requires this session's invocation")

    def _prepare_writer(self, invocation, command):
        original = invocation._frame["params"]["arguments"]
        if not _matches_command(command, original):
            self._refuse_before_writer(invocation, "STALE_INVOCATION", "decision arguments do not match owned call")
        producer = getattr(self._owner.canonical_api, "ProtectedCanonicalDecisionWriter", None)
        if not isinstance(producer, type) or not callable(getattr(producer, "commit_decision", None)):
            self._refuse_before_writer(invocation, "CANONICAL_API_UNAVAILABLE",
                                       "canonical decision producer is unavailable")
        if self._writer is None:
            try:
                self._writer = producer(self._owner.canonical_root, self._owner.authority,
                                        host_authority=_DecisionHost, mailbox=self._owner.mailbox)
            except Exception:
                self._refuse_before_writer(invocation, "CANONICAL_API_UNAVAILABLE",
                                           "canonical decision producer is unavailable")
        if type(self._writer) is not producer:
            self._refuse_before_writer(invocation, "CANONICAL_API_UNAVAILABLE", "canonical decision producer changed")
        return self._writer, original

    @staticmethod
    def _refuse_before_writer(invocation, code, reason):
        invocation._completion = _PreDispatchRefusal(LIVE_KEY, invocation)
        invocation.stage = "complete"
        raise HostAuthorityError(code, reason) from None

    def _commit(self, invocation, writer, original):
        arguments = copy.deepcopy(original)
        # The canonical writer owns the original invocation deadline check. Its
        # no-effect stale result is a known outcome, even when preparation expired.
        self._require_open()
        invocation._dispatching = invocation._writer_entered = True
        try:
            result = writer.commit_decision(invocation, arguments)
            _check_decision_result(result, original)
            completion = _DecisionCompletion(LIVE_KEY, invocation, result)
            invocation._completion = completion
            invocation.stage = "unknown" if completion.state == "unknown" else "complete"
        except BaseException as exc:
            invocation.stage = "unknown"
            if _fence(self._owner):
                _close_after_failure(self._owner)
            if not isinstance(exc, Exception):
                raise
            raise HostAuthorityError("PROVIDER_OUTCOME_UNKNOWN", _UNKNOWN) from None
        finally:
            invocation._dispatching = False
        return copy.deepcopy(result)

    def reply(self, invocation, result):
        """Reply only after a source-issued completion or pre-dispatch refusal."""
        self.require_current()
        owner = self._owner
        fence_reason = "reply IPC is forbidden inside a host fence"
        require(owner.active_guard is None, "ROLE_OPERATION_FORBIDDEN", fence_reason)
        require(type(invocation) is HostInvocation and invocation.session is self
                and invocation in self._pending, "STALE_INVOCATION", "reply has no owned source completion")
        deadline = invocation.deadline_ns
        self._reply_proof(invocation)
        with owner.appserver.operation(deadline):
            self.require_current()
            require(owner.active_guard is None, "ROLE_OPERATION_FORBIDDEN", fence_reason)
            with self._state_lock(deadline):
                self.require_current()
                require(owner.active_guard is None, "ROLE_OPERATION_FORBIDDEN", fence_reason)
                proof = self._reply_proof(invocation)
                require(_remaining(deadline) > 0, "HOST_PROTOCOL_TIMEOUT", _ADMISSION_TIMEOUT)
                invocation._reply_issued = True
                # An authenticated original_only readback can name this
                # original while reply preflight or retirement is in flight.
                invocation.stage = "unknown"
            with _terminal_operation(owner):
                owner.prove_current()
                owner.appserver.reply(invocation.rpc_id, result)
                return self._retire_call(invocation, proof, deadline)

    @staticmethod
    def _reply_proof(invocation):
        proof = invocation._completion
        require(invocation.stage in ("complete", "unknown")
                and type(proof) in (_DecisionCompletion, _PreDispatchRefusal)
                and proof.invocation is invocation and invocation.scope_depth == 0 and not invocation._dispatching,
                "STALE_INVOCATION", "reply has no owned source completion")
        require(not invocation._reply_issued, "HOST_CALL_CONFLICT", "decision reply was already issued")
        return proof

    def _retire_call(self, invocation, proof, deadline):
        state = proof.state if type(proof) is _DecisionCompletion else None
        projection = invocation._projection
        retired = self._owner.exchange("retire_call", {
            **{key: projection[key] for key in _CORRELATION},
            "mode": projection["mode"], "recovery_of": copy.deepcopy(projection["recovery_of"]),
            "outcome": "unknown" if state == "unknown" else "replied", "canonical_state": state},
            deadline / _NS, schema=LIVE_SCHEMA)
        with _terminal_operation(self._owner, validating=True):
            fields(retired, {"actor_cid", "rpc_id", "state"}, "HOST_PROTOCOL_ERROR")
            require(retired["actor_cid"] == self.actor_cid and same_data(retired["rpc_id"], invocation.rpc_id)
                    and retired["state"] in ("awaiting_terminal", "retired", "publication_unknown"),
                    "HOST_PROTOCOL_ERROR", "invalid terminal observation")
            if state != "unknown" and retired["state"] != "publication_unknown":
                invocation.stage = "retired"
        # The runtime still owns the actual terminal legs. Old unknowns stay retained.
        return copy.deepcopy(retired)


def _call_correlation(frame, actor_cid):
    # ProtocolClient has already bounded and decoded the envelope.
    params = frame["params"]
    require(params["threadId"] == actor_cid and params.get("namespace") in (None, "", "functions")
            and params["tool"] == "aegis_decision", "ROLE_OPERATION_FORBIDDEN",
            "call is outside the enrolled decision ceiling")
    arguments = params["arguments"]
    require(type(arguments) is dict and _slug(arguments.get("event_id")),
            "HOST_PROTOCOL_ERROR", "call has no bounded decision correlation")
    return {"actor_cid": actor_cid, "rpc_id": frame["id"], "thread_id": params["threadId"],
            "turn_id": params["turnId"], "call_id": params["callId"], "namespace": params.get("namespace"),
            "tool": params["tool"], "event_id": arguments["event_id"]}


def _text(value, maximum):
    return type(value) is str and 0 < len(value) <= maximum and "\x00" not in value


def _slug(value):
    return type(value) is str and len(value) <= 80 and SLUG.fullmatch(value) is not None


def _matches_command(command, original):
    return (type(command) is dict and len(command) == len(_COMMAND_FIELDS)
            and all(type(key) is str for key in command) and command.keys() == _COMMAND_FIELDS
            and same_data(command, original))


class _PreDispatchRefusal(_NonTransferable):
    def __init__(self, key, invocation):
        require(key is LIVE_KEY and not invocation.scope_entered
                and not invocation._dispatching and invocation.scope_depth == 0,
                "ROLE_OPERATION_FORBIDDEN", "pre-dispatch proof is unavailable")
        self.invocation = invocation


class _DecisionCompletion(_NonTransferable):
    def __init__(self, key, invocation, result):
        require(key is LIVE_KEY and invocation._writer_entered and invocation.scope_depth == 0,
                "ROLE_OPERATION_FORBIDDEN", "decision completion is unavailable")
        self.invocation = invocation
        self.state = result["state"]


def _check_decision_result(result, command):
    code = "PROVIDER_OUTCOME_UNKNOWN"
    require(type(result) is dict and len(result) in (len(_RESULT_FIELDS), len(_RESULT_FIELDS) + 1), code)
    fields(result, _RESULT_FIELDS | ({"next_action"} if "next_action" in result else set()), code)
    state = result["state"]
    require(type(state) is str and state in _EFFECTS and result["effect"] == _EFFECTS[state]
            and result["schema"] == "aegis.protected-decision-commit/v1"
            and result["native_qualified"] is False and _text(result["reason"], 1024)
            and all(same_data(result[key], command[key]) for key in _TARGET), code)
    if state in ("recorded", "recovered"):
        receipt = result["receipt"]
        fields(receipt, {"event_id", "sequence", "event_sha256", "execution_enabled"}, code)
        require(result["code"] is None and "next_action" not in result
                and receipt["event_id"] == command["event_id"] and uint(receipt["sequence"])
                and sha(receipt["event_sha256"]) and receipt["execution_enabled"] is False, code)
    else:
        require(result["receipt"] is None and _text(result["code"], 256)
                and result.get("next_action", _NEXT_ACTION) == _NEXT_ACTION, code)
