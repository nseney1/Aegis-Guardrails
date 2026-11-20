"""Confined lifecycle journal and protected writers over caller-injected ports.

The core mailbox owns descriptors and locks. Host types come exclusively from
the injected authority port; no dynamic host discovery or tools imports occur.
"""
from contextlib import contextmanager
import copy
import hashlib
import os
from threading import local

from aegis_core import team_lifecycle as domain
from aegis_core.team_mailbox import Mailbox
from aegis_core.team_mailbox_index import Index
from aegis_core.team_mailbox_primitives import MailboxRefusal, render_mailbox_refusal, safe_path


__all__ = ['CanonicalGenesisError', 'InitialBootstrapMissing', 'Lifecycle', 'ProtectedCanonicalBootstrapWriter', 'ProtectedCanonicalDecisionWriter', 'ProtectedCanonicalEnrollmentWriter', 'initialize', 'load_json', 'prepare_initial']


@contextmanager
def _refusals():
    """Translate storage failures during entry, body and exit; preserve host errors."""
    try:
        yield
    except MailboxRefusal as error:
        raise domain.LifecycleRefusal(render_mailbox_refusal(error)["reason"]) from None


class _BodyError(Exception):
    """Carry a caller failure through storage cleanup without coercing its type."""

    def __init__(self, original):
        super().__init__("lifecycle caller failed")
        self.original = original


@contextmanager
def _caller_errors():
    try:
        yield
    except Exception as error:
        raise _BodyError(error) from None


class _Unpublished(domain.LifecycleRefusal):
    """A capacity/target failure originating in read-only publication preflight."""


def _advance(policy, state, record):
    """Apply exactly the reader contract to a candidate before publication."""
    domain.fields(record, {"schema", "sequence", "previous", "policy_sha256", "at", "envelope", "event_sha256"})
    domain.require(record["schema"] == domain.JOURNAL and type(record["sequence"]) is int
                   and record["sequence"] == state["sequence"] + 1 <= domain.MAX_EVENTS)
    domain.require(record["previous"] == state["head"])
    domain.require(record["policy_sha256"] == domain.digest(policy))
    domain.require(record["event_sha256"] == domain.digest(record["envelope"]))
    domain.parse_time(record["at"])
    domain.require(record["envelope"]["id"] not in state["receipts"])
    candidate = copy.deepcopy(state)
    domain.reduce_event(policy, candidate, record["envelope"], record["at"])
    receipt = Lifecycle.finish(candidate, record)
    if record["envelope"].get("schema") == domain.INITIAL_ENVELOPE and record["sequence"] == 1:
        domain.checkpoint(policy, candidate)
    return candidate, receipt


@domain.boundary
def load_json(path, *, store, parent=None):
    domain.require(callable(getattr(store, "read", None)))
    path = domain.safe_path(path)
    return domain.strict_json(store.read(path, limit=domain.MAX_BYTES, parent=parent))


class InitialBootstrapMissing(domain.LifecycleRefusal):
    def __init__(self):
        super().__init__("initial_genesis_required")


class Lifecycle:
    """Borrow the mailbox's store; the mailbox context retains ownership."""
    @domain.boundary
    def __init__(self, root, *, mailbox, clock=None):
        domain.require(isinstance(mailbox, (Mailbox, Index)))
        self.root, self.store = domain.safe_path(root), mailbox.store
        domain.require(clock is None or callable(clock))
        self.clock = clock or mailbox.timestamp
        self._local = local()

    @contextmanager
    @domain.boundary
    def view(self, *, write=False):
        with _refusals():
            try:
                with self.store.directory(self.root) as root_fd:
                    if write:
                        with self.store.lock(self.root, parent=root_fd):
                            with self.store.directory(self.root / "events", parent=root_fd) as events_fd:
                                previous = getattr(self._local, "writer_fds", None)
                                self._local.writer_fds = root_fd, events_fd
                                try:
                                    with _caller_errors():
                                        yield root_fd, events_fd
                                finally:
                                    self._local.writer_fds = previous
                    else:
                        with self.store.directory(self.root / "events", parent=root_fd) as events_fd:
                            with _caller_errors():
                                yield root_fd, events_fd
            except _BodyError as error:
                raise error.original from None

    @domain.boundary
    def load(self):
        with self.view() as (root_fd, events_fd):
            policy, state, _ = self.replay(root_fd, events_fd)
            return policy, state

    @domain.boundary
    def replay(self, root_fd, events_fd):
        raw = self.store.read(self.root / "policy.json", limit=domain.MAX_BYTES, parent=root_fd)
        policy = domain.validate_policy(domain.strict_json(raw))
        snapshot = [("policy.json", hashlib.sha256(raw).hexdigest())]
        state, genesis_checkpoint = domain.initial_state(policy), None
        paths = self.store.entries(self.root / "events", parent=events_fd)
        domain.require(len(paths) <= domain.MAX_EVENTS)
        for index, path in enumerate(paths, 1):
            domain.require(path.name == "%06d.json" % index)
            raw = self.store.read(path, limit=domain.MAX_BYTES, parent=events_fd)
            snapshot.append((path.name, hashlib.sha256(raw).hexdigest()))
            record = domain.strict_json(raw)
            state, _ = _advance(policy, state, record)
            if record["envelope"].get("schema") == domain.INITIAL_ENVELOPE and index == 1:
                genesis_checkpoint = copy.deepcopy(domain.checkpoint(policy, state))
        self._local.snapshot = snapshot
        self._local.policy, self._local.state = copy.deepcopy(policy), copy.deepcopy(state)
        return policy, state, genesis_checkpoint

    @domain.boundary
    def initial_bootstrap(self):
        with self.view() as (root_fd, events_fd):
            policy, state, genesis = self.replay(root_fd, events_fd)
        if genesis is None:
            raise InitialBootstrapMissing()
        bootstrap = state["initial_bootstrap"]
        return {"schema": "aegis.initial-bootstrap-snapshot/v1", "policy_sha256": domain.digest(policy),
                "genesis_checkpoint": genesis, "genesis_receipt": copy.deepcopy(bootstrap["genesis"]["receipt"]),
                "reservations": copy.deepcopy(bootstrap["reservations"]),
                "creations": [copy.deepcopy(bootstrap["creations"][cid]) for cid in sorted(bootstrap["creations"])]}

    @staticmethod
    @domain.boundary
    def finish(state, record):
        candidate = copy.deepcopy(state)
        envelope = record["envelope"]
        receipt = {"event_id": envelope["id"], "sequence": record["sequence"],
                   "event_sha256": record["event_sha256"], "execution_enabled": False}
        receipts, head = candidate["receipts"], domain.digest(record)
        row = None
        if envelope.get("schema") == domain.INITIAL_ENVELOPE:
            bootstrap = candidate["initial_bootstrap"]
            row = (bootstrap["genesis"] if envelope["event"]["type"] == "initial_reservations"
                   else bootstrap["creations"][envelope["event"]["actor_cid"]])
        candidate["sequence"], candidate["head"] = record["sequence"], head
        receipts[receipt["event_id"]] = receipt
        if row is not None:
            row["receipt"] = copy.deepcopy(receipt)
        domain.bounded_tree(candidate, limit=67108864, ascii_strings=True)
        state.clear()
        state.update(candidate)
        return receipt


    @domain.boundary
    def require_target(self, root_fd, events_fd):
        with self.store.directory(self.root) as current_root:
            with self.store.directory(self.root / "events", parent=current_root) as current_events:
                for before, after in ((root_fd, current_root), (events_fd, current_events)):
                    a, b = os.fstat(before), os.fstat(after)
                    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                        raise domain.LifecycleRefusal("target_changed")

    @domain.boundary
    def require_snapshot(self, root_fd, events_fd):
        expected = self._local.snapshot
        names = [path.name for path in self.store.entries(self.root / "events", parent=events_fd)]
        if names != [name for name, _sha in expected[1:]]:
            raise domain.LifecycleRefusal("target_changed")
        for name, sha in expected:
            parent = root_fd if name == "policy.json" else events_fd
            path = self.root / name if name == "policy.json" else self.root / "events" / name
            raw = self.store.read(path, limit=domain.MAX_BYTES, parent=parent)
            if hashlib.sha256(raw).hexdigest() != sha:
                raise domain.LifecycleRefusal("target_changed")

    @domain.boundary
    def publish(self, record, root_fd, events_fd):
        try:
            raw = domain.encoded(record, limit=domain.MAX_BYTES - 1) + b"\n"
            domain.strict_json(raw)
            candidate, _ = _advance(self._local.policy, self._local.state, record)
            snapshot = [*self._local.snapshot, ("%06d.json" % record["sequence"], hashlib.sha256(raw).hexdigest())]
            try:
                self.require_target(root_fd, events_fd)
                self.require_snapshot(root_fd, events_fd)
            except (ValueError, OSError):
                raise domain.LifecycleRefusal("target_changed") from None
        except domain.LifecycleRefusal as error:
            if error.code in {"target_changed", "too_large"}:
                raise _Unpublished(error.code) from None
            raise
        path = self.root / "events" / ("%06d.json" % record["sequence"])
        self.store.publish(path, raw, limit=domain.MAX_BYTES, parent=events_fd)
        self._local.snapshot = snapshot
        self._local.state = candidate

    @domain.boundary
    def record(self, envelope):
        domain.bounded_tree(envelope, limit=domain.MAX_BYTES)
        with self.view(write=True) as (root_fd, events_fd):
            policy, state, _ = self.replay(root_fd, events_fd)
            return self.record_under_lock(envelope, policy, state)

    @domain.boundary
    def record_under_lock(self, envelope, policy, state):
        """The injected observer uses view(write=True) and replay before this call."""
        fds = getattr(self._local, "writer_fds", None)
        domain.require(fds is not None)
        root_fd, events_fd = fds
        domain.bounded_tree(envelope, limit=domain.MAX_BYTES)
        domain.bounded_tree(state, limit=67108864)
        domain.fields(envelope, {"id", "actor", "generation", "custody", "event"})
        domain.matching(envelope["id"], domain.SLUG, "event id")
        previous = state["receipts"].get(envelope["id"])
        if previous:
            domain.require(previous["event_sha256"] == domain.digest(envelope))
            return previous
        domain.actor_for(policy, state, envelope)
        domain.require(state["sequence"] < domain.MAX_EVENTS)
        record = {"schema": domain.JOURNAL, "sequence": state["sequence"] + 1, "previous": state["head"],
                  "policy_sha256": domain.digest(policy), "at": self.clock(), "envelope": envelope,
                  "event_sha256": domain.digest(envelope)}
        candidate, receipt = _advance(policy, state, record)
        event = envelope["event"]
        if event["type"] == "decision" and event["decision"] == "approve":
            request = candidate["requests"][event["request_id"]]["request"]
            domain.require(domain.parse_time(record["at"]) < domain.parse_time(request["continuation"]["expires_at"]))
        self.publish(record, root_fd, events_fd)
        state.clear()
        state.update(candidate)
        return receipt

    @domain.boundary
    def status(self):
        policy, state = self.load()
        obligations, candidates, holds = [], [], {}
        small_change_ready = []
        at = self.clock()
        for identifier, row in sorted(state["requests"].items()):
            resolution = row["resolution"]
            if resolution and resolution["kind"] in {"complete", "next"}:
                continue
            owner = resolution if resolution else row["request"]
            stage = "unknown_effect" if domain.unknown_effect(row) else "blocked" if resolution else "pending"
            obligations.append({"request_id": identifier, "request_sha256": row["raw"]["sha256"], "state": stage,
                                "owner": owner["owner"], "next_decision": owner["next_decision"],
                                "blocker": resolution if resolution and resolution["kind"] == "blocked" else None})
            if "small_change" in row and domain.unknown_effect(row):
                writer = row["start"] or row["intent"]
                current = state["current"]["operator"]
                if (writer["actor"], writer["generation"]) != (current, policy["actors"][current]["generation"]):
                    holds[identifier] = ("small-change interrupted writer %s generation %s; T1 dispatcher resume required"
                                         % (writer["actor"], writer["generation"]))
            if not resolution and row["intent"] is None:
                try:
                    operator = state["current"]["operator"]
                    domain.require(domain.active_seconds(state, operator, at) < policy["actors"][operator]["cap_seconds"],
                            "actor cumulative active cap reached")
                    if "small_change" in row:
                        domain.small_change_execution(policy, state, row, at)
                    else:
                        domain.approved_authority(state, row, at)
                except ValueError as exc:
                    holds[identifier] = getattr(exc, "continuation_reason", "lifecycle refused: invalid_record")
                else:
                    if "small_change" in row:
                        small_change_ready.append(identifier)
                        holds[identifier] = "small-change requires the T1 dispatcher"
                    else:
                        candidates.append(identifier)
        result = {"schema": "aegis.lifecycle-status/v1", "state": "pending" if obligations else "complete" if state["requests"] else "untracked",
                "work_complete": bool(state["requests"]) and not obligations, "coverage": "registered_requests_only",
                "execution_enabled": False, "native_enforcement": "unqualified", "policy_sha256": domain.digest(policy),
                "obligations": obligations, "continuation_candidates": candidates, "continuation_holds": holds, **state}
        # This view-only key never changes canonical-only status or checkpoints.
        if any("small_change" in row for row in state["requests"].values()):
            result["small_change_ready"] = small_change_ready
        return result

@domain.boundary
def initialize(root, policy, *, mailbox):
    domain.require(isinstance(mailbox, (Mailbox, Index)))
    store, root = mailbox.store, safe_path(domain.safe_path(root))
    domain.validate_policy(policy)
    raw = domain.encoded(policy, limit=domain.MAX_BYTES - 1) + b"\n"
    domain.require(len(raw) <= domain.MAX_BYTES)
    with store.evidence_transaction():
        domain.require(not store.exists(root))
        undo = []
        with store.directory(root.parent) as parent_fd:
            with store.directory(root, create=True, parent=parent_fd, undo=undo) as root_fd:
                with store.directory(root / "events", create=True, parent=root_fd):
                    store.publish(root / "policy.json", raw, limit=domain.MAX_BYTES, parent=root_fd, undo=undo)
                    os.fsync(root_fd)
                    os.fsync(parent_fd)
    return {"policy_sha256": domain.digest(policy), "execution_enabled": False, "native_enforcement": "unqualified"}


class _ProtectedWriter:
    @domain.boundary
    def __init__(self, root, authority=None, *, mailbox=None, host_authority=None, clock=None):
        domain.require(mailbox is None or isinstance(mailbox, (Mailbox, Index)))
        domain.require(clock is None or callable(clock))
        self.root, self.authority, self._authority = domain.safe_path(root), authority, authority
        self.mailbox, self.host, self.clock = mailbox, host_authority, clock
        self._local, self._last_failure = local(), None

    @contextmanager
    @domain.boundary
    def transaction(self):
        with _refusals():
            reader = Lifecycle(self.root, mailbox=self.mailbox, clock=self.clock)
            with reader.view(write=True) as fds:
                reader.replay(*fds)
                self._local.active = reader, fds
                try:
                    yield reader
                finally:
                    del self._local.active

    @domain.boundary
    def read_record(self, path):
        reader, (root_fd, events_fd) = self._local.active
        return load_json(path, store=reader.store, parent=events_fd)

    @domain.boundary
    def publish_record(self, record):
        reader, fds = self._local.active
        reader.publish(record, *fds)


@domain.boundary
def prepare_initial(policy, state, envelope, at):
    domain.require(state["sequence"] < domain.MAX_EVENTS)
    record = {"schema": domain.JOURNAL, "sequence": state["sequence"] + 1, "previous": state["head"],
              "policy_sha256": domain.digest(policy), "at": at, "envelope": envelope,
              "event_sha256": domain.digest(envelope)}
    _candidate, receipt = _advance(policy, state, record)
    domain.require(len(domain.encoded(record, limit=domain.MAX_BYTES - 1)) + 1 <= domain.MAX_BYTES)
    return record, receipt


_GENESIS_REASONS = {
    "HOST_AUTHORITY_REFUSED": "current protected host authority is required",
    "PLAN_MISMATCH": "protected bootstrap plan does not match",
    "POLICY_INVALID": "protected bootstrap evidence is invalid",
    "ROOT_ALREADY_EXISTS": "protected canonical root already exists",
    "GENESIS_PUBLICATION_UNKNOWN": "canonical genesis may have been published; retain the original root and reservations",
}


class CanonicalGenesisError(domain.LifecycleRefusal, PermissionError):
    """Closed genesis refusal/ambiguity; no implicit retry or cleanup grant."""

    __slots__ = ("_code", "_possible")

    def __init__(self, code, *, possible=False):
        domain.require(type(code) is str and code in _GENESIS_REASONS and type(possible) is bool)
        self._code, self._possible = code, possible
        ValueError.__init__(self, _GENESIS_REASONS[code])

    @domain.boundary
    def as_dict(self):
        return {"state": self.state, "effect": self.effect, "code": self.code,
                "reason": self.reason, "next_action": self.next_action}

    @property
    def code(self):
        return self._code

    @property
    def reason(self):
        return _GENESIS_REASONS[self._code]

    @property
    def state(self):
        return "unknown" if self._possible else "refused"

    @property
    def next_action(self):
        return "Reconcile the original canonical root and protected host evidence before retrying."

    @property
    def effect(self):
        return "possible" if self._possible else "none"


class ProtectedCanonicalEnrollmentWriter(_ProtectedWriter):
    """Fixed-root protected genesis; only actual H source constructs its guard."""

    def initialize_reserved_genesis(self, owned_runtime, reserved_enrollments, approved_plan_ref):
        domain.require(isinstance(self, ProtectedCanonicalEnrollmentWriter))
        host = self.host

        if host is None:
            raise domain.LifecycleRefusal("unqualified")
        claimed = False
        try:
            if (type(self.authority) is not host.HostAuthority
                    or self.authority.owned_runtime is not owned_runtime):
                raise CanonicalGenesisError("HOST_AUTHORITY_REFUSED")
            # These are inert copies of already authenticated protected inputs.
            # No caller-selected plan file is opened, or read back under a fence.
            if (self.root != owned_runtime.canonical_root
                    or approved_plan_ref != owned_runtime.approved_plan_ref):
                raise CanonicalGenesisError("PLAN_MISMATCH")
            plan = owned_runtime.accepted_plan
            domain.fields(plan, {"source", "actors", "current", "successors"})
            domain.evidence([approved_plan_ref])
            policy = domain.validate_policy({"schema": domain.POLICY, "authority": [copy.deepcopy(approved_plan_ref)], **plan})
            domain.require(len(domain.encoded(policy, limit=domain.MAX_BYTES - 1)) + 1 <= domain.MAX_BYTES, "bootstrap policy exceeds lifecycle byte limit")
            domain.require(isinstance(reserved_enrollments, tuple), "bootstrap requires owned reservation tuple")
            rows = []
            for reservation in reserved_enrollments:
                if type(reservation) is not host.ReservedEnrollment:
                    raise CanonicalGenesisError("HOST_AUTHORITY_REFUSED")
                rows.append(reservation.witness)
            envelope = {"schema": domain.INITIAL_ENVELOPE, "id": "initial-genesis",
                        "event": {"type": "initial_reservations", "approved_plan": copy.deepcopy(approved_plan_ref),
                                  "channel_witness": owned_runtime.channel_witness, "reservations": rows}}
            record, _ = prepare_initial(policy, domain.initial_state(policy), envelope, self.clock() if self.clock else self.mailbox.timestamp())
            with self.authority.bootstrap_fence(owned_runtime, approved_plan_ref, reserved_enrollments) as guard:
                guard.require_reserved_genesis_current()
                # Existing-root refusal is known not to claim it. Other errors
                # during this exclusive claim conservatively retain UNKNOWN.
                if self.mailbox.store.exists(self.root):
                    raise CanonicalGenesisError("ROOT_ALREADY_EXISTS")
                guard.require_reserved_genesis_current()
                claimed = True
                initialize(self.root, policy, mailbox=self.mailbox)
                with self.transaction() as reader:
                    guard.require_reserved_genesis_current()
                    self.publish_record(record)
                    snapshot = reader.initial_bootstrap()
                    enrollments = []
                    for row in snapshot["reservations"]:
                        item = {name: row[name] for name in ("actor_cid", "role", "generation", "profile_sha256",
                                                            "cap_seconds", "channel_instance_sha256")}
                        item["reservation_witness_sha256"] = domain.digest(row)
                        enrollments.append(item)
                    answer = {"schema": "aegis.protected-reserved-enrollment-receipt/v1",
                              "policy_sha256": snapshot["policy_sha256"],
                              "checkpoint_sha256": snapshot["genesis_checkpoint"]["sha256"],
                              "enrollments": enrollments}
                    guard.require_reserved_genesis_current()
                    return answer
        except CanonicalGenesisError as exc:
            if claimed:
                raise CanonicalGenesisError("GENESIS_PUBLICATION_UNKNOWN", possible=True) from exc
            raise
        except host.HostAuthorityError as exc:
            code = "GENESIS_PUBLICATION_UNKNOWN" if claimed else "HOST_AUTHORITY_REFUSED"
            raise CanonicalGenesisError(code, possible=claimed) from exc
        except (ValueError, OSError, KeyError, AttributeError) as exc:
            code = "GENESIS_PUBLICATION_UNKNOWN" if claimed else "POLICY_INVALID"
            raise CanonicalGenesisError(code, possible=claimed) from exc


_INITIAL_REASONS = {
    "HOST_AUTHORITY_REFUSED": "current protected INITIAL authority is required",
    "INITIAL_GENESIS_REQUIRED": "protected INITIAL genesis is required",
    "INITIAL_CREATION_FORBIDDEN": "INITIAL creation requires its original current actor",
    "INITIAL_CORRELATION_MISMATCH": "protected INITIAL correlation does not match",
    "INITIAL_EVENT_CONFLICT": "INITIAL event identity conflicts with original evidence",
    "CANONICAL_INVALID": "canonical INITIAL history is invalid",
    "CANONICAL_BUSY": "canonical writer exclusion is busy",
    "INITIAL_CREATION_PUBLICATION_UNKNOWN": "INITIAL intent may have been published; retain its original identity",
}


def _initial_result(state, *, code=None, cid=None, event_id=None, receipt=None):
    return {"schema": "aegis.initial-creation-result/v1", "state": state,
            "effect": {"recorded": "canonical_initial_creation", "recovered": "none",
                       "refused": "none", "unknown": "possible"}[state],
            "code": code, "reason": _INITIAL_REASONS[code] if code else None,
            "actor_cid": cid, "event_id": event_id, "receipt": copy.deepcopy(receipt),
            "native_qualified": False,
            **({"next_action": "Reconcile original canonical evidence before retrying."} if code else {})}


def _initial_creation_envelope(policy, snapshot, witness):
    event = {name: witness[name] for name in ("actor_cid", "role", "generation", "profile_sha256",
                                             "cap_seconds", "channel_instance_sha256", "approved_plan_sha256")}
    event.update(type="initial_creation", genesis_event_sha256=snapshot["genesis_receipt"]["event_sha256"],
                 reservation_set_sha256=domain.digest(snapshot["reservations"]), reservation_witness_sha256=domain.digest(witness))
    return {"schema": domain.INITIAL_ENVELOPE, "id": domain.initial_key(policy, witness["actor_cid"]), "event": event}


class ProtectedCanonicalBootstrapWriter(_ProtectedWriter):
    """Commit one INITIAL intent; never bind or start a runtime from a receipt."""

    def commit_initial_creation(self, bootstrap_guard, reserved_enrollment):
        domain.require(isinstance(self, ProtectedCanonicalBootstrapWriter))
        host = self.host

        if host is None:
            return domain.LifecycleRefusal("unqualified").as_dict()
        possible, cid, identifier = False, None, None

        def refused(code):
            return _initial_result("refused", code=code, cid=cid, event_id=identifier)

        try:
            if (type(bootstrap_guard) is not host.InitialCreationGuard
                    or type(reserved_enrollment) is not host.ReservedEnrollment):
                return refused("HOST_AUTHORITY_REFUSED")
            bootstrap_guard.require_initial_identity_current(reserved_enrollment)
            if self.root != reserved_enrollment.owned_runtime.canonical_root:
                return refused("INITIAL_CORRELATION_MISMATCH")
            with self.transaction() as reader:
                bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                policy, state = reader.load()
                snapshot = reader.initial_bootstrap()
                bootstrap_guard.require_initial_creation_current(reserved_enrollment, policy, state, None)
                cid = reserved_enrollment.actor_cid
                identifier = domain.initial_key(policy, cid)
                original = next((row for row in snapshot["creations"] if row["actor_cid"] == cid), None)
                if original is not None:
                    bootstrap_guard.require_initial_creation_current(reserved_enrollment, policy, state, original)
                    expected = _initial_creation_envelope(policy, snapshot, reserved_enrollment.witness)
                    if (original["envelope"] != expected
                            or original["receipt"]["event_sha256"] != domain.digest(expected)):
                        return refused("INITIAL_EVENT_CONFLICT")
                    bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                    answer = _initial_result("recovered", cid=cid, event_id=identifier, receipt=original["receipt"])
                else:
                    row = next((row for row in snapshot["reservations"] if row["actor_cid"] == cid), None)
                    if row is None:
                        return refused("INITIAL_CORRELATION_MISMATCH")
                    bootstrap_guard.require_initial_creation_current(reserved_enrollment, policy, state, row)
                    if (cid not in policy["current"].values()
                            or state["current"].get(policy["actors"][cid]["role"]) != cid):
                        return refused("INITIAL_CREATION_FORBIDDEN")
                    if row != reserved_enrollment.witness:
                        return refused("INITIAL_CORRELATION_MISMATCH")
                    bootstrap_guard.require_initial_creation_new(reserved_enrollment, policy, state, row)
                    envelope = _initial_creation_envelope(policy, snapshot, row)
                    if identifier in state["receipts"]:
                        return refused("INITIAL_EVENT_CONFLICT")
                    record, receipt = prepare_initial(policy, state, envelope, reader.clock())
                    bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                    possible = True
                    self.publish_record(record)
                    bootstrap_guard.require_initial_identity_current(reserved_enrollment)
                    answer = _initial_result("recorded", cid=cid, event_id=identifier, receipt=receipt)
            bootstrap_guard.require_initial_identity_current(reserved_enrollment)
            return answer
        except host.HostAuthorityError:
            if not possible:
                return refused("HOST_AUTHORITY_REFUSED")
        except InitialBootstrapMissing:
            if not possible:
                return refused("INITIAL_GENESIS_REQUIRED")
        except domain.LifecycleRefusal as exc:
            if not possible:
                if exc.code == "busy":
                    return refused("CANONICAL_BUSY")
                if exc.code == "missing":
                    return refused("INITIAL_GENESIS_REQUIRED")
                return refused("CANONICAL_INVALID")
        except (ValueError, OSError, KeyError, AttributeError) as exc:
            if not possible:
                if isinstance(exc, FileNotFoundError):
                    return refused("INITIAL_GENESIS_REQUIRED")
                return refused("CANONICAL_INVALID")
        return _initial_result("unknown", code="INITIAL_CREATION_PUBLICATION_UNKNOWN", cid=cid, event_id=identifier)


_DECISION_ERRORS = {
    "INVALID_DECISION_INPUT": "invalid decision command",
    "HOST_AUTHORITY_UNAVAILABLE": "protected host authority is unavailable",
    "UNAUTHORIZED_ROLE": "decision requires a current ROOT HostInvocation",
    "STALE_INVOCATION": "decision invocation is stale",
    "SOURCE_MISMATCH": "protected canonical source binding mismatch",
    "REQUEST_HASH_MISMATCH": "request sha256 mismatch",
    "UNKNOWN_REQUEST": "unknown request id",
    "BOUNDED_AUTHORITY_EXPIRED": "bounded authority expired",
    "REPLAY_CONFLICT": "event id conflicts with different decision payload",
    "DECISION_CONFLICT": "decision requires an authority request and a valid first approve/deny or approve-to-deny transition",
    "CAP_REACHED": "actor cumulative active cap reached",
    "CANONICAL_WRITER_BUSY": "mailbox writer is busy; inspect an abandoned lock before retrying",
    "PUBLICATION_UNKNOWN": "canonical decision publication is unresolved",
    "target_changed": "canonical target changed before publication",
    "too_large": "canonical lifecycle capacity exceeded",
}


def _decision_correlations(command):
    if type(command) is not dict or len(command) != 5 or not all(type(key) is str for key in command):
        return {name: None for name in ("event_id", "request_id", "request_sha256")}
    result = {}
    for name, pattern in (("event_id", domain.SLUG), ("request_id", domain.SLUG), ("request_sha256", domain.SHA256)):
        value = command.get(name)
        result[name] = value if type(value) is str and len(value) <= 80 and pattern.fullmatch(value) is not None else None
    return result


def _decision_command(command):
    if (type(command) is not dict or len(command) != 5 or not all(type(key) is str for key in command)
            or set(command) != {"event_id", "request_id", "request_sha256", "decision", "reason"}
            or any(value is None for value in _decision_correlations(command).values())):
        return None
    decision, reason = command["decision"], command["reason"]
    if (type(decision) is not str or decision not in {"approve", "deny"}
            or type(reason) is not str or not 0 < len(reason) <= 1024 or "\x00" in reason):
        return None
    return dict(command)


def _decision_result(command, state, code=None, receipt=None):
    reasons = {"recorded": "canonical decision recorded", "recovered": "original canonical receipt recovered"}
    return {"schema": "aegis.protected-decision-commit/v1", "state": state,
            "effect": {"recorded": "canonical_decision", "recovered": "none",
                       "refused": "none", "unknown": "possible"}[state],
            "code": code, "reason": _DECISION_ERRORS[code] if code else reasons[state],
            **_decision_correlations(command), "receipt": copy.deepcopy(receipt), "native_qualified": False,
            **({"next_action": "Reconcile original canonical evidence before retrying."} if code else {})}


class ProtectedCanonicalDecisionWriter(_ProtectedWriter):
    """One protected decision transaction; results are data, never runtime grants."""

    def commit_decision(self, invocation, command):
        domain.require(isinstance(self, ProtectedCanonicalDecisionWriter))
        host = self.host

        if host is None:
            return domain.LifecycleRefusal("unqualified").as_dict()
        supplied = command
        command = _decision_command(supplied)
        if command is None:
            return _decision_result(supplied, "refused", "INVALID_DECISION_INPUT")
        if type(self._authority) is not host.HostAuthority:
            return _decision_result(command, "refused", "HOST_AUTHORITY_UNAVAILABLE")
        if type(invocation) is not host.HostInvocation:
            return _decision_result(command, "refused", "UNAUTHORIZED_ROLE")
        possible = [False]
        self._last_failure = None

        def refused(code):
            return _decision_result(command, "refused", code)

        try:
            return self._commit_current(invocation, command, possible)
        except host.HostAuthorityError as exc:
            self._last_failure = exc
            # The host's own UNKNOWN covers effects outside this call (for example an
            # earlier scope of the same invocation), so it is never a no-effect refusal.
            if not possible[0] and exc.code != "PROVIDER_OUTCOME_UNKNOWN":
                mappings = {
                    "UNSUPPORTED_HOST": "HOST_AUTHORITY_UNAVAILABLE",
                    "UNPROTECTED_DEPLOYMENT": "HOST_AUTHORITY_UNAVAILABLE",
                    "HOST_PROFILE_UNQUALIFIED": "HOST_AUTHORITY_UNAVAILABLE",
                    "CANONICAL_API_UNAVAILABLE": "HOST_AUTHORITY_UNAVAILABLE",
                    "HOST_PROTOCOL_ERROR": "STALE_INVOCATION", "HOST_PROTOCOL_TIMEOUT": "STALE_INVOCATION",
                    "HOST_CALL_CONFLICT": "STALE_INVOCATION", "STALE_INVOCATION": "STALE_INVOCATION",
                    "ROLE_OPERATION_FORBIDDEN": "UNAUTHORIZED_ROLE", "CANONICAL_CORRELATION_MISMATCH": "SOURCE_MISMATCH",
                    "PROVIDER_HANDLE_INVALID": "UNAUTHORIZED_ROLE",
                    "HISTORY_CURSOR_INVALID": "UNAUTHORIZED_ROLE"}
                return refused(mappings.get(exc.code, "HOST_AUTHORITY_UNAVAILABLE"))
        except domain.LifecycleRefusal as exc:
            self._last_failure = exc
            if exc.code in {"target_changed", "too_large"} and (
                    not possible[0] or isinstance(exc, _Unpublished)):
                return refused(exc.code)
            if exc.code == "busy" and not possible[0]:
                return refused("CANONICAL_WRITER_BUSY")
        except Exception as exc:
            self._last_failure = exc
        return _decision_result(command, "unknown", "PUBLICATION_UNKNOWN")


    def _commit_current(self, invocation, command, possible):
        def refused(code):
            return _decision_result(command, "refused", code)
        with self._authority.effect_fence(invocation, "decision"):
            if self.root != self._authority.canonical_root:
                return refused("SOURCE_MISMATCH")
            with self.transaction() as reader:
                policy, state = reader.load()
                # Neither an unknown target nor an original receipt may be
                # disclosed until current identity is proven under BOTH.
                self._authority.require_current(invocation, policy, state, None)
                self._authority.require_decision_command(invocation, command)
                if invocation.event_id != command["event_id"]:
                    return refused("STALE_INVOCATION")
                recovery = invocation.decision_recovery_event_id
                if recovery is not None and (type(recovery) is not str
                        or domain.SLUG.fullmatch(recovery) is None or recovery != command["event_id"]):
                    return refused("STALE_INVOCATION")
                previous = state["receipts"].get(command["event_id"])
                if previous is not None:
                    record = self.read_record(self.root / "events" / ("%06d.json" % previous["sequence"]))
                    original = record["envelope"]
                    domain.require(record["sequence"] == previous["sequence"]
                            and record["event_sha256"] == previous["event_sha256"]
                            and domain.digest(original) == previous["event_sha256"]
                            and original["id"] == command["event_id"], "original decision receipt differs")
                    event = original["event"]
                    if event["type"] != "decision":
                        return refused("REPLAY_CONFLICT")
                    row = state["requests"].get(event["request_id"])
                    domain.require(row is not None, "original decision request is unavailable")
                    # Guard the ORIGINAL target before comparing any changed
                    # incoming request/hash/reason or rebuilding an envelope.
                    self._authority.require_current(invocation, policy, state, row)
                    original_command = {"event_id": original["id"], **{
                        key: event[key] for key in ("request_id", "request_sha256", "decision", "reason")}}
                    if original_command != command:
                        return refused("REPLAY_CONFLICT")
                    answer = _decision_result(command, "recovered", receipt=previous)
                elif recovery is not None:
                    # The actual source-owned original-only mode never
                    # falls through to NEW, including a missing original.
                    return _decision_result(command, "unknown", "PUBLICATION_UNKNOWN")
                else:
                    row = state["requests"].get(command["request_id"])
                    if row is None:
                        return refused("UNKNOWN_REQUEST")
                    self._authority.require_current(invocation, policy, state, row)
                    if row["raw"]["sha256"] != command["request_sha256"]:
                        return refused("REQUEST_HASH_MISMATCH")
                    value = row["request"]
                    prior = [item for item in state["decisions"] if item["request_id"] == value["id"]]
                    if (value["authority"] != value["id"] or prior and not (
                            prior[-1]["decision"] == "approve" and command["decision"] == "deny")):
                        return refused("DECISION_CONFLICT")
                    at, cid = (self.clock() if self.clock else self.mailbox.timestamp()), invocation.actor_cid
                    actor = policy["actors"][cid]
                    if domain.active_seconds(state, cid, at) >= actor["cap_seconds"]:
                        return refused("CAP_REACHED")
                    if (command["decision"] == "approve"
                            and domain.parse_time(at) >= domain.parse_time(value["continuation"]["expires_at"])):
                        return refused("BOUNDED_AUTHORITY_EXPIRED")
                    domain.require(state["sequence"] < domain.MAX_EVENTS, "lifecycle event limit reached")
                    root = state["current"]["root"]
                    envelope = {"id": command["event_id"], "actor": cid, "generation": actor["generation"],
                                "custody": {"cid": root, "generation": policy["actors"][root]["generation"]},
                                "event": {"type": "decision", **{key: command[key] for key in (
                                    "request_id", "request_sha256", "decision", "reason")}}}
                    record = {"schema": domain.JOURNAL, "sequence": state["sequence"] + 1,
                              "previous": state["head"], "policy_sha256": domain.digest(policy), "at": at,
                              "envelope": envelope, "event_sha256": domain.digest(envelope)}
                    candidate, receipt = _advance(policy, state, record)
                    row = candidate["requests"][command["request_id"]]
                    self._authority.require_current(invocation, policy, candidate, row)
                    possible[0] = True  # Before the first possible publication.
                    self.publish_record(record)
                    state.clear()
                    state.update(candidate)
                    self._authority.require_current(invocation, policy, state, row)
                    answer = _decision_result(command, "recorded", receipt=receipt)
            # Publication, canonical unlock and this final original-budget
            # check are inside the same uncertainty handling scope.
            self._authority.require_current(invocation, policy, state, None)
        # The H guard exit is also complete before returning known data.
        return answer
