"""Mailbox wire primitives and fixed, input-free refusal contracts.

Role tables and permissions are owner-injected policy; they confer no OS authority.
Records retain the legacy wire format. No tools imports or process execution.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType

from aegis_core.primitives import json_preflight, sanitize_display
from aegis_core.redaction import clip_rendered_text, guidance_value

__all__ = ["MailboxRefusal", "BusyError", "RoleTables", "MAX_BYTES", "MAX_RECORDS",
           "bounded_tree", "strict_json", "encoded", "digest", "parse_time", "safe_path",
           "fields", "text", "integer", "matching", "strings", "operation", "validation",
           "status_entries", "bounded_inbox", "message_types", "record_types",
           "reply_reference", "validate_job_receipt", "witness_record", "lock_path", "LockReleaseWarning",
           "OWNER_EVIDENCE_LOCK", "MAX_RELEASE_WARNINGS", "validate_warnings",
           "result_payload", "result_envelope", "checkpoint_payload", "binding_payload", "binding_record"]

MAX_BYTES = 262144
MAX_INBOX_RESPONSE_BYTES = 4194304
MAX_RECORDS = 10000
MAX_RELEASE_WARNINGS = 256
MAX_HISTORY_BYTES = 67108864
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 32768
MAX_JSON_ITEMS = 10000
# The owner's writer ceiling (owner-writers-5, requests/root-c6-owner-decisions-20261102.json). The
# workspace ledger imports it, so a manifest and the store it is built from cannot disagree.
MAX_WRITERS = 5
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_ID = re.compile(r"[0-9a-f]{40}")
MESSAGE_TYPES = {"info", "brief", "dispatch", "result", "review", "escalation", "ack", "job_request", "job_receipt"}
STAGES = {"received", "accepted", "completed"}
JOB_STATES = {"started", "unknown", "refused", "completed", "failed"}
# "unknown" stays open on purpose: an uncertain job keeps its reservation until terminal evidence exists.
TERMINAL_JOB_STATES = {"refused", "completed", "failed"}
MAX_JOB_EVIDENCE = 64
VERIFICATION = {"lease": "reference_only", "scan": "sender_claim", "hook": "sender_claim",
                "tests": "sender_claim", "human_approval": "not_established", "fitness_credit": 0}
DELIVERY_RECEIPT = "aegis.hierarchy-delivery-receipt/v1"
WAKE_STATES = {"started", "exited", "timed_out", "failed_to_start"}
MAX_DELIVERY_IDS = 100
MAX_STATUS_EVIDENCE_BYTES = 67108864
MAX_DIRTY_ENTRIES = 100000000
MAX_RECENT_ACKNOWLEDGMENTS = 20
OWNER_EVIDENCE_LOCK = "team-mailbox-evidence.lock"
DELIVERY_MEANING = ("read means the adapter returned the message to the connection configured for this binding; "
                    "it does not prove the session understood or acted on it. woken means a host process was started "
                    "for a turn; hosts offer no handshake, so it does not prove the turn ran.")



_NEXT = {
    "busy": "Wait for the current writer; inspect an abandoned lock before a bounded retry.",
    "unauthorized": "Use a caller role admitted for this operation.",
    "unsupported_platform": "Use a platform with descriptor-relative no-follow storage.",
    "unknown_host": "Select a host in the injected host table.",
    "host_unavailable": "Provide a qualified host observation port, then retry.",
    "delivery_context_required": "Configure the owner-selected delivery roots before writing evidence.",
    "too_large": "Reduce the input or reconcile retained history before retrying.",
    "unsafe_path": "Restore regular, singly linked records under the trusted root.",
    "missing": "Restore the required record from trusted evidence before retrying.",
    "exists": "Read the current history before retrying with a new identifier.",
    "closed": "Open a new mailbox context.",
    "invalid_record": "Reconcile the input and stored history against the mailbox schema.",
    "io": "Check storage availability and read current history before retrying.",
}


class MailboxRefusal(ValueError):
    """Operational refusal: code 1, fixed reason and a concrete next action."""
    def __init__(self, reason):
        self.reason = reason
        self.next_action = _NEXT[reason]
        self.code = 1
        self.status = "refused"
        super().__init__("mailbox refused: " + reason)

    def as_dict(self):
        return {"status": self.status, "reason": self.reason,
                "next_action": self.next_action, "code": self.code}


class BusyError(MailboxRefusal):
    """One lock-busy type, shared by every mailbox writer."""
    def __init__(self, path=None):
        super().__init__("busy")
        if path is not None:
            self.next_action = "Inspect the current writer or abandoned lock at " + lock_display(path) + "; retry only after release."


@dataclass(frozen=True)
class LockReleaseWarning:
    """A lock needs inspection; the operation reports its publication outcome."""
    path: Path

    def as_dict(self):
        shown = lock_display(self.path)
        return {"status": "warning", "reason": "lock_release", "code": 0, "lock_path": shown,
                "next_action": "Inspect the lock at " + shown + " before another write."}


def lock_display(path):
    path = safe_path(path)
    # Generated lock names are public identifiers, separate from the untrusted parent.
    structured = path.name in {".write.lock", OWNER_EVIDENCE_LOCK} or re.fullmatch(r"\.witness-[0-9a-f]{64}\.lock", path.name)
    limit = 1023 - len(path.name) if structured else 1024
    shown = guidance_value(str(path.parent if structured else path), limit=limit, canonicalize=sanitize_display)
    shown = clip_rendered_text(shown, limit=limit, canonicalize=sanitize_display)
    return shown.rstrip("/") + "/" + path.name if structured else shown


def lock_path(directory, destination=None, *, owner=False):
    directory = safe_path(directory)
    require(type(owner) is bool and (not owner or destination is None))
    name = OWNER_EVIDENCE_LOCK if owner else ".write.lock"
    if destination is not None:
        destination = safe_path(destination)
        require(directory in destination.parents, reason="unsafe_path")
        suffix = destination.relative_to(directory).as_posix().encode("utf-8")
        name = ".witness-" + hashlib.sha256(suffix).hexdigest() + ".lock"
    return safe_path(directory / name)


def require(condition, message="", *, reason="invalid_record"):
    # Legacy validation labels are deliberately never exposed as diagnostics.
    if not condition:
        raise MailboxRefusal(reason)


def fields(value, required, optional=()):
    require(type(value) is dict)
    require(set(required) <= value.keys())
    require(value.keys() <= set(required) | set(optional))


def text(value, label, limit=4096):
    require(type(value) is str and 0 < len(value) <= limit and "\x00" not in value)
    require(not any(0xD800 <= ord(char) <= 0xDFFF for char in value))
    return value


def validate_warnings(warnings, *, allow_none=True, limit=MAX_RELEASE_WARNINGS):
    """Bound diagnostic metadata before inspecting entries; it is never state."""
    require(type(allow_none) is bool and type(limit) is int and 0 <= limit <= MAX_RELEASE_WARNINGS)
    if warnings is None:
        require(allow_none)
        return
    require(type(warnings) is list)
    require(len(warnings) <= limit, reason="too_large")
    for warning in warnings:
        require(type(warning) is dict and len(warning) == 5)
        fields(warning, {"status", "reason", "code", "lock_path", "next_action"})
        require(type(warning["status"]) is str and warning["status"] == "warning")
        require(type(warning["reason"]) is str and warning["reason"] == "lock_release")
        require(type(warning["code"]) is int and warning["code"] == 0)
        text(warning["lock_path"], "warning lock", 1024)
        text(warning["next_action"], "warning action")


def result_payload(result):
    """Copy a public result without bounded, typed diagnostic metadata."""
    require(type(result) is dict)
    require(len(result) <= MAX_JSON_ITEMS, reason="too_large")
    if "warnings" in result:
        validate_warnings(result["warnings"], allow_none=False)
    return {key: value for key, value in result.items() if key != "warnings"}


def result_envelope(result):
    """Copy validated diagnostics for transport, where their bytes still count."""
    payload = result_payload(result)
    if "warnings" in result:
        payload["warnings"] = [dict(warning) for warning in result["warnings"]]
    return payload


def checkpoint_payload(checkpoint, *, preserve_warnings=False):
    """Only source slots carry API results; other checkpoint fields stay strict."""
    require(type(preserve_warnings) is bool)
    require(type(checkpoint) is dict)
    require(len(checkpoint) <= MAX_JSON_ITEMS, reason="too_large")
    result = dict(checkpoint)
    if "sources" in result:
        sources = result["sources"]
        require(type(sources) is list and len(sources) <= 256)
        normalize = result_envelope if preserve_warnings else result_payload
        result["sources"] = [normalize(source) for source in sources]
    return result


def binding_payload(binding, *, preserve_warnings=False):
    """Draft and binding inputs share checkpoint source-result positions."""
    require(type(preserve_warnings) is bool)
    result = result_envelope(binding) if preserve_warnings else result_payload(binding)
    if "ready" in result:
        require(type(result["ready"]) is bool)
    if result.get("checkpoint") is not None:
        result["checkpoint"] = checkpoint_payload(result["checkpoint"], preserve_warnings=preserve_warnings)
    return result


def binding_record(binding):
    """Validate result metadata separately from the stored binding's budget."""
    result = binding_payload(binding)
    result.pop("ready", None)
    return result


def safe_path(value):
    spelling = str(value) if isinstance(value, Path) else value
    require(type(spelling) is str and 0 < len(spelling) <= 32768, reason="unsafe_path")
    require("\x00" not in spelling and "\\" not in spelling, reason="unsafe_path")
    path = Path(spelling)
    require(path.is_absolute() and ".." not in path.parts and len(path.parts) <= 128,
            reason="unsafe_path")
    for part in path.parts[1:]:
        require(len(part) <= 255 and not any(0xD800 <= ord(c) <= 0xDFFF for c in part),
                reason="unsafe_path")
        require(len(part.encode("utf-8")) <= 255, reason="unsafe_path")
    return path


def bounded_tree(value, *, limit=MAX_BYTES, ascii_strings=False):
    """Budget JSON-shaped values before serialization; reject cycles and depth."""
    budget = [limit, 0]

    def visit(item, depth):
        require(depth <= MAX_JSON_DEPTH)
        budget[1] += 1
        require(budget[1] <= MAX_JSON_NODES, reason="too_large")
        if type(item) is str:
            require(len(item) <= budget[0], reason="too_large")
            for char in item:
                code = ord(char)
                require(not 0xD800 <= code <= 0xDFFF)
                if ascii_strings:
                    cost = (2 if char in ('"', "\\", "\b", "\f", "\n", "\r", "\t")
                            else 6 if code < 32 or 127 <= code <= 65535
                            else 12 if code > 65535 else 1)
                else:
                    cost = 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
                budget[0] -= cost
                require(budget[0] >= 0, reason="too_large")
            budget[0] -= 2
        elif type(item) in (dict, list, tuple):
            require(depth < MAX_JSON_DEPTH)
            require(len(item) <= MAX_JSON_ITEMS, reason="too_large")
            # Brackets/braces, commas, and object colons all count on the wire.
            budget[0] -= 2 + max(0, len(item) - 1) + (len(item) if type(item) is dict else 0)
            require(budget[0] >= 0, reason="too_large")
            for key in item:
                if type(item) is dict:
                    require(type(key) is str)
                    visit(key, depth + 1)
                    visit(item[key], depth + 1)
                else:
                    visit(key, depth + 1)
        elif item is None or type(item) in (bool, int, float):
            require(type(item) is not int or item.bit_length() <= 64)
            require(type(item) is not float or math.isfinite(item))
            # Scalars are bounded above before this small representation allocation.
            budget[0] -= len(repr(item))
        else:
            require(False)
        require(budget[0] >= 0, reason="too_large")

    visit(value, 0)


def strict_json(raw):
    require(type(raw) in (str, bytes))
    require(len(raw) <= MAX_BYTES, reason="too_large")
    try:
        checked = json_preflight(raw, max_bytes=MAX_BYTES, max_depth=MAX_JSON_DEPTH,
                                 max_nodes=MAX_JSON_NODES, max_items=MAX_JSON_ITEMS,
                                 max_string=MAX_BYTES, max_atom=64)
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result)
                result[key] = value
            return result
        def nonfinite(value):
            raise MailboxRefusal("invalid_record")
        result = json.loads(checked, object_pairs_hook=pairs, parse_constant=nonfinite)
        bounded_tree(result)
        return result
    except MailboxRefusal:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise MailboxRefusal("invalid_record") from None


def operation(write=False, *, evidence=False, authorization=None, envelope=False, input_record=None):
    """Normalize failures; authorize (position, keyword, member, action) before locking."""
    def decorate(function):
        @wraps(function)
        def call(self, *args, **kwargs):
            depth = getattr(self.calls, "depth", 0)
            observed = [] if not depth and envelope else None
            try:
                if write:
                    self.roles.authorize(self.caller_role, function.__name__)
                if authorization is not None:
                    position, keyword, member, action = authorization
                    value = args[position] if len(args) > position else kwargs.get(keyword)
                    requested = (type(value) is dict and member in value) if member is not None else value is not None
                    if requested:
                        self.roles.authorize(self.caller_role, action)
                if input_record is not None:
                    position, keyword, normalize = input_record
                    if len(args) > position:
                        args = (*args[:position], normalize(args[position]), *args[position + 1:])
                    else:
                        require(keyword in kwargs)
                        kwargs = {**kwargs, keyword: normalize(kwargs[keyword])}
                if write or evidence or input_record is not None:
                    for argument in (*args, *kwargs.values()):
                        if type(argument) in (dict, list, tuple):
                            bounded_tree(argument)
                kind = "evidence-destination" if evidence else "mailbox"
                with self.store._warning_listener(observed):
                    with self.store.creation(kind) if write or evidence else nullcontext():
                        with self.store.evidence_transaction() if write or evidence else nullcontext():
                            with self.store.lock(self.root) if write else nullcontext():
                                self.calls.depth = depth + 1
                                if not depth:
                                    self.calls.history_bytes = {}
                                    self.refresh()
                                result = function(self, *args, **kwargs)
                if not depth and envelope:
                    warnings = self.store.drain_warnings()
                    seen = {id(warning) for warning in warnings}
                    warnings.extend(warning for warning in observed if id(warning) not in seen)
                    if warnings:
                        result = {**result, "warnings": warnings}
                return result
            except MailboxRefusal:
                raise
            except OSError:
                raise MailboxRefusal("io") from None
            except (ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
                raise MailboxRefusal("invalid_record") from None
            finally:
                self.calls.depth = depth
        return call
    return decorate


def validation(function):
    """Fixed refusals for pure public record helpers as well as service methods."""
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except MailboxRefusal:
            raise
        except (ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
            raise MailboxRefusal("invalid_record") from None
    return call


def message_types(message):
    """Check types consumed by history queries; full wire schemas live in Mailbox."""
    require(type(message) is dict)
    for name in ("message_id", "from", "to", "type", "created_at", "acknowledgment", "in_reply_to"):
        if name in message:
            text(message[name], name, 256)
    if "readiness" in message:
        readiness = message["readiness"]
        require(type(readiness) is dict)
        for name in ("worktree", "branch", "lease_ref"):
            if name in readiness:
                text(readiness[name], name)
    if "receipt" in message:
        require(type(message["receipt"]) is dict)
        if "state" in message["receipt"]:
            text(message["receipt"]["state"], "job state", 128)
    return message


def record_types(records):
    """Bound a history mapping and check query field types before indexing/hashing."""
    require(type(records) is dict)
    require(len(records) <= MAX_RECORDS, reason="too_large")
    for identifier, record in records.items():
        text(identifier, "message id", 256)
        record = result_payload(record)
        require("message" in record)
        message_types(record["message"])


def reply_reference(message, records):
    """Check one reference in an already validated history, without scanning it."""
    require(type(message) is dict and type(records) is dict)
    identifier = text(message.get("in_reply_to"), "referenced message", 256)
    reference = records.get(identifier)
    reference = result_payload(reference)
    require(type(reference.get("message")) is dict)
    original = reference["message"]
    for left, right in (("from", "to"), ("to", "from")):
        text(message.get(left), "reply endpoint", 256)
        text(original.get(right), "original endpoint", 256)
        require(message[left] == original[right])
    return original


def integer(value, label, minimum=1, maximum=1000000):
    require(type(value) is int and minimum <= value <= maximum, "invalid " + label)
    return value


def matching(value, pattern, label):
    require(type(value) is str and len(value) <= 256 and pattern.fullmatch(value) is not None,
            "invalid " + label)
    return value


def strings(value, label, *, nonempty=False):
    require(isinstance(value, list) and len(value) <= 256 and (bool(value) or not nonempty), "invalid " + label)
    for item in value:
        text(item, label)


def parse_time(value):
    text(value, "UTC timestamp", 64)
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is not None,
            "invalid UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise MailboxRefusal("invalid_record") from None
    return parsed


def encoded(value):
    bounded_tree(value, ascii_strings=True)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


@validation
def status_entries(raw):
    """Count bounded porcelain -z entries without splitting the entire buffer."""
    require(type(raw) is bytes)
    require(len(raw) <= MAX_STATUS_EVIDENCE_BYTES, reason="too_large")
    count, index = 0, 0
    while index < len(raw):
        end = raw.find(b"\0", index)
        end = len(raw) if end < 0 else end
        if end > index:
            count += 1
            renamed = raw[index:index + 1] in (b"R", b"C") or raw[index + 1:index + 2] in (b"R", b"C")
            if renamed:
                extra = raw.find(b"\0", end + 1)
                end = len(raw) if extra < 0 else extra
        index = end + 1
    return count


@dataclass(frozen=True)
class RoleTables:
    """Injected immutable grammar, routes, independence and operation permissions."""
    writes: dict = field(default_factory=dict)
    endpoint_roles: tuple = ("front-door", "orchestrator", "root", "lane", "router", "decider")
    lane_kinds: tuple = ("implementer", "integrator", "reviewer")
    vertical_routes: tuple = (("front-door", "orchestrator"), ("orchestrator", "lane"),
        ("orchestrator", "root"), ("router", "root"), ("router", "orchestrator"),
        ("decider", "orchestrator"), ("decider", "root"))
    across_roles: tuple = ("front-door", "orchestrator", "lane")
    independent: frozenset = frozenset({"root", "reviewer", "decider"})

    def __post_init__(self):
        object.__setattr__(self, "writes", MappingProxyType(
            {role: frozenset(actions) for role, actions in self.writes.items()}))
        for name in ("endpoint_roles", "lane_kinds", "across_roles"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "vertical_routes", tuple(tuple(p) for p in self.vertical_routes))
        object.__setattr__(self, "independent", frozenset(self.independent))

    def authorize(self, caller_role, action):
        require(type(caller_role) is str and action in self.writes.get(caller_role, ()),
                reason="unauthorized")

    def endpoint_parts(self, endpoint):
        require(isinstance(endpoint, str), "invalid endpoint")
        require(len(endpoint) <= 256)
        parts = endpoint.split("/")
        require(len(parts) in (2, 3), "invalid endpoint")
        matching(parts[0], SLUG, "hierarchy")
        require(parts[0] not in {"across", "bindings"}, "reserved hierarchy name")
        require(parts[1] in self.endpoint_roles, "invalid endpoint role")
        require((parts[1] == "lane") == (len(parts) == 3), "invalid endpoint")
        if len(parts) == 3:
            matching(parts[2], SLUG, "lane id")
        return parts


    def validate_manifest(self, manifest):
        bounded_tree(manifest)
        fields(manifest, {"schema", "endpoints", "counterparts", "writer_limit"})
        require(manifest["schema"] == "aegis.hierarchy-pilot/v1", "unsupported manifest schema")
        integer(manifest["writer_limit"], "writer_limit", maximum=MAX_WRITERS)
        endpoints = manifest["endpoints"]
        require(isinstance(endpoints, dict) and 0 < len(endpoints) <= 256, "invalid endpoints")
        hierarchies = set()
        for endpoint, definition in endpoints.items():
            parts = self.endpoint_parts(endpoint)
            hierarchies.add(parts[0])
            if parts[1] == "lane":
                fields(definition, {"kind"})
                require(isinstance(definition["kind"], str) and definition["kind"] in self.lane_kinds, "invalid lane kind")
            else:
                fields(definition, set())
        for hierarchy in hierarchies:
            require(hierarchy + "/front-door" in endpoints and hierarchy + "/orchestrator" in endpoints,
                    "each hierarchy requires a front door and orchestrator")
        counterparts = manifest["counterparts"]
        require(isinstance(counterparts, list) and len(counterparts) <= 256, "invalid counterparts")
        paired = set()
        for pair in counterparts:
            require(isinstance(pair, list) and len(pair) == 2 and all(isinstance(p, str) and p in endpoints for p in pair),
                    "counterparts must name two endpoints")
            left, right = (self.endpoint_parts(p) for p in pair)
            require("root" not in (left[1], right[1]), "root endpoints cannot be counterparts")
            require(left[0] != right[0] and left[1] == right[1], "counterparts must have the same role across hierarchies")
            require(left[1] in self.across_roles, "only front doors, orchestrators and lanes can be counterparts")
            require(not any(p in paired for p in pair), "endpoint has more than one counterpart")
            paired.update(pair)
        return manifest




@validation
def bounded_inbox(result, render):
    """Page a fully validated count-limited inbox using its actual transport bytes.

    The caller has already checked history and expanded every requested brief in
    the count-limited selection. Byte paging must not hide any of those errors.
    Binding and checkpoint briefs are mandatory, including duplicate references.
    """
    result = result_envelope(result)
    require(callable(render))
    messages = result["messages"]
    require(type(messages) is list and len(messages) <= 100)
    messages = [result_envelope(record) for record in messages]
    result["messages"] = messages
    if result.get("binding") is not None:
        result["binding"] = binding_payload(result["binding"], preserve_warnings=True)
    integer(result["remaining"], "remaining messages", minimum=0, maximum=MAX_RECORDS)
    for record in messages:
        require(type(record) is dict and "message" in record)
        message_types(record["message"])
    total = len(messages) + result["remaining"]

    def page(count):
        remaining = total - count
        return {**result, "messages": messages[:count], "remaining": remaining,
                "next_after": messages[count - 1]["message"]["message_id"] if count and remaining else None}

    def fits(value):
        rendered = render(value)
        require(type(rendered) in (bytes, str))
        return len(rendered) <= MAX_INBOX_RESPONSE_BYTES

    selected = page(0)
    require(fits(selected),
            "inbox response metadata exceeds 4194304 bytes")
    for count in range(1, len(messages) + 1):
        candidate = page(count)
        if not fits(candidate):
            require(count > 1, "inbox first message cannot fit 4194304 byte response budget")
            # A complete validated message/path record adds more bytes in either
            # transport than any reduction of the bounded cursor/count fields.
            break
        selected = candidate
    return selected




@validation
def witness_record(result, worktree):
    """Validate an observation before admitting its evidence or checkpoint."""
    result = result_payload(result)
    bounded_tree(result)
    fields(result, {"worktree", "source_revision", "source_tree", "dirty_state_sha256", "dirty_entries"},
           {"dirty_evidence"})
    require(result["worktree"] == str(worktree))
    matching(result["source_revision"], GIT_ID, "source revision")
    matching(result["source_tree"], GIT_ID, "source tree")
    matching(result["dirty_state_sha256"], SHA256, "dirty digest")
    integer(result["dirty_entries"], "dirty entries", minimum=0, maximum=MAX_DIRTY_ENTRIES)
    if "dirty_evidence" in result:
        text(result["dirty_evidence"], "dirty evidence")
    return dict(result)


@validation
def validate_job_receipt(receipt):
    """Structure only. Evidence paths stay inert: nothing here reads them or trusts the claim."""
    fields(receipt, {"state"}, {"exit_code", "evidence", "reason"})
    state = receipt["state"]
    require(isinstance(state, str) and state in JOB_STATES, "invalid job state")
    exit_code = receipt.get("exit_code")
    if state == "completed":
        require(type(exit_code) is int and exit_code == 0, "completed job requires exit code 0")
    elif state == "failed":
        require(type(exit_code) is int and exit_code != 0, "failed job requires a nonzero exit code")
    else:
        require(exit_code is None or type(exit_code) is int, "invalid exit code")
    if state in {"completed", "failed"}:
        require(isinstance(receipt.get("evidence"), list) and bool(receipt["evidence"]),
                "job receipt requires evidence")
    if state in {"refused", "unknown"}:
        require(isinstance(receipt.get("reason"), str) and bool(receipt["reason"]), "job receipt requires a reason")
    if "reason" in receipt:
        text(receipt["reason"], "reason")
    evidence = receipt.get("evidence", [])
    require(isinstance(evidence, list) and len(evidence) <= MAX_JOB_EVIDENCE, "invalid evidence list")
    for item in evidence:
        fields(item, {"path", "sha256"})
        matching(item["sha256"], SHA256, "evidence sha256")
        path = safe_path(text(item["path"], "evidence path"))
        require(path.is_absolute() and ".." not in path.parts, "evidence path must be absolute")
