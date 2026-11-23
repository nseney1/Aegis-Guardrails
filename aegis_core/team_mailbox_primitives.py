"""Mailbox wire primitives and fixed, input-free refusal contracts.

Role tables and permissions are owner-injected policy; they confer no OS authority.
Records retain the legacy wire format. No tools imports or process execution.
Public mailbox boundaries render refusals from raw state and known advice families,
never from instance methods. Class-creation checks are defence in depth: mixins,
hooks skipping super(), __getattribute__ and metaclasses are outside those checks'
scope. Direct calls to a custom subclass's own as_dict outside these boundaries
are also outside this guarantee.
Generic base-class handlers may mask an __init__-bypassing subclass; masking
yields no unadvised output; honest construction fails loudly before any handler.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from types import MappingProxyType

from aegis_core.primitives import json_preflight, sanitize_display
from aegis_core.redaction import clip_rendered_text, guidance_value

__all__ = ["MailboxRefusal", "MailboxReasonError", "render_mailbox_refusal", "BusyError", "RoleTables", "MAX_BYTES", "MAX_RECORDS",
           "bounded_tree", "strict_json", "encoded", "digest", "parse_time", "safe_path",
           "fields", "text", "integer", "matching", "strings", "validation",
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
    "rate_limited": "Wait for the rate window to pass before retrying the post or disposition.",
    "scope": "choose a permitted route and message role for this endpoint",
    "binding": "refresh the connection from the current acknowledged endpoint binding",
    "reference": "Use a validated existing message or record reference.",
    "history": "ask the owner to resolve the mailbox history limit",
    "io": "Check storage availability and read current history before retrying.",
}


_MANIFEST_REPAIR_ACTIONS = {
    "manifest": "Restore a bounded manifest with schema, writer_limit, endpoints and counterparts before retrying.",
    "schema": "Repair the manifest schema field to use aegis.hierarchy-pilot/v1 before retrying.",
    "writer_limit": "Repair the manifest writer_limit field to use an integer within the owner writer ceiling before retrying.",
    "endpoints": "Repair the manifest endpoints field: check endpoint names, lane kinds and required hierarchy roles before retrying.",
    "counterparts": "Repair the manifest counterparts field: check endpoint pairs, cross-hierarchy roles and unique membership before retrying.",
}


@contextmanager
def _manifest_field(field):
    """Attach only source-selected advice; legacy labels may contain input values."""
    try:
        yield
    except MailboxRefusal as error:
        payload = render_mailbox_refusal(error)
        refusal = MailboxRefusal(payload["reason"])
        refusal.next_action = _MANIFEST_REPAIR_ACTIONS[field]
        render_mailbox_refusal(refusal, reraise=True)


class MailboxReasonError(Exception):
    """Programming error: a refusal reason has no fixed recovery advice."""


_RECORD_ADVICE = MappingProxyType({
    "E_FORMAT": "Supply a valid canonical record and matching retry arguments.",
    "E_HASH": "Restore the record bytes from trusted evidence.",
    "E_AUTH": "Use the current binding and granted record references.",
    "E_REF": "Use a validated existing message or record reference.",
    "E_SELECTOR": "Select fields present in the record schema.",
    "E_SPAN": "Select spans present in the validated record.",
    "E_LIMIT": "Reduce the record, selection or retained history.",
})


def _refusal_error(reason, *, consumption=False):
    shown = (guidance_value(reason, limit=160, canonicalize=sanitize_display)
             if type(reason) is str else "<non-string>")
    shown = clip_rendered_text(shown, limit=160, canonicalize=sanitize_display)
    message = ("mailbox refusal advice does not match reason: " if consumption
               else "mailbox refusal reason has no advice: ")
    raise MailboxReasonError(message + (shown or "<empty>")) from None


def _refusal_policy(cls):
    table = getattr(cls, "advice_table", None)
    if table is MailboxRefusal.advice_table:
        table = _NEXT
    contract = getattr(cls, "advice_contract", None)
    if (type(table) not in (dict, MappingProxyType) or not 0 < len(table) <= 128
            or type(contract) is not str or contract not in {"mailbox", "busy", "record_codec"}):
        raise MailboxReasonError("invalid mailbox refusal advice declaration") from None
    for key, value in table.items():
        if (type(key) is not str or not 0 < len(key) <= 160
                or type(value) is not str or not 0 < len(value) <= MAX_BYTES):
            raise MailboxReasonError("invalid mailbox refusal advice declaration") from None
    return table, contract


def _record_advice(state, reason, action, *, initializing=False):
    record = state.get("record_error")
    if type(record) is not dict or len(record) > 128:
        _refusal_error(reason, consumption=True)
    detail = record.get("error")
    if type(detail) is not dict or len(detail) > 128:
        _refusal_error(reason, consumption=True)
    if initializing:
        reason = detail.get("code")
    if (type(reason) is not str or reason not in _RECORD_ADVICE
            or type(detail.get("code")) is not str or detail["code"] != reason):
        _refusal_error(reason, consumption=True)
    selected = detail.get("next_action", _RECORD_ADVICE[reason])
    if initializing:
        action = selected
    if (type(selected) is not str or not 0 < len(selected) <= MAX_BYTES
            or action not in (selected, _RECORD_ADVICE[reason])):
        _refusal_error(reason, consumption=True)
    # Retain envelope bytes while making its advice fields an independent snapshot.
    return {**record, "error": dict(detail)}


def _refusal_state(error):
    state = object.__getattribute__(error, "__dict__")
    table, contract = _refusal_policy(type(error))
    return _refusal_values(state, table, contract)


def _refusal_values(state, table, contract):
    reason, action = state.get("reason"), state.get("next_action")
    code, status = state.get("code"), state.get("status")
    if (type(reason) is not str or type(action) is not str or not 0 < len(action) <= MAX_BYTES
            or type(code) is not int or code != 1 or type(status) is not str or status != "refused"):
        _refusal_error(reason, consumption=True)
    record = None
    if contract == "record_codec":
        record = _record_advice(state, reason, action)
    else:
        if reason not in table or contract == "busy" and reason != "busy":
            _refusal_error(reason, consumption=True)
        allowed = action == table[reason]
        if (not allowed and contract == "mailbox" and table is _NEXT
                and reason in {"invalid_record", "too_large"}):
            allowed = action in _MANIFEST_REPAIR_ACTIONS.values()
        if not allowed and contract == "busy":
            path = state.get("_busy_path")
            if type(path) is type(Path()):
                try:
                    expected = ("Inspect the current writer or abandoned lock at " + lock_display(path)
                                + "; retry only after release.")
                except MailboxRefusal:
                    _refusal_error(reason, consumption=True)
                allowed = action == expected
        if not allowed:
            _refusal_error(reason, consumption=True)
    return {"status": status, "reason": reason, "next_action": action, "code": code}, record, contract



def render_mailbox_refusal(error, *, record=False, reraise=False):
    """Render known-family state; optionally rethrow a safe family instance.

    Subclass metadata and instance methods supply no rendering authority.
    Rebuilding exceptions also prevents a later caller from invoking an
    overridden serializer after the boundary has validated their raw state.
    """
    module = sys.modules.get("aegis_core.team_mailbox_records")
    record_family = vars(module).get("RecordRefusal") if module is not None else None
    family = None
    for base in type.__getattribute__(type(error), "__mro__"):
        if base is BusyError or base is MailboxRefusal or base is record_family:
            family = base
            break
    if family is None:
        _refusal_error(None, consumption=True)
    contract = ("busy" if family is BusyError else
                "record_codec" if family is record_family else "mailbox")
    state = object.__getattribute__(error, "__dict__")
    payload, envelope, _contract = _refusal_values(state, _NEXT, contract)
    if reraise:
        refusal = ValueError.__new__(family)
        refusal.reason, refusal.next_action = payload["reason"], payload["next_action"]
        refusal.code, refusal.status = payload["code"], payload["status"]
        if contract == "record_codec":
            refusal.record_error = envelope
        if contract == "busy":
            refusal._busy_path = state.get("_busy_path")
        ValueError.__init__(refusal, _refusal_message(payload, contract))
        raise refusal from None
    return envelope if record and contract == "record_codec" else payload


def _refusal_message(payload, contract):
    prefix = "record refused: " if contract == "record_codec" else "mailbox refused: "
    return prefix + payload["reason"]


class MailboxRefusal(ValueError):
    """Operational refusal: code 1, fixed reason and a concrete next action.

    Advice is checked before construction and again at consumption. Subclasses
    overriding initialization must declare their own table or advice contract.
    The dictionary, text and public payload fields share one validation boundary.
    """
    advice_table = _NEXT
    advice_contract = "mailbox"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if any(name in cls.__dict__ for name in ("as_dict", "__str__", "__repr__", "__getattribute__")):
            raise MailboxReasonError("mailbox refusal consumption methods cannot be overridden") from None
        if "__init__" in cls.__dict__ and not any(
                name in cls.__dict__ for name in ("advice_table", "advice_contract")):
            raise MailboxReasonError("mailbox refusal initializer must declare advice") from None
        _refusal_policy(cls)
        if "__init__" in cls.__dict__:
            initializer = cls.__dict__["__init__"]
            if not callable(initializer):
                raise MailboxReasonError("invalid mailbox refusal advice declaration") from None

            @wraps(initializer)
            def initialize(self, *args, **kwargs):
                state = object.__getattribute__(self, "__dict__")
                depth = state.get("_refusal_initializing", 0)
                if type(depth) is not int or not 0 <= depth < 32:
                    _refusal_error(state.get("reason"), consumption=True)
                state["_refusal_initializing"] = depth + 1
                try:
                    result = initializer(self, *args, **kwargs)
                    if result is not None:
                        raise MailboxReasonError("mailbox refusal initializer must return None") from None
                finally:
                    state["_refusal_initializing"] = depth
                if depth == 0:
                    _refusal_state(self)
            cls.__init__ = initialize

    def __init__(self, reason):
        table, contract = _refusal_policy(type(self))
        table = _RECORD_ADVICE if contract == "record_codec" else table
        if type(reason) is not str or reason not in table:
            _refusal_error(reason)
        self.reason = reason
        self.next_action = table[reason]
        self.code = 1
        self.status = "refused"
        super().__init__("mailbox refused: " + reason)

    def as_dict(self):
        return _refusal_state(self)[0]

    def __getattribute__(self, name):
        if name in {"reason", "next_action", "code", "status", "record_error", "args"}:
            state = object.__getattribute__(self, "__dict__")
            if (name == "record_error" and state.get("_refusal_initializing", 0)
                    and _refusal_policy(type(self))[1] == "record_codec"):
                return _record_advice(state, None, None, initializing=True)
            payload, record, contract = _refusal_state(self)
            if name in payload:
                return payload[name]
            if name == "record_error" and contract == "record_codec":
                return record
            if name == "args":
                return (_refusal_message(payload, contract),)
        return object.__getattribute__(self, name)

    def __str__(self):
        payload, _record, contract = _refusal_state(self)
        return _refusal_message(payload, contract)

    def __repr__(self):
        return type(self).__name__ + "(" + repr(MailboxRefusal.__str__(self)) + ")"


class BusyError(MailboxRefusal):
    """One lock-busy type, shared by every mailbox writer."""
    advice_table = _NEXT
    advice_contract = "busy"

    def __init__(self, path=None):
        super().__init__("busy")
        self._busy_path = safe_path(path) if path is not None else None
        if path is not None:
            self.next_action = "Inspect the current writer or abandoned lock at " + lock_display(self._busy_path) + "; retry only after release."


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


def bounded_tree(value, *, limit=MAX_BYTES, ascii_strings=False, source_bytes=False):
    """Budget JSON-shaped values before serialization; reject cycles and depth."""
    require(type(source_bytes) is bool)
    budget = [limit, 0]

    def visit(item, depth):
        require(depth <= MAX_JSON_DEPTH)
        budget[1] += 1
        require(budget[1] <= MAX_JSON_NODES, reason="too_large")
        if type(item) is str:
            require(len(item) <= budget[0], reason="too_large")
            if item.isascii():
                budget[0] -= len(item)
                if ascii_strings:
                    budget[0] -= item.count('"') + item.count("\\")
                    if not item.isprintable():
                        budget[0] -= 5 * item.count("\x7f")
                        budget[0] -= sum(item.count(chr(code)) * (1 if code in (8, 9, 10, 12, 13) else 5)
                                         for code in range(32))
            else:
                for char in item:
                    code = ord(char)
                    require(source_bytes or not 0xD800 <= code <= 0xDFFF)
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
            require(source_bytes or type(item) is not float or math.isfinite(item))
            # Scalars are bounded above before this small representation allocation.
            if not source_bytes or type(item) not in (int, float):
                budget[0] -= len(repr(item))
        else:
            require(False)
        require(budget[0] >= 0, reason="too_large")

    visit(value, 0)


def strict_json(raw, *, limit=MAX_BYTES, max_atom=64, source_bytes=False):
    require(type(raw) in (str, bytes))
    require(type(limit) is int and limit >= 0)
    require(type(max_atom) is int and max_atom > 0 and type(source_bytes) is bool)
    require(len(raw) <= limit, reason="too_large")
    try:
        preflight = raw
        if source_bytes and type(raw) is str:
            # Count original UTF-8/surrogatepass width before allocating a copy.
            # The two extra bytes are bounded_tree's surrounding string quotes.
            bounded_tree(raw, limit=limit + 2, source_bytes=True)
            # U+FFFD has the same width and JSON lexical role as a surrogate.
            # Only preflight sees it; parsing retains the original legacy text.
            preflight = re.sub("[\ud800-\udfff]", "\ufffd", raw)
        checked = json_preflight(preflight, max_bytes=limit, max_depth=MAX_JSON_DEPTH,
                                 max_nodes=MAX_JSON_NODES, max_items=MAX_JSON_ITEMS,
                                 max_string=limit, max_atom=max_atom)
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result)
                result[key] = value
            return result
        def nonfinite(value):
            raise MailboxRefusal("invalid_record")
        def bounded_integer(value):
            # A raw-byte policy may admit long float atoms, never giant ints.
            require(len(value) <= 21)
            digits = value.lstrip("-")
            require(len(digits) < 20 or len(digits) == 20 and digits <= "18446744073709551615")
            return int(value)
        if not source_bytes:
            result = json.loads(checked, object_pairs_hook=pairs, parse_constant=nonfinite)
        else:
            source = raw if type(raw) is str else checked
            result = json.loads(source, object_pairs_hook=pairs, parse_constant=nonfinite,
                                parse_int=bounded_integer)
        bounded_tree(result, limit=limit, source_bytes=source_bytes)
        return result
    except MailboxRefusal as error:
        render_mailbox_refusal(error, reraise=True)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise MailboxRefusal("invalid_record") from None


def validation(function):
    """Fixed refusals for pure public record helpers as well as service methods."""
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except MailboxRefusal as error:
            render_mailbox_refusal(error, reraise=True)
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
    require(reference is not None, reason="reference")
    reference = result_payload(reference)
    require(type(reference.get("message")) is dict)
    original = reference["message"]
    for left, right in (("from", "to"), ("to", "from")):
        text(message.get(left), "reply endpoint", 256)
        text(original.get(right), "original endpoint", 256)
        require(message[left] == original[right], reason="scope")
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
        with _manifest_field("manifest"):
            bounded_tree(manifest)
            fields(manifest, {"schema", "endpoints", "counterparts", "writer_limit"})
        with _manifest_field("schema"):
            require(manifest["schema"] == "aegis.hierarchy-pilot/v1", "unsupported manifest schema")
        with _manifest_field("writer_limit"):
            integer(manifest["writer_limit"], "writer_limit", maximum=MAX_WRITERS)
        with _manifest_field("endpoints"):
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
        with _manifest_field("counterparts"):
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
