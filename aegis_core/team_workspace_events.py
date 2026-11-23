"""Workspace event validation and in-memory ledger transitions."""
from __future__ import annotations

from pathlib import Path
import re

from aegis_core.team_mailbox_primitives import (
    GIT_ID, MAX_RECORDS, MAX_WRITERS, SHA256, SLUG,
    bounded_tree, integer, matching, parse_time, strings, text,
)
from aegis_core.team_workspace_display import require, refusals

__all__ = [
    "EVENT_SCHEMA", "SUPERSEDE_EVENT_SCHEMA", "REPLAY_SCHEMAS", "MAX_HEAVY", "MAX_HEAVY_TESTS",
    "DEFAULT_HEAVY_TESTS", "MAX_PRIORITY", "KINDS", "INITIATIVE_STATES", "LIMIT_FIELDS",
    "record", "key", "rows", "require_ledger", "path", "fields", "absolute",
    "evidence_reference", "validate_initiative", "validate_lists", "require_unclaimed_lanes",
    "validate_envelope", "apply_event", "apply_init", "apply_set_limits", "apply_register", "apply_update",
    "apply_request", "apply_withdraw", "apply_grant", "apply_release", "apply_merge", "apply_clear",
]

EVENT_SCHEMA = "aegis.hierarchy-workspace-event/v1"
SUPERSEDE_EVENT_SCHEMA = "aegis.hierarchy-workspace-event/v2"
REPLAY_SCHEMAS = frozenset((EVENT_SCHEMA, SUPERSEDE_EVENT_SCHEMA))
MAX_HEAVY = 3
MAX_HEAVY_TESTS = 1
DEFAULT_HEAVY_TESTS = 1
MAX_PRIORITY = 1000
KINDS = ("writer", "heavy", "heavy-tests")
INITIATIVE_STATES = {"active", "paused", "done"}
_FIELD_LIMIT = MAX_RECORDS
# Report-only recovery is limited to queue events. Other kinds refuse a damaged time.
_QUEUE_TIME_KINDS = frozenset(("request", "grant", "release", "withdraw"))


def record(value):
    """Require a record before accessing any of its fields."""
    require(type(value) is dict)
    return value

def key(value):
    """Validate JSON-shaped dictionary identities without attempting hash()."""
    if type(value) is tuple:
        for item in value:
            key(item)
    else:
        require(type(value) in (str, int, float, bool, type(None)))
    return value

def rows(mapping):
    """Iterate validated rows without copying the ledger mapping."""
    for row in record(mapping).values():
        yield record(row)

def require_ledger(value):
    """Check the state and methods used by workspace transitions and views."""
    for name in ("initiatives", "requests", "granted_counts"):
        record(getattr(value, name, None))
    require(type(getattr(value, "seq", None)) is int and 0 <= value.seq)
    require(type(getattr(value, "open_holders", None)) is set)
    require(all(callable(getattr(value, name, None)) for name in ("initiative", "request", "held", "unresolved")))
    limits = getattr(value, "limits", None)
    require(limits is None or type(limits) is dict)
    for name in KINDS:
        require(isinstance(value.granted_counts.get(name), (int, float)))
        require(limits is None or isinstance(limits.get(name), (int, float)))

def _names(value):
    require(type(value) in (str, list, tuple, dict, set, frozenset) and len(value) <= _FIELD_LIMIT)
    require(all(type(name) is str for name in value))
    return set(value)

def path(value):
    """Validate an absolute path spelling without accessing the filesystem."""
    spelling = str(value) if isinstance(value, Path) else value
    require(type(spelling) is str and 0 < len(spelling) <= 32768 and "\x00" not in spelling, reason="unsafe_path")
    path = Path(spelling)
    require(path.is_absolute() and ".." not in path.parts and len(path.parts) <= 128, reason="unsafe_path")
    for part in path.parts[1:]:
        require(len(part) <= 255 and not any(0xD800 <= ord(c) <= 0xDFFF for c in part), reason="unsafe_path")
        require(len(part.encode("utf-8")) <= 255, reason="unsafe_path")
    return path

@refusals
def fields(value, required, optional=()):
    """Bound and validate the legacy fields without echoing unexpected keys."""
    bounded_tree(value)
    require(isinstance(value, dict))
    require(_names(required) <= value.keys())
    require(value.keys() <= _names(required) | _names(optional))

@refusals
def absolute(value, label):
    path(value)
    return value

@refusals
def evidence_reference(value):
    fields(value, {"path", "sha256"})
    matching(value["sha256"], SHA256, "evidence sha256")
    absolute(value["path"], "evidence path")

@refusals
def validate_initiative(data):
    fields(data, {"id", "project", "repository", "priority", "target_branch"},
           {"touched_paths", "blocked_by", "checkouts", "lanes", "mailbox_root", "delivery_dir", "source"})
    if "source" in data:
        text(data["source"], "source")
    matching(data["id"], SLUG, "initiative id")
    matching(data["project"], SLUG, "project")
    text(data["repository"], "repository", 256)
    integer(data["priority"], "priority", maximum=MAX_PRIORITY)
    text(data["target_branch"], "target_branch", 256)
    validate_lists(data)
    for name in ("mailbox_root", "delivery_dir"):
        if name in data:
            absolute(data[name], name)

@refusals
def validate_lists(data):
    record(data)
    if "touched_paths" in data:
        strings(data["touched_paths"], "touched paths")
    if "blocked_by" in data:
        strings(data["blocked_by"], "blocked_by")
    if "lanes" in data:
        strings(data["lanes"], "lanes")
    if "checkouts" in data:
        strings(data["checkouts"], "checkouts")
        for checkout in data["checkouts"]:
            absolute(checkout, "checkout")

@refusals
def apply_init(ledger, data, _event):
    require_ledger(ledger)
    require(ledger.seq == 0)
    fields(data, {"writer_limit", "heavy_limit"}, {"heavy_tests_limit"})
    integer(data["writer_limit"], "writer_limit", maximum=MAX_WRITERS)
    integer(data["heavy_limit"], "heavy_limit", maximum=MAX_HEAVY)
    heavy_tests = integer(data.get("heavy_tests_limit", DEFAULT_HEAVY_TESTS), "heavy_tests_limit", maximum=MAX_HEAVY_TESTS)
    require(ledger.limits is None)
    ledger.limits = {"writer": data["writer_limit"], "heavy": data["heavy_limit"], "heavy-tests": heavy_tests}

LIMIT_FIELDS = {"writer_limit": ("writer", MAX_WRITERS), "heavy_limit": ("heavy", MAX_HEAVY),
                "heavy_tests_limit": ("heavy-tests", MAX_HEAVY_TESTS)}

@refusals
def apply_set_limits(ledger, data, _event):
    """Apply reviewed limits without preempting work already granted."""
    require_ledger(ledger)
    fields(data, {"source"}, set(LIMIT_FIELDS))
    text(data["source"], "source")
    changes = sorted(data.keys() - {"source"})
    require(changes)
    for name in changes:
        kind, ceiling = LIMIT_FIELDS[name]
        integer(data[name], name, maximum=ceiling)
        held = ledger.granted_counts[kind]
        require(data[name] >= held)
    for name in changes:
        ledger.limits[LIMIT_FIELDS[name][0]] = data[name]

def _owned(value):
    """Copy nested containers so a retained row does not alias its caller."""
    kind = type(value)
    if kind is dict:
        return {key: _owned(item) for key, item in value.items()}
    if kind is list:
        return [_owned(item) for item in value]
    if kind is tuple:
        return tuple(_owned(item) for item in value)
    return value

@refusals
def require_unclaimed_lanes(ledger, repository, lanes, identifier):
    require_ledger(ledger)
    strings(lanes, "lanes")
    for other in rows(ledger.initiatives):
        strings(other["lanes"], "lanes")
        if other["id"] != identifier and other["repository"] == repository:
            taken = sorted(set(lanes) & set(other["lanes"]))
            require(not taken)

@refusals
def apply_register(ledger, data, event):
    require_ledger(ledger)
    record(event)
    bounded_tree(data)
    data = _owned(data)
    validate_initiative(data)
    require(data["id"] not in ledger.initiatives)
    require_unclaimed_lanes(ledger, data["repository"], data.get("lanes", []), data["id"])
    ledger.initiatives[data["id"]] = {
        "touched_paths": [], "blocked_by": [], "checkouts": [], "lanes": [], **data, "state": "active",
        "base_moved": None, "registered_at": event["at"]}

@refusals
def apply_update(ledger, data, _event):
    require_ledger(ledger)
    bounded_tree(data)
    data = _owned(data)
    fields(data, {"initiative", "source"}, {"priority", "state", "blocked_by", "touched_paths", "checkouts", "lanes"})
    initiative = ledger.initiative(data["initiative"])
    text(data["source"], "source")
    validate_lists(data)
    require_unclaimed_lanes(ledger, initiative["repository"], data.get("lanes", []), initiative["id"])
    if "priority" in data:
        integer(data["priority"], "priority", maximum=MAX_PRIORITY)
    if "state" in data:
        require(isinstance(data["state"], str) and data["state"] in INITIATIVE_STATES)
        if data["state"] == "done":
            require(not any(r["initiative"] == initiative["id"] and r["state"] in ("queued", "granted")
                            for r in rows(ledger.requests)))
    initiative.update({key: value for key, value in data.items() if key not in ("initiative", "source")})

@refusals
def apply_request(ledger, data, event):
    require_ledger(ledger)
    record(event)
    bounded_tree(data)
    data = _owned(data)
    fields(data, {"request_id", "initiative", "kind", "holder"}, {"reference", "supersedes"})
    initiative = ledger.initiative(data["initiative"])
    require(initiative["state"] == "active")
    require(isinstance(data["kind"], str) and data["kind"] in KINDS)
    text(data["holder"], "holder", 256)
    if "reference" in data:
        text(data["reference"], "reference")
    require(key(data["request_id"]) not in ledger.requests)
    previous = None
    if "supersedes" in data:
        identifier = text(data["supersedes"], "supersedes", 12)
        require(re.fullmatch(r"req-[0-9]{8}", identifier) is not None)
        require(event["schema"] == SUPERSEDE_EVENT_SCHEMA)
        require(identifier in ledger.requests)
        previous = ledger.requests[identifier]
        require(all(previous[key] == data[key] for key in ("initiative", "holder", "kind")))
        require(previous["state"] != "granted")
        require(previous["state"] == "queued")
    holder = (data["kind"], data["holder"])
    require(previous is not None or holder not in ledger.open_holders)
    replacement = {**data, "state": "queued", "seq": previous["seq"] if previous is not None else event["seq"],
                   "requested_at": event["at"], "reserved_repository": initiative["repository"],
                   "reserved_paths": _owned(initiative["touched_paths"])}
    if previous is not None:
        previous.update(state="withdrawn", closed_at=event["at"], superseded_by=data["request_id"])
    ledger.requests[data["request_id"]] = replacement
    ledger.open_holders.add(holder)

@refusals
def apply_withdraw(ledger, data, event):
    require_ledger(ledger)
    record(event)
    fields(data, {"request_id", "source"})
    text(data["source"], "source")
    request = ledger.request(data["request_id"])
    require(request["state"] == "queued")
    request.update(state="withdrawn", closed_at=event["at"])
    ledger.open_holders.remove((request["kind"], request["holder"]))

@refusals
def apply_grant(ledger, data, event):
    require_ledger(ledger)
    record(event)
    fields(data, {"request_id"})
    request = ledger.request(data["request_id"])
    require(request["state"] == "queued")
    require(ledger.granted_counts[request["kind"]] < ledger.limits[request["kind"]], reason="capacity_full")
    request.update(state="granted", granted_at=event["at"])
    ledger.granted_counts[request["kind"]] += 1

@refusals
def apply_release(ledger, data, event):
    require_ledger(ledger)
    record(event)
    bounded_tree(data)
    data = _owned(data)
    fields(data, {"request_id", "evidence"})
    evidence_reference(data["evidence"])
    request = ledger.request(data["request_id"])
    require(request["state"] == "granted")
    request.update(state="released", closed_at=event["at"], evidence=data["evidence"])
    ledger.open_holders.remove((request["kind"], request["holder"]))
    ledger.granted_counts[request["kind"]] -= 1

@refusals
def apply_merge(ledger, data, event):
    require_ledger(ledger)
    record(event)
    fields(data, {"repository", "branch", "commit", "source"}, {"initiative"})
    text(data["repository"], "repository", 256)
    text(data["branch"], "branch", 256)
    matching(data["commit"], GIT_ID, "commit")
    text(data["source"], "source")
    if "initiative" in data:
        ledger.initiative(data["initiative"])
    for initiative in rows(ledger.initiatives):
        if (initiative["repository"] == data["repository"] and initiative["target_branch"] == data["branch"]
                and initiative["state"] != "done" and initiative["id"] != data.get("initiative")):
            initiative["base_moved"] = {"commit": data["commit"], "at": event["at"], "source": data["source"]}

@refusals
def apply_clear(ledger, data, _event):
    require_ledger(ledger)
    fields(data, {"initiative", "base_commit", "evidence", "source"})
    text(data["source"], "source")
    evidence_reference(data["evidence"])
    initiative = ledger.initiative(data["initiative"])
    require(initiative["base_moved"] is not None)
    require(initiative["base_moved"]["commit"] == data["base_commit"])
    initiative["base_moved"] = None

@refusals
def validate_envelope(event, expected_seq, *, recover_queue_time, max_records=MAX_RECORDS):
    """Check schema, expected sequence and time before any transition.

    recover_queue_time is the report-reader policy: a damaged time on a queue
    event becomes None and the original mapping is left unchanged. Every other
    damaged time is a refusal. Callers pass the only sequence this event may carry
    and the record ceiling that sequence has to fit.
    """
    event = record(event)
    fields(event, {"schema", "seq", "at", "kind", "data"})
    require(key(event["schema"]) in REPLAY_SCHEMAS)
    require(type(expected_seq) is int and expected_seq >= 1)
    require(type(max_records) is int and max_records >= 1)
    require(expected_seq <= max_records, reason="too_large")
    require(type(event["seq"]) is int and event["seq"] == expected_seq)
    require(type(recover_queue_time) is bool)
    try:
        parse_time(event["at"])
    except ValueError:
        kind = event["kind"]
        if not (recover_queue_time and type(kind) is str and kind in _QUEUE_TIME_KINDS):
            raise
        event = {**event, "at": None}
    return event

@refusals
def apply_event(ledger, event, transitions):
    """Apply one event using the store's public transition dispatch table."""
    event = record(event)
    kind = key(event["kind"])
    transition = record(transitions).get(kind)
    require(callable(transition))
    require(kind == "init" or ledger.limits is not None)
    require(type(getattr(ledger, "seq", None)) is int)
    require(ledger.seq == 0 if kind == "init" else ledger.seq >= 1)
    data, seq = event["data"], event["seq"]
    transition(ledger, data, event)
    ledger.seq = seq
