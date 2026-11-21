"""Bounded work queue; cooperative team labels, CAS revisions and expiring claims.

Model inputs and editable files are hostile. Owner-UID rewriting of owner state
is outside the v5.0 threat model. Claims convey scheduling, never OS authority.
Untrusted item paths are globs, never files to open. Reads use confined storage;
fixed owner-managed state uses the reviewed workspace lock and atomic publisher.
Reads neither create directories nor acquire a creating lock.
"""
from __future__ import annotations

from builtins import list as array
from contextlib import ExitStack, nullcontext
import json
from pathlib import Path
import re
import secrets
import time

from aegis_core import events, gitsafe, primitives, storage, team, team_claims, team_paths, team_profile, team_writer_binding
from aegis_core.atomicio import atomic_write_bytes
from aegis_core.redaction import redact_command_secrets
from aegis_core.storage import locked
from aegis_core.workspace.layout import AEGIS_DIRNAME

__all__ = [
    "MAX_BYTES", "MAX_ITEMS", "MAX_FIELDS", "MAX_TEXT", "MAX_COMPLETED", "QueueRefusal",
    "descriptor_supported", "valid_workspace_spelling", "valid_key", "valid_lane", "valid_revision",
    "check_capabilities", "normalize_branch", "parse_item", "list_argument_refusal", "refusal", "add", "list", "claim",
    "release", "unclaim", "done", "audit", "compact",
]

MAX_BYTES = 1048576
MAX_ITEMS = 256
MAX_FIELDS = 128
MAX_TEXT = team_claims.RECOVERY_TEXT_LIMIT
MAX_COMPLETED = 8192
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 65536
MAX_JSON_ITEMS = 65536
# An astral codepoint is two six-byte escapes; the closing quote also counts.
MAX_JSON_STRING = 12 * MAX_TEXT + 1
MAX_JSON_ATOM = 64
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
_REVISION = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_NEXT = {
    "invalid_item": "Supply a bounded queue item with the documented fields and single-line values.",
    "credential_like_text": "Rephrase the field without credential-assignment syntax (for example, use 'Update login flow'); never include credentials.",
    "invalid_arguments": "Use the documented queue arguments and the revision returned by list.",
    "invalid_queue_state": "Ask the coordinator to repair the queue state from trusted evidence.",
    "unsupported_platform": "Use a platform supporting descriptor-relative no-follow file operations.",
    "queue_size_limit": "Run aegis team queue compact to reduce readable retained state; if the queue already exceeds the 1 MiB file or reader limits, ask the coordinator to repair it from trusted evidence.",
    "queue_history_limit": "Ask the coordinator to archive and reconcile completed-ID history before further compaction; completed IDs must remain reserved.",
    "brief_outside_scope": "Correct brief_paths to name only files admitted by the item's paths, then add the item again.",
    "queue_live_limit": "Complete unfinished work before adding more than 256 unfinished items.",
    "queue_lock_timeout": "Wait for the workspace writer to finish, then list and retry with its current revision.",
    "queue_io_unavailable": "Check the trusted workspace and queue paths, then list before retrying a mutation.",
    "profile_unavailable": "Correct the layered team profile before claiming work.",
    "item_exists": "Run aegis team queue list --include-done to inspect existing items and completed_ids; use a new stable id for different work.",
    "item_missing": "List the queue and select an existing item id.",
    "stale_revision": "List the item again and decide whether to retry with its current revision.",
    "already_claimed": "Wait for release or lease expiry; then list and claim the current revision.",
    "lane_busy": "Release or complete the lane's current queue claim before claiming another item.",
    "lane_required": "Pass --lane with the current claim's lane from list before releasing or completing live work.",
    "lane_mismatch": "Use the current claim's lane from list, or ask its holder to release the work.",
    "not_claimed": "Claim the queued item before releasing or completing it.",
    "lease_expired": "List and claim the item again before completing it.",
    "item_done": "Select unfinished work; completed IDs remain reserved, including compacted history.",
    "capability_mismatch": "Select an item matching the team's declared capability labels.",
    "capacity_full": "Release or complete live work before claiming another writer slot.",
    "blocked": "Resolve the listed blockers, then list and retry the current revision.",
    "unclaim_lease_refused": "Inspect the named lease and its release command; reconcile ownership, then retry unclaim with the unchanged queue revision.",
    "writer_not_stopped": "Stop the lane's writer and queued jobs, verify their liveness in the host layer, then explicitly acknowledge this with --writer-stopped.",
    "writer_live": "Stop the bound writer, then retry unclaim; --writer-stopped cannot override a verified live writer.",
    "identity_unavailable": "Verify the bound writer has stopped, then retry unclaim with --writer-stopped; process identity could not be verified.",
    "binding_scope_mismatch": "Reconcile the writer binding's boot and PID namespace, verify the writer has stopped, then retry unclaim with --writer-stopped.",
    "bindings_unavailable": "Repair the owner-managed writer binding or verify the writer has stopped, then retry unclaim with --writer-stopped.",
    "writer_absent": "Verify the writer and queued jobs have stopped, then explicitly acknowledge this with --writer-stopped.",
    "writer_replaced": "Verify the original writer and queued jobs have stopped, then explicitly acknowledge this with --writer-stopped.",
    "unclaim_event_unavailable": "Ask the coordinator to reconcile unreadable or inconsistent private unclaim receipts in .aegis/state/unclaim-receipts from trusted evidence, then retry the queue operation.",
    "unclaim_recovery_required": "Use the concrete unclaim retry command and recorded caller in blockers after reconciling changed leases or private receipts in .aegis/state/unclaim-receipts; any pending intent remains reserved.",
}


class QueueRefusal(ValueError):
    """Fixed reason only; no input or OS diagnostic crosses the service boundary."""

    def __init__(self, reason, *, blockers=None):
        super().__init__(reason)
        self.reason, self.blockers = reason, blockers


class _QueueLabel:
    """Keep display markup separate from its independently untrusted fields."""

    def __init__(self, identifier, title, lane):
        self.identifier, self.title, self.lane = identifier, title, lane


def descriptor_supported():
    return storage.confined_descriptor_supported()


def _shown(value):
    if type(value) is _QueueLabel:
        # Redact each source field before adding the label's punctuation. The
        # generated colon must not turn an ordinary id such as BL-AUTH into a
        # credential assignment and redact its separately validated title.
        label = _shown(value.identifier) + ": " + _shown(value.title)
        lane = _shown(value.lane)
        if lane is not None:
            label = lane + " [" + label + "]"
        return primitives.sanitize_display(label, max_len=MAX_TEXT)
    if type(value) is str:
        clean = primitives.sanitize_display(value, max_len=None)
        return primitives.sanitize_display(redact_command_secrets(clean), max_len=MAX_TEXT)
    if type(value) is dict:
        return {_shown(key): _shown(item) for key, item in value.items()}
    if type(value) in (array, tuple):
        return [_shown(item) for item in value]
    return value


def _require(condition, reason="invalid_item"):
    if not condition:
        raise QueueRefusal(reason)


def valid_key(value):
    """Whether value is one bounded single-line queue identifier. Performs no I/O."""
    return (type(value) is str and len(value) <= 64 and _KEY.fullmatch(value) is not None
            and primitives.sanitize_display(value, max_len=None) == value
            and redact_command_secrets(value) == value)


def valid_lane(value):
    """Whether value is a queue lane the team grammar also accepts. Performs no I/O."""
    return valid_key(value) and team.valid_lane(value)


def valid_revision(value):
    """Whether value is 64 lowercase hex characters. Performs no I/O."""
    return type(value) is str and len(value) == 64 and _REVISION.fullmatch(value) is not None


_key = valid_key
_lane = valid_lane


def _text(value, limit=MAX_TEXT, empty=False):
    _require(type(value) is str and (empty or bool(value)) and len(value) <= limit)
    _require(not any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in "\u2028\u2029" for char in value))
    _require(primitives.sanitize_display(value, max_len=None) == value)
    _require(redact_command_secrets(value) == value, "credential_like_text")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise QueueRefusal("invalid_item") from None
    return value


def _strings(value, *, paths=False):
    _require(type(value) is array and len(value) <= MAX_FIELDS)
    for entry in value:
        if not paths:
            _require(_key(entry))
        _text(entry, 256)
        if paths:
            _require("\\" not in entry and ":" not in entry)
    _require(len(set(value)) == len(value))
    if paths and value:
        try:
            team_paths.claim_paths(value)
        except team_paths.LeasePathError:
            raise QueueRefusal("invalid_item") from None
    return value


def check_capabilities(value):
    """Validate one capability list. QueueRefusal carries a fixed code and performs no I/O."""
    return _strings(value)


def _item(value):
    _require(type(value) is dict and len(value) <= 10)
    required = {"id", "title", "paths", "capabilities"}
    allowed = required | {"after", "hold", "hold_until", "scope_rulings", "invariants", "brief_paths"}
    _require(required <= value.keys() and value.keys() <= allowed)
    _require(valid_key(value["id"]))
    _text(value["title"], 256)
    _strings(value["paths"], paths=True)
    _require(bool(value["paths"]))
    _strings(value.get("brief_paths", []), paths=True)
    scope = team_paths.claim_paths(value["paths"])
    for path in value.get("brief_paths", []):
        _require(not path.startswith("/") and not any(char in path for char in "*?[]"))
        _require(team_paths.first_match(scope, path) is not None, "brief_outside_scope")
    check_capabilities(value["capabilities"])
    _strings(value.get("after", []))
    _require(value["id"] not in value.get("after", []))
    _text(value.get("hold", ""), empty=True)
    conditions = value.get("hold_until", [])
    _require(type(conditions) is array and len(conditions) <= MAX_FIELDS)
    for condition in conditions:
        _require(type(condition) is dict and 1 <= len(condition) <= 2)
        kind = condition.get("kind")
        _require(type(kind) is str and kind in ("lease_free", "milestone", "owner", "coordinator"))
        expected = {"kind", "paths"} if kind == "lease_free" else {"kind", "name"} if kind == "milestone" else {"kind"}
        _require(condition.keys() == expected)
        if kind == "lease_free":
            _strings(condition["paths"], paths=True)
            _require(bool(condition["paths"]))
        elif kind == "milestone":
            _require(_key(condition["name"]))
    for name in ("scope_rulings", "invariants"):
        values = value.get(name, [])
        _require(type(values) is array and len(values) <= MAX_FIELDS)
        for text in values:
            _text(text)
    return value


def _json(raw, reason):
    """Preflight byte, nesting, node, string and container limits before parsing."""
    try:
        text = primitives.json_preflight(
            raw, max_bytes=MAX_BYTES, max_depth=MAX_JSON_DEPTH, max_nodes=MAX_JSON_NODES,
            max_items=MAX_JSON_ITEMS, max_string=MAX_JSON_STRING,
            string_units="source", max_atom=MAX_JSON_ATOM)
        return primitives.strict_loads(text)
    except (UnicodeError, ValueError, RecursionError):
        raise QueueRefusal(reason) from None


def parse_item(text):
    """Bound and validate the CLI's inline JSON; no attacker-selected file is opened."""
    try:
        return {"refused": False, "item": _item(_json(text, "invalid_item"))}
    except QueueRefusal as error:
        return {"refused": True, "reason": error.reason, "next_action": _NEXT[error.reason]}


def refusal(reason, *, verb="usage"):
    """Fixed, non-echoing envelope for failures before a service operation runs."""
    if type(reason) is not str or reason not in _NEXT:
        reason = "invalid_arguments"
    if type(verb) is not str or verb not in ("add", "list", "claim", "release", "unclaim", "done", "audit", "compact", "usage"):
        verb = "usage"
    payload = primitives.envelope("aegis team queue " + verb, {}, schema="aegis.team.queue." + verb + "/v1")
    payload.update(refused=True, status="refused", reason=reason, next_action=_NEXT[reason],
                   exit_code=2 if reason in ("invalid_arguments", "invalid_item", "credential_like_text", "brief_outside_scope") else 1)
    return _shown(payload)


def list_argument_refusal(arguments):
    """Validate the closed public list input before any workspace binding or IO."""
    try:
        _require(type(arguments) is dict and len(arguments) <= 2)
        _require(arguments.keys() <= {"capabilities", "include_done"})
        _require(type(arguments.get("include_done", False)) is bool)
        if "capabilities" in arguments:
            check_capabilities(arguments["capabilities"])
    except QueueRefusal:
        return refusal("invalid_arguments", verb="list")
    return None


def valid_workspace_spelling(raw):
    """Check both path flavours without filesystem access or normalization."""
    if (type(raw) is not str or not raw or len(raw) > 32768 or
            raw.count("/") + raw.count("\\") > 256 or "\x00" in raw):
        return False
    return ".." not in re.split(r"[\\/:]", raw)


def _root(root):
    """Bound the owner-selected workspace before constructing its path."""
    spelling = str(root) if isinstance(root, Path) else root
    _require(valid_workspace_spelling(spelling), "invalid_arguments")
    path = Path(spelling)
    _require(path.is_absolute(), "invalid_arguments")
    _require(descriptor_supported(), "unsupported_platform")
    try:
        # Entering the confined context checks the workspace's Aegis directory
        # without requiring a lane configuration or creating any state.
        with storage.confined_file(path, (AEGIS_DIRNAME, "team.json")) as handle:
            handle.parent_stat()
    except storage.ConfinedFileError:
        raise QueueRefusal("queue_io_unavailable") from None
    return path


def _read(root, parts, limit=MAX_BYTES):
    try:
        with storage.confined_file(root, parts) as handle:
            return handle.read_bytes(limit)
    except storage.ConfinedFileError as error:
        if error.reason == "missing":
            return None
        raise QueueRefusal("queue_size_limit" if error.reason == "too_large" else "queue_io_unavailable") from None


def _state(root):
    raw = _read(root, (AEGIS_DIRNAME, "state", "team-queue.json"))
    if raw is None:
        return {"version": 1, "items": {}, "milestones": [], "completed": {}}
    return _decode_state(raw)


def _decode_state(raw):
    try:
        value = _json(raw, "invalid_queue_state")
        required = {"version", "items", "milestones"}
        _require(type(value) is dict and required <= value.keys() <= required | {"completed", "unclaim"})
        _require(type(value["version"]) is int and value["version"] == 1)
        _strings(value["milestones"])
        _require(type(value["items"]) is dict)
        completed = value.setdefault("completed", {})
        _require(type(completed) is dict and len(completed) <= MAX_COMPLETED)
        for key, marker in completed.items():
            _require(_key(key) and marker is True and key not in value["items"])
        unfinished = 0
        for key, row in value["items"].items():
            required = {"item", "state", "revision", "lane", "expires_at"}
            _require(type(row) is dict and required <= row.keys() <= required | {"branch"})
            _item(row["item"])
            _require(key == row["item"]["id"])
            _require(valid_revision(row["revision"]))
            _require(type(row["state"]) is str and row["state"] in ("queued", "claimed", "done"))
            _require(row["lane"] is None or valid_lane(row["lane"]))
            # _json already bounds stored metadata. Preserve branch evidence
            # under older claim rules; an unsupported value is an item finding,
            # never a reason to disable the queue or its recovery commands.
            _require(row["expires_at"] is None or (type(row["expires_at"]) is int and 0 <= row["expires_at"] <= 4102531200))
            unfinished += row["state"] != "done"
            _require(unfinished <= MAX_ITEMS)
            if row["state"] == "claimed":
                _require(row["lane"] is not None and row["expires_at"] is not None)
            elif row["state"] == "queued":
                _require(row["lane"] is None and row["expires_at"] is None)
        _require(team_claims.validate_pending(value, _key, _text))
        return value
    except QueueRefusal:
        raise QueueRefusal("invalid_queue_state") from None


def _serialized_size(value, remaining):
    """Count ensure_ascii compact JSON bytes before allocating serialized output."""
    if type(value) is str:
        size = 2
        for char in value:
            code = ord(char)
            size += (2 if char in '\\"\b\f\n\r\t' else 6 if code < 32 or 127 <= code <= 65535
                     else 12 if code > 65535 else 1)
            _require(size <= remaining, "queue_size_limit")
    elif type(value) is dict:
        size = 2 + max(0, len(value) - 1)
        for key, entry in value.items():
            size += _serialized_size(key, remaining - size) + 1
            size += _serialized_size(entry, remaining - size)
    elif type(value) is array:
        size = 2 + max(0, len(value) - 1)
        for entry in value:
            size += _serialized_size(entry, remaining - size)
    else:
        size = len(str(value)) if type(value) is int else 4 if value is None or value is True else 5
    _require(size <= remaining, "queue_size_limit")
    return size


def _publish(root, state, *, raw=None, before_publish=None):
    if raw is None:
        _serialized_size(state, MAX_BYTES)
        raw = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    _require(len(raw) <= MAX_BYTES, "queue_size_limit")
    try:
        _decode_state(raw)
    except QueueRefusal:
        raise QueueRefusal("queue_size_limit") from None
    # Only this fixed owner-managed record is published. No item field supplies
    # a pathname. Concurrent owner-UID rewriting of run controls is out of scope.
    if before_publish is not None:
        before_publish()
    atomic_write_bytes(storage.state_dir(root) / "team-queue.json", raw, mode=0o600, follow_links=False)


def _live(row, now):
    return row["state"] == "claimed" and row["expires_at"] > now


def _block(reason, action, **fields):
    return {"refused": True, "reason": reason, "next_action": action, **fields}


def _blockers(item, state, lanes, found, now, queue_paths, *, config_checked=True, leases_checked=True):
    blockers = []
    current = state["items"].get(item["id"])
    holder = current["lane"] if current is not None and _live(current, now) else None
    if config_checked and not lanes:
        blockers.append(_block("coordinator", "Ask the coordinator to repair or configure valid lanes in .aegis/team.json."))
    if item.get("hold"):
        blockers.append(_block("judgment_hold", "Ask the holding actor to resolve the judgment hold."))
    for dependency in item.get("after", []):
        if dependency not in state["completed"] and state["items"].get(dependency, {}).get("state") != "done":
            blockers.append(_block("after", "Complete the prerequisite item before retrying.", item_id=dependency))
    for condition in item.get("hold_until", []):
        kind = condition["kind"]
        if kind in ("owner", "coordinator"):
            blockers.append(_block(kind, "Wait for the named actor to record a decision; this condition never self-clears."))
        elif kind == "milestone" and condition["name"] not in state["milestones"]:
            blockers.append(_block(kind, "Wait for the coordinator to record the milestone.", milestone=condition["name"]))
        elif kind == "lease_free":
            if not leases_checked:
                blockers.append(_block(kind, "Run aegis team queue list --json to evaluate current live leases before claiming."))
                continue
            wanted = team_paths.claim_paths(condition["paths"])
            covered = (bool(found.unreadable) or any(lease.lane != holder and not lease.expired(now) and team_paths.overlap(lease.path_set, wanted)
                       for lease in found.leases) or any(_live(row, now) and team_paths.overlap(queue_paths[row["item"]["id"]], wanted)
                       for row in state["items"].values() if row["item"]["id"] != item["id"]))
            if covered:
                blockers.append(_block(kind, "Wait for the covering live leases to expire or be released."))
    return blockers


def _item_state(row, now):
    """Project effective scheduling state and its expiry evidence for every view."""
    expired = row["state"] == "claimed" and not _live(row, now)
    return {"state": "queued" if expired else row["state"], "lease_expired": expired,
            "expires_at": row["expires_at"]}


def _view(row, now, blockers=()):
    item = row["item"]
    result = {**item, **{key: value for key, value in row.items() if key != "item"},
            **_item_state(row, now),
            "label": _QueueLabel(item["id"], item["title"], row["lane"]),
            "blockers": array(blockers), "conditions_met": not blockers}
    if not _branch_evidence(row.get("branch"))[0]:
        result["branch_supported"] = False
    return result


def normalize_branch(value):
    """Return one optional local branch, or QueueRefusal('invalid_arguments'). Performs no I/O."""
    try:
        return team.normalize_branch(value)
    except team.TeamUsageError:
        raise QueueRefusal("invalid_arguments") from None


_branch_name = normalize_branch


def _branch_evidence(value):
    """Classify stored evidence without rewriting it or refusing its queue."""
    try:
        return True, _branch_name(value)
    except QueueRefusal:
        return False, None


def _claim_constraints(row, state, lanes, found, now, queue_paths, index, blockers=None):
    """Evaluate item-wide conditions once; typed paths remain inert globs."""
    item = row["item"]
    blockers = (_blockers(item, state, lanes, found, now, queue_paths)
                if blockers is None else array(blockers))
    scope = queue_paths[item["id"]]
    if any(team_paths.first_match(scope, path) is None for path in item.get("brief_paths", [])):
        blockers.append(_block("brief_outside_scope", "Correct brief_paths to name only files admitted by the item's paths before claiming."))
    overlaps = [_block("scope_overlap", "Release the overlapping queue claim before retrying.", item_id=other["item"]["id"])
                for other in index["live"] if team_paths.overlap(queue_paths[other["item"]["id"]], scope)]
    covering = {lease.lane for lease in index["leases"] if team_paths.overlap(scope, lease.path_set)}
    return {"blockers": blockers, "overlaps": overlaps, "covering": covering}


def _change(state, verb, now, *, item=None, identifier=None, expect=None, lane=None, capabilities=None, ttl_s=3600, branch=None, lanes=None, found=None, root=None, queue_paths=None):
    if verb == "add":
        _require(item["id"] not in state["items"] and item["id"] not in state["completed"], "item_exists")
        _require(sum(row["state"] != "done" for row in state["items"].values()) < MAX_ITEMS, "queue_live_limit")
        row = {"item": item, "state": "queued", "revision": secrets.token_hex(32), "lane": None, "expires_at": None}
        state["items"][item["id"]] = row
        return row
    _require(identifier not in state["completed"], "item_done")
    _require(identifier in state["items"], "item_missing")
    row = state["items"][identifier]
    _require(row["revision"] == expect, "stale_revision")
    if verb == "claim":
        _check_claim(root, state, row, lane, capabilities, lanes, found, now, queue_paths)
        row.update(state="claimed", lane=lane, expires_at=now + ttl_s, branch=branch)
    else:
        _require(row["state"] == "claimed", "not_claimed")
        if _live(row, now):
            _require(lane is not None, "lane_required")
            _require(lane == row["lane"], "lane_mismatch")
        if verb == "done":
            _require(_live(row, now), "lease_expired")
            row["state"] = "done"
            if not _branch_evidence(row.get("branch"))[0]:
                row.pop("branch", None)
        else:
            row.update(state="queued", lane=None, expires_at=None)
            row.pop("branch", None)
    row["revision"] = secrets.token_hex(32)
    return row


def _claim_policy(root):
    try:
        limit = team_profile.load(root)["profile"]["run_config"]["limits"]["writers_max"]
        return {"valid": True, "writers_max": limit}
    except team_profile.ProfileError:
        return {"valid": False}


def _claim_index(state, found, now):
    live = tuple(row for row in state["items"].values() if _live(row, now))
    leases = tuple(lease for lease in found.leases if not lease.expired(now))
    busy = {row["lane"] for row in live}
    return {"live": live, "leases": leases, "busy": busy,
            "occupied": busy | {lease.lane for lease in leases}}


def _foreign_lease(covering, lane, found):
    return bool(found.unreadable) or len(covering) > 1 or (bool(covering) and lane not in covering)


def _capacity(index, lane, policy):
    return len(index["occupied"]) + (lane not in index["occupied"]) <= policy["writers_max"]


def _check_claim(root, state, row, lane, capabilities, lanes, found, now, queue_paths):
    """Claims and fingerprints share item constraints and lane predicates."""
    _require(row["state"] != "done", "item_done")
    _require(not _live(row, now), "already_claimed")
    index = _claim_index(state, found, now)
    _require(lane not in index["busy"], "lane_busy")
    _require(set(row["item"]["capabilities"]) <= set(capabilities), "capability_mismatch")
    constraints = _claim_constraints(row, state, lanes, found, now, queue_paths, index)
    blockers = constraints["blockers"]
    if _foreign_lease(constraints["covering"], lane, found):
        blockers.append(_block("foreign_lease", "Wait for foreign repository leases to expire or be released; repair unreadable leases, then retry the current revision."))
    if lanes and lane not in lanes:
        blockers.append(_block("coordinator", "Ask the coordinator to configure the requested lane in .aegis/team.json."))
    blockers.extend(constraints["overlaps"])
    if blockers:
        raise QueueRefusal("blocked", blockers=blockers)
    policy = _claim_policy(root)
    _require(policy["valid"], "profile_unavailable")
    _require(not found.unreadable and _capacity(index, lane, policy), "capacity_full")


def _claimable(state, lanes, found, moment, queue_paths, policy, leases_checked, item_blockers):
    result = []
    if not leases_checked or not policy["valid"]:
        return result
    index = _claim_index(state, found, moment)
    eligible = {lane for lane in (lanes or {})
                if lane not in index["busy"] and _capacity(index, lane, policy)}
    for identifier, row in sorted(state["items"].items()):
        if row["state"] == "done" or _live(row, moment):
            continue
        constraints = _claim_constraints(row, state, lanes, found, moment, queue_paths, index,
                                         item_blockers[identifier])
        if constraints["blockers"] or constraints["overlaps"] or found.unreadable:
            continue
        # No covering lease permits any eligible lane; one requires that lane.
        # Multiple covering lanes always imply a foreign lease for every lane.
        covering = constraints["covering"]
        if eligible and (not covering or (len(covering) == 1 and covering <= eligible)):
            result.append([identifier, row["revision"]])
    return result


def _lanes(root):
    """A policy refusal gates claims; it cannot invalidate queue storage."""
    try:
        raw = _read(root, (AEGIS_DIRNAME, "team.json"), team.MAX_CONFIG_BYTES)
        if raw is None:
            return None
        lanes = team.parse_team(raw).lanes
        return lanes if lanes and all(_lane(name) for name in lanes) else None
    except (QueueRefusal, team.TeamFileError):
        return None


def _compact(root, state, caller):
    # Keep bodies still needed by unfinished work and durable minimal completion
    # markers for every removed body, including dependencies filed in the future.
    needed = {name for row in state["items"].values() if row["state"] != "done"
              for name in row["item"].get("after", [])}
    removed = [key for key, row in state["items"].items() if row["state"] == "done" and key not in needed]
    _require(len(state["completed"]) + len(removed) <= MAX_COMPLETED, "queue_history_limit")
    for key in removed:
        state["completed"][key] = True
        del state["items"][key]
    result = {"removed_count": len(removed), "removed_ids": sorted(removed),
              "retained_done_count": sum(row["state"] == "done" for row in state["items"].values())}
    if removed:
        _publish(root, state)
        if events.try_append(root, "lease_claimed", "queue_compact",
                             _shown({"queue": True, "action": "compact", "caller": caller, **result})) is not None:
            result["warnings"] = [_block("event_not_recorded", "Check the events log; list before retrying this completed compaction.")]
    return result


def _mutate(root, state, verb, moment, caller, lanes, found, queue_paths, arguments):
    """Publish once and append the correlated transition receipt under the caller's lock."""
    previous = state["items"].get(arguments.get("identifier"))
    previous = dict(previous) if previous is not None else None
    row = _change(state, verb, moment, lanes=lanes, found=found, root=root, queue_paths=queue_paths, **arguments)
    _publish(root, state, before_publish=lambda: team_claims.reconcile_completed(root, previous, _json))
    holder = row["lane"] or (previous["lane"] if previous else None)
    detail = {"queue": True, "action": verb, "caller": caller,
              "item_id": row["item"]["id"], "lane": holder,
              "label": _QueueLabel(row["item"]["id"], row["item"]["title"], holder),
              "from_revision": previous["revision"] if previous else None, "to_revision": row["revision"],
              "from_holder": previous["lane"] if previous else None,
              "to_holder": row["lane"] if row["state"] == "claimed" else None,
              "from_state": previous["state"] if previous else None, "to_state": row["state"],
              "from_expires_at": previous["expires_at"] if previous else None,
              "expires_at": row["expires_at"] if row["state"] == "claimed" else None}
    blockers = ([] if row["state"] == "done" else
        _blockers(row["item"], state, lanes, found, moment, queue_paths,
                  config_checked=verb == "claim", leases_checked=verb == "claim"))
    result = {"item": _view(row, moment, blockers)}
    # Reuse the existing kind; queue/action distinguish these from lane receipts.
    if events.try_append(root, "lease_claimed", "queue_" + verb, _shown(detail)) is not None:
        result["warnings"] = [_block("event_not_recorded", "Ask the coordinator to check the events log; list before retrying this completed mutation.")]
    return result


def _lease_findings(state, found, moment):
    findings = []
    unreadable = {lease.lane for lease in found.unreadable}
    for identifier, row in state["items"].items():
        fields = {"item_id": identifier, "lane": row["lane"]}
        supported, expected = _branch_evidence(row.get("branch"))
        if not supported:
            if row["state"] == "done":
                action = "Complete any unfinished dependents, then run aegis team queue compact; completed IDs remain reserved."
            elif row["state"] == "claimed":
                action = "Run aegis team queue release with this item's current --expect revision and --lane from list, then re-claim with a supported local --branch."
            else:
                action = "Claim this queued item with its current --expect revision and a supported local --branch."
            findings.append({**fields, "code": "CLAIM-BRANCH-UNSUPPORTED", **_block("claim_branch_unsupported", action)})
            expected = None
        if not _live(row, moment):
            continue
        if supported and expected is None:
            findings.append({**fields, "code": "CLAIM-BRANCH-UNKNOWN", **_block("claim_branch_unknown",
                "Release and re-claim this queue item with an explicit --branch for the lane; never infer it from workspace HEAD.")})
        lease = found.get(row["lane"])
        if row["lane"] in unreadable:
            code, reason = "LEASE-UNREADABLE", "lease_unreadable"
            action = "Run aegis team list --json; inspect the unreadable lease, then use aegis team release with its current --expect OID before claiming again."
        elif lease is None or lease.expired(moment):
            code, reason = "LANE-NO-LEASE", "lane_no_lease"
            action = "Ask the coordinator to establish a live repository lease for this claimed lane and branch."
        else:
            try:
                actual = _branch_name(lease.branch)
            except QueueRefusal:
                actual = None
            if actual is None:
                code, reason = "LEASE-BRANCH-UNKNOWN", "lease_branch_unknown"
                action = "Ask the lane holder to release and recreate its repository lease with an explicit valid --branch."
            elif expected is not None and actual != expected:
                code, reason = "LEASE-BRANCH-MISMATCH", "lease_branch_mismatch"
                action = "Ask the coordinator to reconcile the repository lease branch with the branch recorded by the queue claim."
            else:
                continue
        findings.append({**fields, "code": code, **_block(reason, action)})
    return findings


def _observe(root, state, verb, moment, lanes, found, queue_paths, capabilities, include_done, leases_checked, view):
    rows, findings, item_blockers = [], [], {}
    for identifier in sorted(state["items"]):
        row = state["items"][identifier]
        blockers = (_blockers(row["item"], state, lanes, found, moment, queue_paths,
                             leases_checked=leases_checked) if row["state"] != "done" else [])
        item_blockers[identifier] = blockers
        if row["state"] == "done" and not include_done:
            continue
        if capabilities is not None and not set(row["item"]["capabilities"]) <= set(capabilities):
            continue
        if view == "full":
            rows.append(_view(row, moment, blockers))
        if row["state"] == "done" or _live(row, moment):
            continue
        if blockers and all(block["reason"] == "coordinator" for block in blockers):
            findings.append({"item_id": identifier, "code": "WAITING_ONLY_COORDINATOR", **_block("coordinator", "Ask the coordinator to resolve the listed conditions.")})
        typed = row["item"].get("hold_until", [])
        if typed and blockers and all(block["reason"] == "judgment_hold" for block in blockers):
            findings.append({"item_id": identifier, "code": "CONDITIONS_MET_STILL_HELD", **_block("held_conditions_met", "Review and remove the judgment hold when ready; retain typed conditions for claim-time checks.")})
    result = {"items": rows} if view == "full" else {"view": view}
    if include_done and view == "full":
        result["completed_ids"] = sorted(state["completed"])
    if verb == "audit":
        result["findings"] = findings + _lease_findings(state, found, moment)
        if view == "findings":
            identifiers = sorted({finding["item_id"] for finding in result["findings"]})
            result.update(
                affected_items=[{"id": identifier, **{key: state["items"][identifier][key]
                                for key in ("revision", "lane")},
                                **_item_state(state["items"][identifier], moment)} for identifier in identifiers],
                counts={"items": len(state["items"]), "findings": len(result["findings"]),
                        "affected_items": len(identifiers)}, omitted=["items"],
                next_action="Run aegis team queue list --include-done --view full --json and read full constraints before changing holds or work.")
    if verb == "list":
        policy = _claim_policy(root)
        claimable = _claimable(state, lanes, found, moment, queue_paths, policy, leases_checked, item_blockers)
        result["claimable_fingerprint"] = team_claims.fingerprint(
            state, found, moment, claimable, dict(lanes) if lanes is not None else None, policy, leases_checked)
        if view == "fingerprint":
            result.update(omitted=["items", "completed_ids"],
                          next_action="After a fingerprint change, run aegis team queue list --view full --json; the fingerprint never authorizes a claim.")
    return result


def _unclaim(root, state, moment, caller, arguments):
    original = _read(root, (AEGIS_DIRNAME, "state", "team-queue.json"))
    def restore():
        _publish(root, state, raw=original)
    try:
        result = team_claims.transition(root, state, now=moment, caller=caller,
                                       publish=_publish, restore=restore, shown=_shown, decode=_json, **arguments)
    except team_claims.ClaimRefusal as error:
        raise QueueRefusal(error.reason, blockers=error.blockers) from None
    row = result.pop("row")
    final = result.pop("state")
    queue_paths = {key: team_paths.claim_paths(value["item"]["paths"]) for key, value in final["items"].items()}
    blockers = _blockers(row["item"], final, None, team.LeaseSet((), ()), moment, queue_paths,
                         config_checked=False, leases_checked=False)
    return {**result, "item": _view(row, moment, blockers)}


def _unclaim_inputs(caller, arguments):
    """Retain the original acknowledgement, reason, caller refusal order."""
    _require(arguments["writer_stopped"], "writer_not_stopped")
    arguments["reason"] = _text(arguments.get("reason", ""), empty=True)
    try:
        return _text(team.default_owner() if caller is None else caller, 200)
    except QueueRefusal:
        raise QueueRefusal("invalid_arguments") from None


def _run_unclaim(root, moment, caller, arguments):
    """Defer a bounded input refusal until a serialized live-writer check.

    Without binding evidence the original input refusal wins, including when
    workspace discovery, lock acquisition, or state observation also fails.
    """
    input_error = None
    try:
        caller = _unclaim_inputs(caller, arguments)
    except QueueRefusal as error:
        input_error = error
    with ExitStack() as stack:
        try:
            root = _root(root)
            stack.enter_context(locked(root, timeout=5.0))
            stack.enter_context(team_writer_binding.claim_exclusion(root, validated_workspace=True))
            state = _state(root)
            team_claims.check_writer(root, state, arguments["identifier"],
                                     arguments["lane"], arguments["writer_stopped"])
        except team_claims.ClaimRefusal:
            raise
        except team_writer_binding.BindingLockRefused as error:
            if input_error is not None:
                raise input_error from None
            raise QueueRefusal("queue_lock_timeout" if error.code == "state_locked" else "queue_io_unavailable") from None
        except (QueueRefusal, storage.LockTimeoutError, OSError, ValueError, RuntimeError, gitsafe.GitError):
            if input_error is not None:
                raise input_error from None
            raise
        if input_error is not None:
            raise input_error
        return _unclaim(root, state, moment, caller, arguments)


def _arguments(verb, valid_clock, caller, arguments):
    """Validate structural inputs; _run_unclaim orders its remaining refusals."""
    _require(valid_clock, "invalid_arguments")
    include_done = arguments.pop("include_done", False)
    _require(type(include_done) is bool, "invalid_arguments")
    view = arguments.pop("view", "full")
    _require(type(view) is str and len(view) <= 11 and view in ("full", {"list": "fingerprint", "audit": "findings"}.get(verb)),
             "invalid_arguments")
    if verb == "add":
        arguments["item"] = _item(arguments["item"])
    if verb in ("claim", "release", "unclaim", "done"):
        _require(valid_key(arguments.get("identifier")), "invalid_arguments")
        expected = arguments.get("expect")
        _require(valid_revision(expected), "invalid_arguments")
    capabilities = arguments.get("capabilities")
    _require(verb != "claim" or capabilities is not None, "invalid_arguments")
    if capabilities is not None:
        try:
            check_capabilities(capabilities)
        except QueueRefusal:
            raise QueueRefusal("invalid_arguments") from None
    if verb in ("claim", "release", "unclaim", "done"):
        lane = arguments.get("lane")
        _require((lane is None and verb not in ("claim", "unclaim")) or valid_lane(lane), "invalid_arguments")
    if verb == "unclaim":
        _require(type(arguments.get("writer_stopped")) is bool, "invalid_arguments")
    if verb == "claim":
        lane, ttl = arguments.get("lane"), arguments.get("ttl_s")
        _require(type(ttl) is int and 1 <= ttl <= team.MAX_TTL_S, "invalid_arguments")
        try:
            arguments["branch"] = normalize_branch(arguments.get("branch"))
        except QueueRefusal:
            raise QueueRefusal("invalid_arguments") from None
    write = verb not in ("list", "audit")
    if write and verb != "unclaim":
        try:
            caller = _text(team.default_owner() if caller is None else caller, 256)
        except QueueRefusal:
            raise QueueRefusal("invalid_arguments") from None
    return include_done, capabilities, write, caller, view


def _project(payload, error=None):
    """Render the fixed envelope after an operation or its documented refusal."""
    if isinstance(error, (QueueRefusal, team_claims.ClaimRefusal)):
        payload.update(refused=True, status="refused", reason=error.reason, next_action=_NEXT[error.reason],
                       exit_code=2 if error.reason in ("invalid_item", "invalid_arguments", "credential_like_text", "brief_outside_scope") else 1)
        if error.blockers is not None:
            payload["blockers"] = error.blockers
    elif isinstance(error, storage.LockTimeoutError):
        payload.update(refused=True, status="refused", reason="queue_lock_timeout", next_action=_NEXT["queue_lock_timeout"], exit_code=1)
    elif error is not None:
        payload.update(refused=True, status="refused", reason="queue_io_unavailable", next_action=_NEXT["queue_io_unavailable"], exit_code=1)
    return _shown(payload)


def _run(root, verb, now=None, caller=None, **arguments):
    moment = int(time.time()) if now is None else now
    # Invalid clocks never reach utc_stamp or acquire a descriptor.
    valid_clock = type(moment) is int and 0 <= moment <= 4102444800
    payload = primitives.envelope("aegis team queue " + verb, {}, schema="aegis.team.queue." + verb + "/v1",
                                  now=moment if valid_clock else 0)
    payload.update(refused=False, status="done", exit_code=0)
    try:
        include_done, capabilities, write, caller, view = _arguments(verb, valid_clock, caller, arguments)
        if verb == "unclaim":
            payload.update(_run_unclaim(root, moment, caller, arguments))
            return _project(payload)
        root = _root(root)
        with locked(root, timeout=5.0) if write else nullcontext():
            state = _state(root)
            if "unclaim" in state:
                raise team_claims.recovery_refusal(state["unclaim"], root=root)
            if verb == "compact":
                payload.update(_compact(root, state, caller))
                return _project(payload)
            # Parse each stored queue scope once for this observation. PathSet
            # values stay separate from the JSON state that will be published.
            queue_paths = {key: team_paths.claim_paths(row["item"]["paths"])
                           for key, row in state["items"].items()}
            lanes = _lanes(root) if verb in ("claim", "list", "audit") else None
            leases_checked = verb in ("claim", "audit")
            found = team.read_leases(root) if leases_checked else team.LeaseSet((), ())
            if verb == "list":
                found, leases_checked = team_claims.observe_leases(root)
            if write:
                payload.update(_mutate(root, state, verb, moment, caller, lanes, found, queue_paths, arguments))
            else:
                payload.update(_observe(root, state, verb, moment, lanes, found, queue_paths, capabilities, include_done, leases_checked, view))
    except (QueueRefusal, team_claims.ClaimRefusal, storage.LockTimeoutError,
            OSError, ValueError, RuntimeError, gitsafe.GitError) as error:
        return _project(payload, error)
    return _project(payload)


def add(root, item, *, now=None, caller=None):
    return _run(root, "add", now, caller=caller, item=item)


def list(root, *, capabilities=None, include_done=False, view="full", now=None):
    arguments = {"include_done": include_done}
    if capabilities is not None:
        arguments["capabilities"] = capabilities
    invalid = list_argument_refusal(arguments)
    if invalid is not None:
        return invalid
    return _run(root, "list", now, capabilities=capabilities, include_done=include_done, view=view)


def compact(root, *, now=None, caller=None):
    return _run(root, "compact", now, caller=caller)


def audit(root, *, view="full", now=None):
    return _run(root, "audit", now, view=view)


def claim(root, identifier, *, expect, lane, capabilities=(), ttl_s=3600, branch=None, now=None, caller=None):
    return _run(root, "claim", now, caller=caller, identifier=identifier, expect=expect, lane=lane,
                capabilities=[] if capabilities == () else capabilities, ttl_s=ttl_s, branch=branch)


def release(root, identifier, *, expect, lane=None, now=None, caller=None):
    return _run(root, "release", now, caller=caller, identifier=identifier, expect=expect, lane=lane)


def unclaim(root, identifier, *, expect, lane, reason="", writer_stopped=False, now=None, caller=None):
    return _run(root, "unclaim", now, caller=caller, identifier=identifier, expect=expect, lane=lane,
                reason=reason, writer_stopped=writer_stopped)


def done(root, identifier, *, expect, lane=None, now=None, caller=None):
    return _run(root, "done", now, caller=caller, identifier=identifier, expect=expect, lane=lane)
