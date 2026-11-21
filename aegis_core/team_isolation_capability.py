"""Isolation capability report from a validated document and injected tables.

The vocabulary and host table are caller arguments. This module does not import
tools/, open a path, or start a process. Bad input returns a typed refusal.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath, PureWindowsPath
from types import SimpleNamespace

from aegis_core.diagnostic_messages import receipt_value
from aegis_core.primitives import DuplicateKeyError, json_preflight, strict_loads
from aegis_core.team_isolation_refusal import CAPABILITY_CODES, REFUSALS, IsolationRefusal
from aegis_core.team_isolation_refusal import finish as _finish, refusal as _refusal

__all__ = [
    "MAX_DOCUMENT_BYTES",
    "REFUSALS",
    "IsolationRefusal",
    "capability_report",
    "compare",
    "present_text",
    "probe_plan",
    "probe_verdict",
    "resolved_capabilities",
]

MAX_ITEMS = 256
MAX_NAME = 256
MAX_MAP_VALUES = 1024
MAX_PATH = 4096
MAX_ROOTS = 16
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_DEPTH = 8
MAX_NODES = 8192
MAX_STRING = 4096
MAX_ATOM = 64
_BASE_IDS = ("prohibited-tool", "outside-write", "outside-edit", "outside-read", "prohibited-mcp")
_RESOLUTION_CODES = {
    "invalid_role", "invalid_host_mapping", "invalid_mcp_tools", "invalid_file_tools",
    "invalid_prohibited_call_tools", "uncovered_prohibited_calls", "prohibited_capability",
}
_DOC_KEYS = frozenset({"v", "entry", "host", "mcp_tools", "prohibited_call_tools", "file_tools"})
# Version 1 of the isolation document selects this closed role schema. The key sets are the
# registry validator's fields(); value sets arrive in the injected vocabulary.
_VOCAB_FIELDS = (
    "reads", "writes", "calls", "approvals", "assistants", "endpoint_roles", "lane_kinds",
    "kinds", "m1_uses", "independence_rules", "lifecycle_roles", "adapters", "profile_sources",
    "lifecycle_tools", "decision_tools",
)
_VOCAB_ORDERED = ("read_tools", "write_tools")
_VOCAB_MAPS = ("decision_reads",)
_VOCAB_KEYS = frozenset(_VOCAB_FIELDS + _VOCAB_ORDERED + _VOCAB_MAPS)
_ACTION_GROUPS = ("reads", "writes", "calls", "approvals")
_ENTRY_KEYS = frozenset({
    "title", "kind", "m1", "responsibility", "endpoint", "hat_of", "service", "lifecycle_role",
    "reads", "writes", "calls", "approvals", "prohibitions", "independence", "model_profile",
    "reports_to", "provision",
})
_PROHIBITION_KEYS = frozenset(_ACTION_GROUPS)
_ENDPOINT_REQUIRED = frozenset({"role"})
_ENDPOINT_OPTIONAL = frozenset({"lane_kind"})
_PROVISION_REQUIRED = frozenset({"adapter", "reader_shell", "assistants", "team_kind", "lifecycle_tools"})
_PROVISION_OPTIONAL = frozenset({"decision_tools"})
_INDEPENDENCE_KEYS = frozenset({"rule", "separate_session"})
_PROFILE_KEYS = frozenset({"source", "effort", "tier"})
_DECISION_WRITE_BAN = frozenset({"source", "mailbox", "board"})
_LIFECYCLE_BINDINGS = (
    ("router_status", "reads", "lifecycle", "router"),
    ("decider_record", "approvals", "lifecycle:delegated_decision", "decider"),
)
_TEXT_LIMIT = 256
_SERVICE_LIMIT = 128
_FIXED_PROFILE = "fixed"
_LANE_ROLE = "lane"
_REVIEWER_KIND = "reviewer"
_SERVICE_KIND = "service"
_DECISION_ADAPTER = "decision"
_LIMIT_REASONS = {"size", "string", "nodes", "container", "nesting", "atom"}
_INPUT_ERRORS = (ValueError, TypeError, UnicodeError, RecursionError, KeyError, AttributeError, IndexError)


def present_text(value):
    """Bound, canonicalize, redact, then clip through the shared receipt projection."""
    if type(value) is not str:
        return ""
    return receipt_value(value)

def _guard(function):
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except IsolationRefusal as refusal:
            return _refusal(refusal.code)
        except _INPUT_ERRORS:
            return _refusal("invalid_document")
    wrapped.__name__ = function.__name__
    wrapped.__doc__ = function.__doc__
    return wrapped

def _name(value):
    # Length is checked before scanning characters. Newlines are refused, not joined.
    return (type(value) is str and 0 < len(value) <= MAX_NAME and value.isascii()
            and all(32 <= ord(char) < 127 for char in value))

def _capability(value):
    if not _name(value):
        return False
    return value in {"read", "write-scope", "shell", "subagent"} or (
        value.startswith("mcp:") and len(value) > 4
        and all(char.isalnum() or char in "_./:-" for char in value[4:]))

def _catalog_name(value):
    return (type(value) is str and 0 < len(value) <= MAX_NAME and value.isascii()
            and all(32 <= ord(char) < 127 or char in "\t\r\n\v\f" for char in value))

def _names(value, *, empty=False, sequence=False, capabilities=False, catalog=False):
    # Exact builtins only. The public boundary already snapshotted caller objects.
    if sequence:
        kind = type(value) in (list, tuple)
    else:
        kind = type(value) is list
    if not kind or not (0 if empty else 1) <= len(value) <= MAX_ITEMS:
        return None
    # Bounds precede traversal, string inspection, set allocation and sorting.
    valid = _capability if capabilities else (_catalog_name if catalog else _name)
    if not all(valid(item) for item in value):
        return None
    names = set(value)
    return names if len(names) == len(value) else None

def _as_names(value, *, ordered):
    if ordered:
        if type(value) not in (list, tuple):
            return None
    elif type(value) not in (set, frozenset, list, tuple):
        return None
    if not 0 < len(value) <= MAX_ITEMS:
        return None
    if any(not _name(item) for item in value):
        return None
    if ordered and len(set(value)) != len(value):
        return None
    return tuple(value) if ordered else set(value)

def _decision_reads(value, tools, reads):
    if type(value) is not dict or len(value) != len(tools):
        return None
    # The key count is rejected before any mapped read-set is walked.
    try:
        if any(not _name(key) for key in value) or set(value) != set(tools):
            return None
    except _INPUT_ERRORS:
        return None
    parsed = {}
    for key in tools:
        names = _as_names(value[key], ordered=False)
        if names is None or not names <= reads:
            return None
        parsed[key] = names
    return parsed

def _text_bytes(value):
    """Byte length, or over the ceiling. Length is decided before any encode."""
    size = len(value)
    if size > MAX_DOCUMENT_BYTES:
        return MAX_DOCUMENT_BYTES + 1
    if size == 0 or value.isascii():
        return size
    total = 0
    for char in value:
        code = ord(char)
        total += 1 if code < 0x80 else 2 if code < 0x800 else 3 if code < 0x10000 else 4
        if total > MAX_DOCUMENT_BYTES:
            return total
    return total

_MISS = object()

def _fit(work, size):
    if size > MAX_DOCUMENT_BYTES or work[1] + size > MAX_DOCUMENT_BYTES:
        return False
    work[1] += size
    return True

def _atom(value, work):
    kind = type(value)
    if kind is str or kind is bytes or kind is bytearray:
        size = _text_bytes(value) if kind is str else len(value)
        return value if _fit(work, size) else _MISS
    if value is None or kind is bool or kind is float:
        return value if _fit(work, 1) else _MISS
    if kind is not int:
        return _MISS
    bits = value.bit_length()
    size = (bits + 7) // 8 or 1
    if bits > MAX_DOCUMENT_BYTES * 8 or not _fit(work, size):
        return _MISS
    return value

def _take(value):
    """Observed entries only. len() on the foreign object is never consulted."""
    try:
        iterator, found = iter(value), []
        while len(found) <= MAX_ITEMS:
            try:
                found.append(next(iterator))
            except StopIteration:
                return found
        return _MISS
    except _INPUT_ERRORS:
        return _MISS

def _snapshot(value, work, depth, values):
    """One shared budget. work[0] is spent before each descent; work[1] is bytes."""
    if depth > MAX_DEPTH or work[0] <= 0:
        return _MISS
    work[0] -= 1
    if isinstance(value, Mapping):
        found = _take(value)
        if found is _MISS:
            return _MISS
        snaps = []
        for key in found:
            snap = _snapshot(key, work, depth + 1, True)
            if snap is _MISS:
                return _MISS
            snaps.append(snap)
        if not values:
            return snaps
        copied = {}
        for key, snap in zip(found, snaps):
            try:
                child = _snapshot(value[key], work, depth + 1, True)
            except _INPUT_ERRORS:
                return _MISS
            if child is _MISS or snap in copied:
                return _MISS
            copied[snap] = child
        return copied
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, (Sequence, set, frozenset)):
        return _atom(value, work)
    found = _take(value)
    if found is _MISS:
        return _MISS
    copied = []
    for item in found:
        snap = _snapshot(item, work, depth + 1, True)
        if snap is _MISS:
            return _MISS
        copied.append(snap)
    if isinstance(value, (set, frozenset)):
        try:
            return frozenset(copied)
        except _INPUT_ERRORS:
            return _MISS
    return tuple(copied) if type(value) is tuple else copied

def _plain(value):
    try:
        return _snapshot(value, [MAX_NODES, 0], 0, True)
    except _INPUT_ERRORS:
        return _MISS

def _freeze(value):
    """Snapshot one caller argument. None stays absent. Failure is _MISS."""
    if value is None:
        return None
    return _plain(value)

def _vocabulary(value):
    if value is None:
        return None, "missing_vocabulary"
    if not isinstance(value, Mapping):
        return None, "invalid_table"
    work = [MAX_NODES, 0]
    try:
        keys = _snapshot(value, work, 0, False)
        if keys is _MISS or len(keys) != len(_VOCAB_KEYS) or set(keys) != _VOCAB_KEYS:
            return None, "invalid_table"
        copied = {}
        for key in _VOCAB_KEYS:
            copied[key] = _snapshot(value[key], work, 1, True)
            if copied[key] is _MISS:
                return None, "invalid_table"
        parsed = {}
        for key in _VOCAB_FIELDS:
            names = _as_names(copied[key], ordered=False)
            if names is None:
                return None, "invalid_table"
            parsed[key] = names
        for key in _VOCAB_ORDERED:
            names = _as_names(copied[key], ordered=True)
            if names is None:
                return None, "invalid_table"
            parsed[key] = names
        reads = _decision_reads(copied["decision_reads"], parsed["decision_tools"], parsed["reads"])
        if reads is None:
            return None, "invalid_table"
        parsed["decision_reads"] = reads
    except _INPUT_ERRORS:
        return None, "invalid_table"
    if set(parsed["read_tools"]) & set(parsed["write_tools"]):
        return None, "invalid_table"
    parsed["file_tool_names"] = parsed["read_tools"] + parsed["write_tools"]
    return SimpleNamespace(**parsed), None

def _host_table(value):
    if value is None:
        return None, "missing_host_table"
    if type(value) is not dict or not value or any(not _name(key) for key in value):
        return None, "invalid_table"
    return value, None

def _file_tools(reads, writes, vocab):
    found = []
    if "source" in reads:
        found.extend(vocab.read_tools)
    if "source" in writes:
        found.extend(vocab.write_tools)
    return found

def _bind(code):
    return None, code

def _keys(value, required, optional=()):
    """Closed object. The caller snapshot is already an exact dict."""
    allowed = required | set(optional)
    if type(value) is not dict:
        return "invalid_role"
    if len(value) > len(allowed):
        return "unknown_field"
    keys = set(value)
    if keys - allowed:
        return "unknown_field"
    if not required <= keys:
        return "invalid_role"
    return None

def _actions(value, permitted):
    names = _names(value, empty=True)
    if names is None or not names <= permitted:
        return None
    return names

def _text(value, limit):
    return type(value) is str and 0 < len(value) <= limit and "\x00" not in value and value.isascii()

def _entry_actions(entry, vocab):
    allowed = {}
    for group in _ACTION_GROUPS:
        names = _actions(entry.get(group), getattr(vocab, group))
        if names is None:
            return None
        allowed[group] = names
    return allowed

def _prohibitions(denied, allowed, vocab):
    code = _keys(denied, _PROHIBITION_KEYS)
    if code:
        return None, code
    prohibited = {}
    for group in _ACTION_GROUPS:
        names = _actions(denied.get(group), getattr(vocab, group))
        if names is None or names & allowed[group]:
            return None, "invalid_role"
        prohibited[group] = names
    return prohibited, None

def _checked_lifecycle(entry, allowed, vocab):
    marked = {action for group in ("writes", "approvals") for action in allowed[group]
              if action.startswith("lifecycle:")}
    role = entry.get("lifecycle_role")
    if role is None:
        return (None, "invalid_role") if marked else (None, None)
    if not _name(role) or role not in vocab.lifecycle_roles:
        return None, "invalid_role"
    return role, None

def _independence(value, vocab):
    code = _keys(value, _INDEPENDENCE_KEYS)
    if code:
        return code
    rule = value.get("rule")
    if not _name(rule) or rule not in vocab.independence_rules or type(value.get("separate_session")) is not bool:
        return "invalid_role"
    return None

def _profile(value, vocab):
    if type(value) is not dict:
        return "invalid_role"
    if len(value) > len(_PROFILE_KEYS):
        return "unknown_field"
    keys = set(value)
    if keys - _PROFILE_KEYS:
        return "unknown_field"
    source = value.get("source")
    if "source" not in keys or not _name(source) or source not in vocab.profile_sources:
        return "invalid_role"
    if source != _FIXED_PROFILE and keys != {"source"}:
        return "unknown_field"
    for key in ("effort", "tier"):
        if key in value and not _name(value.get(key)):
            return "invalid_role"
    return None

def _endpoint(value, vocab):
    if value is None:
        return None, None, None
    code = _keys(value, _ENDPOINT_REQUIRED, _ENDPOINT_OPTIONAL)
    if code:
        return code, None, None
    role = value.get("role")
    if not _name(role) or role not in vocab.endpoint_roles:
        return "invalid_role", None, None
    # lane_kind is present if and only if the endpoint role is lane, and then
    # it must be a vocabulary string. Null is not a member.
    if ("lane_kind" in value) != (role == _LANE_ROLE):
        return "invalid_role", None, None
    if role != _LANE_ROLE:
        return None, role, None
    kind = value["lane_kind"]
    if not _name(kind) or kind not in vocab.lane_kinds:
        return "invalid_role", None, None
    return None, role, kind

def _identity(entry, endpoint, vocab):
    kind, m1 = entry.get("kind"), entry.get("m1")
    if not _name(kind) or kind not in vocab.kinds or not _name(m1) or m1 not in vocab.m1_uses:
        return "invalid_role"
    if not _text(entry.get("title"), _TEXT_LIMIT) or not _text(entry.get("responsibility"), _TEXT_LIMIT):
        return "invalid_role"
    service, hat, reports = entry.get("service"), entry.get("hat_of"), entry.get("reports_to")
    if service is not None and (endpoint is not None or kind != _SERVICE_KIND or not _text(service, _SERVICE_LIMIT)):
        return "invalid_role"
    if hat is not None and (endpoint is not None or not _name(hat)):
        return "invalid_role"
    if reports is not None and not _name(reports):
        return "invalid_role"
    return None

def _provision(value, endpoint, allowed, lifecycle_role, vocab):
    if value is None or endpoint is None:
        return (None, None) if value is None and endpoint is None else ("invalid_role", None)
    code = _keys(value, _PROVISION_REQUIRED, _PROVISION_OPTIONAL)
    if code:
        return code, None
    adapter, assistants = value.get("adapter"), value.get("assistants")
    if (not _name(adapter) or adapter not in vocab.adapters or type(value.get("reader_shell")) is not bool
            or type(value.get("team_kind")) is not bool
            or (assistants is not None and (not _name(assistants) or assistants not in vocab.assistants))):
        return "invalid_role", None
    if value["reader_shell"] and ("source" not in allowed["reads"] or "source" in allowed["writes"]):
        return "invalid_role", None
    if adapter == _DECISION_ADAPTER and (allowed["writes"] & _DECISION_WRITE_BAN):
        return "invalid_role", None
    tools = _actions(value.get("lifecycle_tools"), vocab.lifecycle_tools)
    if tools is None or (adapter == _DECISION_ADAPTER and tools):
        return "invalid_role", None
    for tool, group, action, bound_role in _LIFECYCLE_BINDINGS:
        if tool in tools and (action not in allowed[group] or lifecycle_role != bound_role):
            return "invalid_role", None
    decision = _actions(value.get("decision_tools", []), vocab.decision_tools)
    if decision is None or (decision and adapter != _DECISION_ADAPTER):
        return "invalid_role", None
    for tool in decision:
        needed = vocab.decision_reads.get(tool)
        if needed is None or not needed <= allowed["reads"]:
            return "invalid_role", None
    return None, {"reader_shell": value["reader_shell"], "helpers": assistants is not None}

def _role(entry, vocab):
    if type(entry) is not dict:
        return _bind("invalid_role")
    code = _keys(entry, _ENTRY_KEYS)
    if code:
        return _bind(code)
    allowed = _entry_actions(entry, vocab)
    if allowed is None:
        return _bind("invalid_role")
    prohibited, code = _prohibitions(entry.get("prohibitions"), allowed, vocab)
    if code:
        return _bind(code)
    lifecycle_role, code = _checked_lifecycle(entry, allowed, vocab)
    if code:
        return _bind(code)
    for check in (_independence(entry.get("independence"), vocab), _profile(entry.get("model_profile"), vocab)):
        if check:
            return _bind(check)
    code, endpoint_role, lane_kind = _endpoint(entry.get("endpoint"), vocab)
    if code:
        return _bind(code)
    code = _identity(entry, endpoint_role, vocab)
    if code:
        return _bind(code)
    code, provision = _provision(entry.get("provision"), endpoint_role, allowed, lifecycle_role, vocab)
    if code or endpoint_role is None:
        return _bind(code or "invalid_role")
    reads, writes = allowed["reads"], allowed["writes"]
    return {"file_tools": _file_tools(reads, writes, vocab), "writer": "source" in writes,
            "reader_shell": provision["reader_shell"], "helpers": provision["helpers"],
            "reviewer": lane_kind == _REVIEWER_KIND, "calls": sorted(prohibited["calls"])}, None

def _host(mapping, vocab):
    if type(mapping) is not dict or len(mapping) != 4:
        return None
    if any(type(mapping.get(key)) is not bool for key in ("reader_shell", "writer_shell", "session_helpers")):
        return None
    files = mapping.get("file_tools")
    required = vocab.file_tool_names
    if type(files) is not dict or len(files) != len(required):
        return None
    read_names = set(vocab.read_tools)
    for name in required:
        if files.get(name) != ("read" if name in read_names else "write-scope"):
            return None
    return mapping

def _call_mapping(mapping, calls, vocab):
    if type(mapping) is not dict:
        return None, list(calls), "invalid_prohibited_call_tools"
    total, normalized = 0, {}
    for key, values in mapping.items():
        if (not _name(key) or key not in vocab.calls or type(values) not in (list, tuple)
                or not 0 < len(values) <= MAX_ITEMS):
            return None, list(calls), "invalid_prohibited_call_tools"
        total += len(values)
        if total > MAX_MAP_VALUES:
            return None, list(calls), "invalid_prohibited_call_tools"
        tools = _names(values, sequence=True, capabilities=True)
        if tools is None:
            return None, list(calls), "invalid_prohibited_call_tools"
        normalized[key] = tools
    uncovered = sorted(set(calls) - normalized.keys())
    return normalized, uncovered, "uncovered_prohibited_calls" if uncovered else None

def _unresolved(code, calls=(), uncovered=()):
    return {"status": "unknown", "code": code, "capabilities": [], "file_tools": [],
            "prohibited_calls": list(calls), "uncovered_calls": list(uncovered)}

def _resolved(entry, host_capabilities, mcp_tools, prohibited_call_tools, file_tools, vocab):
    role, code = _role(entry, vocab)
    if code:
        return _unresolved(code)
    calls = role["calls"]
    selected = role["file_tools"] if file_tools is None else file_tools
    if type(selected) is not list:
        return _unresolved("invalid_file_tools", calls)
    sequence = list(selected)
    names = _names(sequence, empty=True)
    if names is None or not names <= set(role["file_tools"]):
        return _unresolved("invalid_file_tools", calls)
    mapping, uncovered, code = _call_mapping(prohibited_call_tools, calls, vocab)
    if code:
        return _unresolved(code, calls, uncovered)
    host = _host(host_capabilities, vocab)
    if host is None:
        return _unresolved("invalid_host_mapping", calls)
    capabilities = {host["file_tools"][name] for name in sequence}
    if role["writer"] and host["writer_shell"]:
        capabilities.update(("shell", "read", "write-scope"))
    elif role["reader_shell"] and host["reader_shell"]:
        capabilities.update(("shell", "read"))
    if host["session_helpers"] and role["helpers"] and not role["reviewer"]:
        capabilities.add("subagent")
    mcp = _names(mcp_tools, empty=True, capabilities=True)
    if (mcp is None or len(mcp) + len(capabilities) > MAX_ITEMS
            or any(not name.startswith("mcp:") for name in mcp)):
        return _unresolved("invalid_mcp_tools", calls)
    capabilities.update(mcp)
    if any(capabilities & mapping[call] for call in calls):
        return _unresolved("prohibited_capability", calls)
    return {"status": "resolved", "code": "resolved", "capabilities": sorted(capabilities),
            "file_tools": sequence, "prohibited_calls": calls, "uncovered_calls": []}

def _comparison(status, code, *, extras=(), missing=(), uncovered=()):
    return {"status": status, "code": code, "extras": sorted(extras),
            "missing": sorted(missing), "uncovered_calls": list(uncovered)}

def _compared(resolved, served_normalized, prohibited_call_tools, vocab):
    if type(resolved) is not dict or len(resolved) > 8:
        return _comparison("unknown", "invalid_resolution")
    status = resolved.get("status")
    if "prohibited_calls" in resolved:
        calls = _names(resolved.get("prohibited_calls"), empty=True)
        if calls is None or not calls <= vocab.calls:
            return _comparison("unknown", "invalid_resolution")
    elif status in ("unknown", "refused"):
        calls = set()
    else:
        return _comparison("unknown", "invalid_resolution")
    if status in ("unknown", "refused") and prohibited_call_tools is None and not calls:
        mapping, uncovered, code = {}, [], None
    else:
        mapping, uncovered, code = _call_mapping(prohibited_call_tools, sorted(calls), vocab)
    if code:
        return _comparison("unknown", code, uncovered=uncovered)
    if status in ("unknown", "refused"):
        refusal = resolved.get("code")
        kept = refusal if _name(refusal) and (refusal in CAPABILITY_CODES or refusal in _RESOLUTION_CODES) else "invalid_resolution"
        return _comparison("unknown", kept, uncovered=uncovered)
    expected = _names(resolved.get("capabilities"), capabilities=True)
    if status != "resolved" or expected is None:
        return _comparison("unknown", "invalid_resolution")
    if any(expected & mapping[call] for call in calls):
        return _comparison("unknown", "prohibited_capability")
    served = _names(served_normalized, catalog=True)
    if served is None:
        return _comparison("unknown", "invalid_catalog")
    extras, missing = served - expected, expected - served
    if extras:
        return _comparison("exceeds", "extra_capabilities", extras=extras, missing=missing)
    if missing:
        return _comparison("unknown", "incomplete_catalog", missing=missing)
    return _comparison("match", "equal_catalog")

def _path(value):
    if type(value) is not str or not 0 < len(value) <= MAX_PATH or not value.isascii():
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if value.startswith(("//", "\\\\")):
        return None
    windows = len(value) > 2 and value[1] == ":"
    if not windows and "\\" in value:
        return None
    spelling = value.replace("\\", "/")
    parts = spelling.split("/")
    if any(part in {".", ".."} for part in parts):
        return None
    if windows and any(part.endswith((".", " ")) or ":" in part for part in parts[1:]):
        return None
    path = PureWindowsPath(value) if windows else PurePosixPath(value)
    return path if path.is_absolute() and path.as_posix() == spelling else None

def _roots(values):
    if type(values) is not list or len(values) > MAX_ROOTS:
        return None
    paths = [_path(value) for value in values]
    if any(path is None for path in paths) or len(set(paths)) != len(paths):
        return None
    return paths

def _outside(path, roots):
    return all(type(path) is type(root) and path != root and root not in path.parents for root in roots)

def _prefix_sibling(path, root):
    if not root.name or root.parent not in path.parents:
        return False
    name = path.relative_to(root.parent).parts[0]
    root_name = root.name
    if isinstance(root, PureWindowsPath):
        name, root_name = name.casefold(), root_name.casefold()
    return name != root_name and name.startswith(root_name)

def _no_plan():
    return {"status": "unknown", "code": "invalid_probe_plan", "attempts": []}

def _attempts(role, roots, prohibited_tool, prohibited_mcp, outside_path, edit_path, canary_path, sibling_path):
    if (prohibited_tool not in ("shell", "subagent") or not _capability(prohibited_mcp)
            or not prohibited_mcp.startswith("mcp:")):
        return None
    outside, edit, canary = _path(outside_path), _path(edit_path), _path(canary_path)
    paths = (outside, edit, canary)
    if any(path is None for path in paths) or outside == edit:
        return None
    if any(type(path) is not type(outside) or not _outside(path, roots) for path in paths):
        return None
    sibling = _path(sibling_path) if role["writer"] else None
    if role["writer"] and (sibling is None or not roots or not _outside(sibling, roots)
                           or not any(_prefix_sibling(sibling, root) for root in roots)):
        return None
    attempts = [
        {"id": "prohibited-tool", "operation": "call", "capability": prohibited_tool, "path": None},
        {"id": "outside-write", "operation": "write", "capability": "write-scope", "path": outside_path},
        {"id": "outside-edit", "operation": "edit", "capability": "write-scope", "path": edit_path},
        {"id": "outside-read", "operation": "read", "capability": "read", "path": canary_path},
        {"id": "prohibited-mcp", "operation": "call", "capability": prohibited_mcp, "path": None},
    ]
    if role["writer"]:
        attempts.append({"id": "sibling-write", "operation": "write", "capability": "write-scope", "path": sibling_path})
    return attempts

def _planned(entry, resolved, *, vocab, host_capabilities, mcp_tools, prohibited_tool, prohibited_mcp,
             write_roots, outside_path, edit_path, canary_path, sibling_path=None,
             prohibited_call_tools=None, file_tools=None):
    role, code = _role(entry, vocab)
    roots = _roots(write_roots)
    if code or role is None or roots is None or type(resolved) is not dict or len(resolved) != 6:
        return _no_plan()
    if set(resolved) != {"status", "code", "capabilities", "file_tools", "prohibited_calls", "uncovered_calls"}:
        return _no_plan()
    granted = _names(resolved.get("capabilities"), empty=True, capabilities=True)
    calls = _names(resolved.get("prohibited_calls"), empty=True)
    selected = _names(resolved.get("file_tools"), empty=True)
    uncovered = resolved.get("uncovered_calls")
    if (resolved.get("status") != "resolved" or resolved.get("code") != "resolved"
            or granted is None or calls != set(role["calls"]) or selected is None
            or type(uncovered) is not list or len(uncovered) != 0
            or not _capability(prohibited_tool) or not _capability(prohibited_mcp)
            or prohibited_tool in granted or prohibited_mcp in granted):
        return _no_plan()
    expected = _resolved(entry, host_capabilities, mcp_tools, prohibited_call_tools, file_tools, vocab)
    if expected["status"] != "resolved" or resolved != expected:
        return _no_plan()
    attempts = _attempts(role, roots, prohibited_tool, prohibited_mcp, outside_path, edit_path, canary_path, sibling_path)
    return _no_plan() if attempts is None else {"status": "planned", "code": "planned", "attempts": attempts}

def _checked_plan(entry, resolved, roots, plan, *, vocab, host_capabilities, mcp_tools,
                  prohibited_call_tools=None, file_tools=None):
    role, code = _role(entry, vocab)
    if (code or role is None or type(plan) is not dict or len(plan) != 3
            or plan.get("status") != "planned" or plan.get("code") != "planned"):
        return None
    attempts = plan.get("attempts")
    if type(attempts) is not list or len(attempts) != (6 if role["writer"] else 5):
        return None
    required = _BASE_IDS + (("sibling-write",) if role["writer"] else ())
    for name, attempt in zip(required, attempts):
        if type(attempt) is not dict or len(attempt) != 4 or not _name(attempt.get("id")):
            return None
        if attempt["id"] != name or not _capability(attempt.get("capability")):
            return None
        if not _name(attempt.get("operation")) or (attempt.get("path") is not None and _path(attempt["path"]) is None):
            return None
    regenerated = _planned(
        entry, resolved, write_roots=roots, host_capabilities=host_capabilities, mcp_tools=mcp_tools,
        prohibited_call_tools=prohibited_call_tools, file_tools=file_tools, vocab=vocab,
        prohibited_tool=attempts[0]["capability"], prohibited_mcp=attempts[4]["capability"],
        outside_path=attempts[1].get("path"), edit_path=attempts[2].get("path"),
        canary_path=attempts[3].get("path"),
        sibling_path=attempts[5].get("path") if role["writer"] else None)
    if regenerated["status"] != "planned" or regenerated["attempts"] != attempts:
        return None
    return {attempt["id"]: attempt for attempt in regenerated["attempts"]}

def _judged(entry, resolved, roots, plan, observations, *, vocab, host_capabilities, mcp_tools,
            prohibited_call_tools=None, file_tools=None):
    expected = _checked_plan(
        entry, resolved, roots, plan, host_capabilities=host_capabilities, mcp_tools=mcp_tools,
        prohibited_call_tools=prohibited_call_tools, file_tools=file_tools, vocab=vocab)
    if expected is None:
        return {"status": "unknown", "code": "invalid_probe_plan"}
    if type(observations) is not list or len(observations) > len(expected):
        return {"status": "unknown", "code": "invalid_observations"}
    seen, outcomes = set(), set()
    for observation in observations:
        if type(observation) is not dict or len(observation) != 5:
            return {"status": "unknown", "code": "invalid_observations"}
        if set(observation) != {"id", "outcome", "operation", "capability", "path"}:
            return {"status": "unknown", "code": "invalid_observations"}
        name, outcome = observation.get("id"), observation.get("outcome")
        if (not _name(name) or name not in expected or name in seen
                or not _name(outcome) or outcome not in {"refused", "allowed", "unknown"}):
            return {"status": "unknown", "code": "invalid_observations"}
        for key in ("operation", "capability", "path"):
            value = observation.get(key)
            if key == "path":
                if value is not None and _path(value) is None:
                    return {"status": "unknown", "code": "invalid_observations"}
            elif not _name(value):
                return {"status": "unknown", "code": "invalid_observations"}
            if value != expected[name][key]:
                return {"status": "unknown", "code": "invalid_observations"}
        seen.add(name)
        outcomes.add(outcome)
    if "allowed" in outcomes:
        return {"status": "fail", "code": "attempt_allowed"}
    if seen != expected.keys():
        return {"status": "unknown", "code": "incomplete_observations"}
    if outcomes != {"refused"}:
        return {"status": "unknown", "code": "inconclusive_observations"}
    return {"status": "pass", "code": "all_refused"}

def _decode_utf8(raw):
    return raw.decode("utf-8")

def _document_text(raw):
    if type(raw) is bytes:
        if len(raw) > MAX_DOCUMENT_BYTES:
            return None, "oversized"
        try:
            return _decode_utf8(raw), None
        except UnicodeError:
            return None, "invalid_encoding"
    if type(raw) is str:
        if len(raw) > MAX_DOCUMENT_BYTES:
            return None, "oversized"
        return raw, None
    return None, "invalid_document"

def _preflight(text):
    try:
        return json_preflight(
            text, max_bytes=MAX_DOCUMENT_BYTES, max_depth=MAX_DEPTH, max_nodes=MAX_NODES,
            max_items=MAX_ITEMS, max_string=MAX_STRING, max_atom=MAX_ATOM), None
    except ValueError as exc:
        reason = exc.args[0] if exc.args else ""
        if reason in _LIMIT_REASONS:
            return None, "oversized"
        return None, "invalid_document"

def _loads(text):
    try:
        return strict_loads(text), None
    except DuplicateKeyError:
        return None, "ambiguous"
    except _INPUT_ERRORS:
        return None, "invalid_document"

def _document(value):
    if type(value) is not dict or set(value) != _DOC_KEYS or type(value["v"]) is not int or value["v"] != 1:
        if type(value) is dict and set(value) - _DOC_KEYS:
            return None, "unknown_field"
        return None, "invalid_document"
    host = value["host"]
    tools = value["file_tools"]
    if (type(value["entry"]) is not dict or not _name(host) or type(value["mcp_tools"]) is not list
            or type(value["prohibited_call_tools"]) is not dict
            or (tools is not None and type(tools) is not list)):
        return None, "invalid_document"
    return value, None

def _capability_report(document, vocabulary=None, hosts=None):
    vocab, code = _vocabulary(vocabulary)
    if code:
        return _refusal(code)
    table, code = _host_table(None if hosts is None else _freeze(hosts))
    if code:
        return _refusal(code)
    if type(document) is bytes and len(document) > MAX_DOCUMENT_BYTES:
        return _refusal("oversized")
    # Character count can hide a UTF-8 overflow. The snapshot would collapse
    # that size failure to _MISS, so the byte reason is kept before it runs.
    if type(document) is str and _text_bytes(document) > MAX_DOCUMENT_BYTES:
        return _refusal("oversized")
    text, code = _document_text(_freeze(document))
    if code:
        return _refusal(code)
    text, code = _preflight(text)
    if code:
        return _refusal(code)
    value, code = _loads(text)
    if code:
        return _refusal(code)
    body, code = _document(value)
    if code:
        return _refusal(code)
    host_name = body["host"]
    if host_name not in table:
        return _refusal("unknown_host")
    return _finish(_resolved(
        body["entry"], table[host_name], body["mcp_tools"], body["prohibited_call_tools"],
        body["file_tools"], vocab))

def _resolve(entry, host_capabilities, mcp_tools, prohibited_call_tools=None, file_tools=None,
             vocabulary=None):
    vocab, code = _vocabulary(vocabulary)
    if code:
        return _refusal(code)
    return _finish(_resolved(
        _freeze(entry), _freeze(host_capabilities), _freeze(mcp_tools),
        _freeze(prohibited_call_tools), _freeze(file_tools), vocab))

def _compare(resolved, served_normalized, prohibited_call_tools=None, vocabulary=None):
    vocab, code = _vocabulary(vocabulary)
    if code:
        return _refusal(code)
    return _finish(_compared(
        _freeze(resolved), _freeze(served_normalized), _freeze(prohibited_call_tools), vocab))

def _probe(entry, resolved, vocabulary=None, **kwargs):
    vocab, code = _vocabulary(vocabulary)
    if code:
        return _refusal(code)
    frozen = {key: _freeze(value) for key, value in kwargs.items()}
    return _finish(_planned(_freeze(entry), _freeze(resolved), vocab=vocab, **frozen))

def _verdict(entry, resolved, roots, plan, observations, vocabulary=None, **kwargs):
    vocab, code = _vocabulary(vocabulary)
    if code:
        return _refusal(code)
    frozen = {key: _freeze(value) for key, value in kwargs.items()}
    return _finish(_judged(
        _freeze(entry), _freeze(resolved), _freeze(roots), _freeze(plan), _freeze(observations),
        vocab=vocab, **frozen))

capability_report = _guard(_capability_report)
resolved_capabilities = _guard(_resolve)
compare = _guard(_compare)
probe_plan = _guard(_probe)
probe_verdict = _guard(_verdict)
