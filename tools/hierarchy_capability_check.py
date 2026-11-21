"""Pure, offline capability analysis, without host selection or qualification.

Provision/adapters must supply the host mapping, the role-selected MCP surface, and
prohibited_call_tools (registry call -> normalized capabilities implementing it).
No production caller supplies that last mapping yet; wiring and its authoritative
producer are later work. This module invents no action-to-tool relation.

Vocabulary: read, write-scope, shell, subagent, mcp:<tool>. MCP names should include
the server, e.g. mcp:server/tool, to preserve server identity. Adapters normalize
native catalogs BEFORE compare; comparison never folds case, strips whitespace,
or matches prefixes. Host mapping file_tools maps the registry's file tool names
to read/write-scope; its reader_shell, writer_shell and session_helpers are bools.
Session helpers mean subagent, and reviewer sessions always exclude them.

All public functions return status/code data on refusal, never input diagnostics.
Resolution codes: invalid_role, invalid_host_mapping, invalid_mcp_tools, invalid_file_tools,
invalid_prohibited_call_tools, uncovered_prohibited_calls, prohibited_capability.
Comparison additionally uses invalid_resolution, invalid_catalog, incomplete_catalog.
Probe codes: invalid_probe_plan, invalid_observations, incomplete_observations,
inconclusive_observations; an allowed observation fails even with missing attempts.
Plans require a complete resolution matching the trusted registry entry and
provisioning inputs; prohibited calls must be absent from it. Verdicts revalidate
through the same planner with those inputs and trusted roots. Observations repeat
the planned id, operation, capability and path along with their outcome. Edit uses an
independent existing canary supplied by the caller. Paths are lexical descriptions
only; nothing here opens them or proves canary existence. Ambiguous/non-normalized
paths, including UNC and double-leading-slash spellings, are refused.
Offline match/pass does not establish native enforcement or activation (D8).
"""
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hierarchy_roles as roles  # noqa: E402


MAX_ITEMS = 256
MAX_NAME = 256
MAX_MAP_VALUES = 1024
MAX_PATH = 4096
MAX_ROOTS = 16
_BASE_IDS = ("prohibited-tool", "outside-write", "outside-edit", "outside-read", "prohibited-mcp")
_RESOLUTION_CODES = {"invalid_role", "invalid_host_mapping", "invalid_mcp_tools",
                     "invalid_file_tools", "invalid_prohibited_call_tools", "uncovered_prohibited_calls",
                     "prohibited_capability"}


def _name(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_NAME and value.isascii()
            and all(32 <= ord(char) < 127 for char in value))


def _capability(value):
    if not _name(value):
        return False
    return value in {"read", "write-scope", "shell", "subagent"} or (
        value.startswith("mcp:") and len(value) > 4
        and all(char.isalnum() or char in "_./:-" for char in value[4:]))


def _catalog_name(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_NAME and value.isascii()
            and all(32 <= ord(char) < 127 or char in "\t\r\n\v\f" for char in value))


def _names(value, *, empty=False, sequence=False, capabilities=False, catalog=False):
    kind = isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)) if sequence else isinstance(value, list)
    if not kind or not (0 if empty else 1) <= len(value) <= MAX_ITEMS:
        return None
    # Bounds precede traversal, string inspection, set allocation and sorting.
    valid = _capability if capabilities else (_catalog_name if catalog else _name)
    if not all(valid(item) for item in value):
        return None
    names = set(value)
    return names if len(names) == len(value) else None


def _role(entry):
    if not isinstance(entry, Mapping) or len(entry) > 32:
        return None
    reads = _names(entry.get("reads"), empty=True)
    writes = _names(entry.get("writes"), empty=True)
    denied, provision, endpoint = entry.get("prohibitions"), entry.get("provision"), entry.get("endpoint")
    if reads is None or writes is None or not reads <= roles.VOCABULARY["reads"] or not writes <= roles.VOCABULARY["writes"]:
        return None
    if not isinstance(denied, Mapping) or len(denied) > 4:
        return None
    calls = _names(denied.get("calls"), empty=True)
    if calls is None or not calls <= roles.VOCABULARY["calls"]:
        return None
    for group, permitted in (("reads", reads), ("writes", writes)):
        prohibited = _names(denied.get(group), empty=True)
        if prohibited is None or not prohibited <= roles.VOCABULARY[group] or prohibited & permitted:
            return None
    if (not isinstance(provision, Mapping) or len(provision) > 8
            or type(provision.get("reader_shell")) is not bool
            or "assistants" not in provision
            or (provision["assistants"] is not None and (not _name(provision["assistants"])
                                                        or provision["assistants"] not in roles.ASSISTANTS))):
        return None
    if provision["reader_shell"] and ("source" not in reads or "source" in writes):
        return None
    if (not isinstance(endpoint, Mapping) or len(endpoint) > 2
            or not _name(endpoint.get("role")) or endpoint["role"] not in roles.ENDPOINT_ROLES):
        return None
    if endpoint["role"] == "lane" and (not _name(endpoint.get("lane_kind")) or endpoint["lane_kind"] not in roles.LANE_KINDS):
        return None
    return {"file_tools": roles.file_tools(entry), "writer": "source" in writes,
            "reader_shell": provision["reader_shell"], "helpers": provision["assistants"] is not None,
            "reviewer": endpoint.get("lane_kind") == "reviewer", "calls": sorted(calls)}


def _host(mapping):
    if not isinstance(mapping, Mapping) or len(mapping) != 4:
        return None
    if any(type(mapping.get(key)) is not bool for key in ("reader_shell", "writer_shell", "session_helpers")):
        return None
    files = mapping.get("file_tools")
    required = roles.READ_TOOLS + roles.WRITE_TOOLS
    if not isinstance(files, Mapping) or len(files) != len(required):
        return None
    for name in required:
        if files.get(name) != ("read" if name in roles.READ_TOOLS else "write-scope"):
            return None
    return mapping


def _call_mapping(mapping, calls):
    if not isinstance(mapping, Mapping) or len(mapping) > MAX_ITEMS:
        return None, list(calls), "invalid_prohibited_call_tools"
    total = 0
    # Validate aggregate sizes before copying or traversing mapped tool lists.
    for key, values in mapping.items():
        if (not _name(key) or key not in roles.VOCABULARY["calls"] or not isinstance(values, Sequence)
                or isinstance(values, (str, bytes, bytearray)) or not 0 < len(values) <= MAX_ITEMS):
            return None, list(calls), "invalid_prohibited_call_tools"
        total += len(values)
        if total > MAX_MAP_VALUES:
            return None, list(calls), "invalid_prohibited_call_tools"
    normalized = {}
    for key, values in mapping.items():
        tools = _names(values, sequence=True, capabilities=True)
        if tools is None:
            return None, list(calls), "invalid_prohibited_call_tools"
        normalized[key] = tools
    uncovered = sorted(set(calls) - normalized.keys())
    return normalized, uncovered, "uncovered_prohibited_calls" if uncovered else None


def _unresolved(code, calls=(), uncovered=()):
    return {"status": "unknown", "code": code, "capabilities": [], "file_tools": [],
            "prohibited_calls": list(calls), "uncovered_calls": list(uncovered)}


def resolved_capabilities(entry, host_capabilities, mcp_tools, prohibited_call_tools=None, *, file_tools=None):
    """Resolve a supplied registry entry, host mechanism mapping and provisioned MCP list.

    MCP names are normalized, exact, and role-selected by the caller. An incomplete
    or malformed prohibited-call mapping never yields a resolved capability set.
    file_tools may narrow the role's file tools to the provisioned list. A writer
    shell retains read/write-scope access independently of native file-tool narrowing.
    """
    role = _role(entry)
    if role is None:
        return _unresolved("invalid_role")
    calls = role["calls"]
    selected = role["file_tools"] if file_tools is None else file_tools
    names = _names(selected, empty=True)
    if names is None or not names <= set(role["file_tools"]):
        return _unresolved("invalid_file_tools", calls)
    mapping, uncovered, code = _call_mapping(prohibited_call_tools, calls)
    if code:
        return _unresolved(code, calls, uncovered)
    host = _host(host_capabilities)
    if host is None:
        return _unresolved("invalid_host_mapping", calls)
    capabilities = {host["file_tools"][name] for name in selected}
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
            "file_tools": list(selected), "prohibited_calls": calls, "uncovered_calls": []}


def _comparison(status, code, *, extras=(), missing=(), uncovered=()):
    return {"status": status, "code": code, "extras": sorted(extras),
            "missing": sorted(missing), "uncovered_calls": list(uncovered)}


def compare(resolved, served_normalized, prohibited_call_tools=None):
    """Compare exact names and independently recheck prohibited-call coverage.

    A subset is unknown, an extra item exceeds, and an invalid/empty catalog is
    unknown. Bounded ASCII extras (including whitespace variants) are evidence;
    malformed input is not echoed in diagnostics.
    """
    if not isinstance(resolved, Mapping) or len(resolved) > 8:
        return _comparison("unknown", "invalid_resolution")
    calls = _names(resolved.get("prohibited_calls"), empty=True)
    if calls is None or not calls <= roles.VOCABULARY["calls"]:
        return _comparison("unknown", "invalid_resolution")
    mapping, uncovered, code = _call_mapping(prohibited_call_tools, sorted(calls))
    if code:
        return _comparison("unknown", code, uncovered=uncovered)
    if resolved.get("status") == "unknown":
        code = resolved.get("code")
        return _comparison("unknown", code if _name(code) and code in _RESOLUTION_CODES else "invalid_resolution")
    expected = _names(resolved.get("capabilities"), capabilities=True)
    if resolved.get("status") != "resolved" or expected is None:
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
    if not isinstance(value, str) or not 0 < len(value) <= MAX_PATH or not value.isascii():
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
    if not isinstance(values, list) or len(values) > MAX_ROOTS:
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


def probe_plan(entry, resolved, *, host_capabilities, mcp_tools, prohibited_tool, prohibited_mcp, write_roots,
               outside_path, edit_path, canary_path, sibling_path=None, prohibited_call_tools=None, file_tools=None):
    """Re-resolve trusted provisioning inputs before planning caller-prepared canaries.

    The caller supplies the actual host, selected MCP and optional file-tool
    settings independently of the submitted resolution, plan and observations.
    """
    role, roots = _role(entry), _roots(write_roots)
    if role is None or roots is None or not isinstance(resolved, Mapping) or len(resolved) != 6:
        return _no_plan()
    if set(resolved) != {"status", "code", "capabilities", "file_tools", "prohibited_calls", "uncovered_calls"}:
        return _no_plan()
    granted = _names(resolved.get("capabilities"), empty=True, capabilities=True)
    calls = _names(resolved.get("prohibited_calls"), empty=True)
    selected = _names(resolved.get("file_tools"), empty=True)
    uncovered = resolved.get("uncovered_calls")
    if (resolved.get("status") != "resolved" or resolved.get("code") != "resolved"
            or granted is None or calls != set(role["calls"]) or selected is None
            or not isinstance(uncovered, list) or len(uncovered) != 0
            or not _capability(prohibited_tool) or not _capability(prohibited_mcp)
            or prohibited_tool in granted or prohibited_mcp in granted):
        return _no_plan()
    expected = resolved_capabilities(entry, host_capabilities, mcp_tools, prohibited_call_tools, file_tools=file_tools)
    if expected["status"] != "resolved" or resolved != expected:
        return _no_plan()
    attempts = _attempts(role, roots, prohibited_tool, prohibited_mcp, outside_path, edit_path, canary_path, sibling_path)
    return _no_plan() if attempts is None else {"status": "planned", "code": "planned", "attempts": attempts}


def _checked_plan(entry, resolved, roots, plan, *, host_capabilities, mcp_tools, prohibited_call_tools, file_tools):
    role = _role(entry)
    if (role is None or not isinstance(plan, Mapping) or len(plan) != 3
            or plan.get("status") != "planned" or plan.get("code") != "planned"):
        return None
    attempts = plan.get("attempts")
    if not isinstance(attempts, list) or len(attempts) != (6 if role["writer"] else 5):
        return None
    required = _BASE_IDS + (("sibling-write",) if role["writer"] else ())
    for name, attempt in zip(required, attempts):
        if not isinstance(attempt, Mapping) or len(attempt) != 4 or not _name(attempt.get("id")):
            return None
        if attempt["id"] != name or not _capability(attempt.get("capability")):
            return None
        if not _name(attempt.get("operation")) or (attempt.get("path") is not None and _path(attempt["path"]) is None):
            return None
    # Reuse all planning checks, including resolution binding and grant exclusion.
    regenerated = probe_plan(entry, resolved, write_roots=roots,
                             host_capabilities=host_capabilities, mcp_tools=mcp_tools,
                             prohibited_call_tools=prohibited_call_tools, file_tools=file_tools,
                             prohibited_tool=attempts[0]["capability"], prohibited_mcp=attempts[4]["capability"],
                             outside_path=attempts[1].get("path"), edit_path=attempts[2].get("path"),
                             canary_path=attempts[3].get("path"),
                             sibling_path=attempts[5].get("path") if role["writer"] else None)
    if regenerated["status"] != "planned" or regenerated["attempts"] != attempts:
        return None
    return {attempt["id"]: attempt for attempt in regenerated["attempts"]}


def probe_verdict(entry, resolved, roots, plan, observations, *, host_capabilities, mcp_tools,
                  prohibited_call_tools=None, file_tools=None):
    """Revalidate through probe_plan using trusted role, provisioning and root data."""
    expected = _checked_plan(entry, resolved, roots, plan, host_capabilities=host_capabilities,
                             mcp_tools=mcp_tools, prohibited_call_tools=prohibited_call_tools, file_tools=file_tools)
    if expected is None:
        return {"status": "unknown", "code": "invalid_probe_plan"}
    if not isinstance(observations, list) or len(observations) > len(expected):
        return {"status": "unknown", "code": "invalid_observations"}
    seen, outcomes = set(), set()
    for observation in observations:
        if not isinstance(observation, Mapping) or len(observation) != 5:
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
