"""Bounded Codex rollout observations, never authenticated execution authority.

Paths are diagnostic input. The selected parent is anchored through the mailbox
Store's public no-follow walk; an opened stream remains tied to its descriptor.
The installed role registry supplies policy only. No tools module is imported,
and even an injected qualification gate cannot enable execution in this observer.
Wire data and witnesses remain unrendered data; diagnostic reasons use the shared
canonicalize/redact/clip pipeline. Structural JSON bounds are the recorded TA-3f
round-1b parity exceptions. Byte ceilings retain the legacy values.
"""
from functools import wraps
import errno
import hashlib
from inspect import signature
import json
import os
from pathlib import Path
import shlex
import stat

from aegis_core.diagnostic_messages import guidance_value
from aegis_core.team_mailbox_primitives import (
    MailboxRefusal, bounded_tree, require, render_mailbox_refusal, safe_path, strict_json,
)
from aegis_core.team_mailbox_store import Store, descriptor_supported
from aegis_core import team_roles

__all__ = [
    "NativeRolloutRefusal", "MAX_ROLLOUT_BYTES", "MAX_RECORD_BYTES", "NATIVE_GAP",
    "EXEC_SCHEMA", "MULTI_AGENT_SCHEMA", "AGENT_NAMESPACE", "AGENT_TOOL_NAMES",
    "PATCH_CALLS", "PATCH_HEADERS", "UNCONFIRMED_SHAPE", "codex_roles", "rollout_records",
    "witness_of", "event_type", "turn_start", "inspect_codex", "observed_permissions",
    "restricted_profile", "bounded_write_path", "check_profile", "assess_role",
    "text_or_absent", "command_execution", "patch_apply", "patch_input", "patch_paths",
    "patch_output", "response_patch",
]

MAX_ROLLOUT_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
NATIVE_GAP = "authenticated native identity and tool capabilities are unavailable"
EXEC_SCHEMA = "aegis.native-exec-events/v1"
MULTI_AGENT_SCHEMA = "aegis.native-multi-agent/v1"
AGENT_NAMESPACE = "collaboration"
AGENT_TOOL_NAMES = ("followup_task", "interrupt_agent", "list_agents", "send_message", "spawn_agent", "wait_agent")
PATCH_CALLS = {"custom_tool_call": "custom_tool_call_output", "function_call": "function_call_output"}
PATCH_HEADERS = ("*** Add File: ", "*** Update File: ")
UNCONFIRMED_SHAPE = "unconfirmed against a real host"

_NEXT = {
    "invalid_record": "Restore complete native records with recognized bounded shapes, then retry.",
    "too_large": "Reduce the rollout or record to the documented observation byte ceilings, then retry.",
    "incomplete_record": "Wait for the final record to finish or explicitly request a tolerant observation.",
    "unsafe_path": "Select a regular, singly linked rollout under a private no-follow directory, then retry.",
    "missing": "Restore the requested rollout from trusted evidence, then retry.",
    "io": "Check rollout readability and retry from complete current evidence.",
    "unsupported_platform": "Use a platform supporting descriptor-relative no-follow observation.",
    "unqualified": "Keep execution disabled until an owner-approved native authority design is implemented.",
}


class NativeRolloutRefusal(ValueError):
    """Fixed refusal data; untrusted record and path text never enter diagnostics."""
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in _NEXT else "invalid_record"
        self.state, self.status, self.code = "NATIVE_HOLD", "refused", 2
        self.next_action = _NEXT[self.reason]
        super().__init__("native rollout refused: " + self.reason)

    def as_dict(self):
        return {"state": self.state, "status": self.status, "code": self.code,
                "reason": self.reason, "next_action": self.next_action}


def _boundary(function):
    """Check call shape explicitly, rather than introducing a TypeError handler."""
    parameters = signature(function).parameters
    names = frozenset(parameters)
    positional = tuple(name for name, parameter in parameters.items()
                       if parameter.kind == parameter.POSITIONAL_OR_KEYWORD)
    required = frozenset(name for name, parameter in parameters.items()
                         if parameter.default is parameter.empty)
    @wraps(function)
    def call(*args, **kwargs):
        try:
            require(len(args) <= len(positional) and kwargs.keys() <= names)
            provided = frozenset(positional[:len(args)])
            require(not provided & kwargs.keys() and required <= provided | kwargs.keys())
            return function(*args, **kwargs)
        except NativeRolloutRefusal:
            raise
        except MailboxRefusal as error:
            reason = render_mailbox_refusal(error)["reason"]
            raise NativeRolloutRefusal(reason) from None
        except FileNotFoundError:
            raise NativeRolloutRefusal("missing") from None
        except OSError as error:
            raise NativeRolloutRefusal(_io_reason(error)) from None
        except (ValueError, KeyError, IndexError, AttributeError, RecursionError, OverflowError):
            raise NativeRolloutRefusal("invalid_record") from None
    return call


def _mapping(value):
    require(type(value) is dict)
    bounded_tree(value, limit=MAX_RECORD_BYTES, source_bytes=True)
    return value


def _shown(value):
    require(type(value) is str)
    return guidance_value(value, limit=160)


def _shown_tier(value):
    if value is None:
        return "None"
    return _shown(value) if type(value) is str else "<non-string tier>"


def _io_reason(error):
    return {errno.ELOOP: "unsafe_path", errno.ENOTDIR: "unsafe_path"}.get(error.errno, "io")


def _rollout_json(raw):
    return strict_json(raw, limit=MAX_RECORD_BYTES, max_atom=MAX_RECORD_BYTES, source_bytes=True)


def _embedded_json(raw):
    """Distinguish plain legacy text from JSON refused by a structural bound.

    The shared parser preflights the raw byte limit first. The refusal probe
    checks legacy syntax, duplicate keys and constants, discarding numeric and
    object values; it never returns an unchecked tree as parsed evidence.
    Decoder recursion exhaustion keeps the original bounded refusal instead of
    the legacy-text sentinel.
    """
    try:
        return True, _rollout_json(raw)
    except MailboxRefusal as error:
        render_mailbox_refusal(error)
        require(type(raw) is str and len(raw) <= MAX_RECORD_BYTES, reason="too_large")
        def pairs(items):
            seen = set()
            for key, _value in items:
                if key in seen:
                    raise ValueError("duplicate JSON key")
                seen.add(key)
            return None
        def nonfinite(_value):
            raise ValueError("non-finite JSON constant")
        try:
            json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite,
                       parse_int=lambda _value: None, parse_float=lambda _value: None)
        except RecursionError:
            raise error from None
        except (ValueError, OverflowError):
            return False, None
        raise


@_boundary
def codex_roles():
    """Session endpoint roles, plus the legacy diagnostic operator role."""
    return tuple(sorted(set(team_roles.session_roles()) | {"operator"}))


@_boundary
def rollout_records(rollout, tolerant=False):
    """Yield (path, line number, raw bytes, record) from a held bounded stream.

    The final unterminated line is ignored only in tolerant mode. Limits apply
    before parsing, including if a producer appends while observation is running.
    Closing this generator releases the stream, leaf and Store descriptors.
    """
    try:
        if not descriptor_supported():
            raise NativeRolloutRefusal("unsupported_platform")
        require(type(tolerant) is bool)
        path = safe_path(rollout)
        with Store.from_parent(path.parent) as store, store.directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, reason="unsafe_path")
                require(info.st_size <= MAX_ROLLOUT_BYTES, reason="too_large")
                # The leaf has exactly one closer, even when fdopen raises.
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    yield from _stream_records(path, stream, tolerant)
            finally:
                os.close(fd)
    except NativeRolloutRefusal:
        raise
    except MailboxRefusal as error:
        raise NativeRolloutRefusal(render_mailbox_refusal(error)["reason"]) from None
    except FileNotFoundError:
        raise NativeRolloutRefusal("missing") from None
    except OSError as error:
        raise NativeRolloutRefusal(_io_reason(error)) from None
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise NativeRolloutRefusal("invalid_record") from None


def _stream_records(path, stream, tolerant):
    total, number = 0, 0
    while True:
        raw = stream.readline(min(MAX_RECORD_BYTES, MAX_ROLLOUT_BYTES - total) + 1)
        if not raw:
            break
        number += 1
        total += len(raw)
        require(total <= MAX_ROLLOUT_BYTES and len(raw) <= MAX_RECORD_BYTES, reason="too_large")
        if not raw.endswith(b"\n") and tolerant:
            break
        if not raw.endswith(b"\n"):
            raise NativeRolloutRefusal("incomplete_record")
        record = _rollout_json(raw)
        require(type(record) is dict)
        yield path, number, raw, record


@_boundary
def witness_of(path, number, raw, record):
    require(type(path) is str or isinstance(path, Path))
    require(type(number) is int and number > 0 and type(raw) is bytes)
    require(len(raw) <= MAX_RECORD_BYTES, reason="too_large")
    require(type(record) is dict)
    return {"path": str(path), "line": number, "sha256": hashlib.sha256(raw).hexdigest(),
            "timestamp": record.get("timestamp")}


@_boundary
def event_type(record):
    require(type(record) is dict)
    payload = record.get("payload")
    if record.get("type") == "event_msg" and isinstance(payload, dict):
        kind = payload.get("type")
        return kind if type(kind) is str and kind else None
    return None


@_boundary
def turn_start(payload):
    require(type(payload) is dict)
    turn = payload.get("turn_id")
    require(type(turn) is str and bool(turn.strip()))
    return turn


@_boundary
def inspect_codex(rollout, cid, requested_tier="default", tolerant=False, *, qualification_gate=None):
    """Read actual contexts and turn-scoped settings; qualification stays false.

    Settings before a turn are pending. A second unnamed settings record within
    a turn is pending for its successor. Every start clears preceding contexts.
    The optional gate is an injected downstream seam, never execution authority.
    """
    require(type(cid) is str and bool(cid) and len(cid) <= MAX_RECORD_BYTES)
    bounded_tree(requested_tier, limit=MAX_RECORD_BYTES, source_bytes=True)
    require(qualification_gate is None or callable(qualification_gate))
    metadata, context = None, None
    started_turn, running = None, False
    applied, pending = None, None
    witnesses = {}
    for path, number, raw, record in rollout_records(rollout, tolerant):
        kind, payload = record.get("type"), record.get("payload")
        require(type(kind) not in (list, dict))
        event = event_type(record)
        if event == "task_started":
            started_turn, running = turn_start(payload), True
            context = None
            witnesses.pop("turn_record", None)
            applied = None
            if pending is not None and pending[0].get("turn_id") in (None, started_turn):
                applied = pending
            pending = None
            continue
        if event in ("task_complete", "turn_aborted"):
            running = False
            continue
        if event == "thread_settings_applied":
            values = payload.get("thread_settings")
            require(type(values) is dict)
            entry = ({"turn_id": payload.get("turn_id"), "values": values}, witness_of(path, number, raw, record))
            named = payload.get("turn_id")
            if running and (named == started_turn or (named is None and applied is None)):
                applied = entry
            else:
                pending = entry
            continue
        if kind not in ("session_meta", "turn_context"):
            continue
        require(type(payload) is dict)
        witness = witness_of(path, number, raw, record)
        if kind == "session_meta":
            require(payload.get("id") == cid)
            metadata, witnesses["session_record"] = payload, witness
        else:
            context, witnesses["turn_record"] = payload, witness
    if started_turn is None and pending is not None:
        applied = pending
    require(metadata is not None)
    if started_turn is not None:
        require(context is not None and context.get("turn_id") == started_turn)
    require(context is not None)
    profile = {key: context.get(key) for key in ("model", "effort", "cwd", "approval_policy",
                                                "approvals_reviewer", "sandbox_policy", "permission_profile")}
    served, source, settings = None, None, None
    if applied is not None and applied[0]["values"].get("service_tier") is not None:
        settings = applied[0]["values"]
        served, source = settings.get("service_tier"), "thread_settings_applied"
        witnesses["settings_record"] = applied[1]
    elif context.get("service_tier") is not None:
        served, source = context.get("service_tier"), "turn_context"
    elif applied is not None:
        settings = applied[0]["values"]
        witnesses["settings_record"] = applied[1]
    applied_settings = None if settings is None else {
        key: settings.get(key) for key in ("model", "service_tier", "approval_policy", "approvals_reviewer")}
    return {"schema": "aegis.native-observation/v1", "cid": cid,
            "host": "codex-cli" if metadata.get("source") == "exec" else "codex",
            "recorded_source": metadata.get("source"), "profile": profile,
            "observed_permissions": observed_permissions(profile),
            "requested_tier": requested_tier, "served_tier": served, "served_tier_source": source,
            "applied_settings": applied_settings, "environment_cid_matches": os.environ.get("CODEX_THREAD_ID") == cid,
            "identity_authenticated": False, "tool_allowlist_verified": False,
            "native_execution_qualified": False, "qualification_blocker": NATIVE_GAP, **witnesses}


@_boundary
def observed_permissions(profile):
    """Return recorded filesystem entries as data; no authority is inferred."""
    permission = _mapping(profile).get("permission_profile")
    unsupported = {"supported": False, "network": None, "entries": []}
    if not isinstance(permission, dict) or permission.get("type") != "managed":
        return {**unsupported, "reasons": ["permission profile is not a managed restricted profile"]}
    filesystem = permission.get("file_system")
    if not isinstance(filesystem, dict) or filesystem.get("type") != "restricted":
        return {**unsupported, "reasons": ["permission profile is not a managed restricted profile"]}
    raw_entries = filesystem.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        return {**unsupported, "reasons": ["permission profile has no filesystem entries"]}
    entries = []
    for index, entry in enumerate(raw_entries, 1):
        if isinstance(entry, dict) and isinstance(entry.get("path"), dict):
            require(type(entry["path"].get("type")) not in (list, dict))
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), dict) \
                or entry["path"].get("type") not in ("path", "special"):
            return {**unsupported, "reasons": ["unsupported path at entry %d" % index]}
        require(type(entry.get("access")) not in (list, dict))
        if entry.get("access") not in ("read", "write"):
            return {**unsupported, "reasons": ["unsupported access at entry %d" % index]}
        behavior = entry.get("missing_path_behavior", entry["path"].get("missing_path_behavior"))
        if behavior is not None and not isinstance(behavior, str):
            return {**unsupported, "reasons": ["unsupported missing_path_behavior at entry %d" % index]}
        target = entry["path"]
        if target["type"] == "path":
            value = target.get("path")
            if not isinstance(value, str) or not value:
                return {**unsupported, "reasons": ["unsupported path at entry %d" % index]}
        else:
            special = target.get("value")
            if not isinstance(special, dict) or not isinstance(special.get("kind"), str) or not special["kind"]:
                return {**unsupported, "reasons": ["unsupported special path at entry %d" % index]}
            value = special["kind"]
        record = {"kind": target["type"], "path_or_special": value, "access": entry["access"],
                  "missing_path_behavior": behavior}
        if target["type"] == "special" and len(special) > 1:
            record["special_fields"] = {key: item for key, item in special.items() if key != "kind"}
        entries.append(record)
    return {"supported": True, "network": permission.get("network"), "entries": entries, "reasons": []}


@_boundary
def restricted_profile(profile):
    observed = observed_permissions(profile)
    if not observed["supported"] or observed["network"] != "restricted":
        return None
    return observed["entries"]


@_boundary
def bounded_write_path(value):
    require(type(value) is str)
    require(len(value) <= MAX_RECORD_BYTES, reason="too_large")
    path = Path(value)
    return path.is_absolute() and str(path) == value and ".." not in path.parts and path.parent != path


@_boundary
def check_profile(observation, model, effort, cwd, *, write_roots=(), allow_tmpdir=False,
                  allow_special_writes=(), approval_policy="on-request", approvals_reviewer="auto_review"):
    """Compare requested policy; a matching maintenance profile never qualifies execution."""
    require(type(observation) is dict)
    require(type(allow_special_writes) in (tuple, list, set, frozenset))
    require(len(allow_special_writes) <= 10000, reason="too_large")
    require(all(type(name) is str and bool(name) for name in allow_special_writes))
    specials = set(allow_special_writes) | ({"tmpdir"} if allow_tmpdir else set())
    require("root" not in specials)
    profile = _mapping(observation["profile"])
    reasons, checks = [], {}
    for name, actual, expected, reason in (("model", profile["model"], model, "model mismatch"),
                                           ("effort", profile["effort"], effort, "reasoning effort mismatch"),
                                           ("cwd", profile["cwd"], cwd, "working directory mismatch")):
        if expected is None:
            checks[name] = "unchecked"
            reasons.append("%s unchecked: no value was requested" % name)
        elif actual != expected:
            checks[name] = "mismatch"
            reasons.append(reason)
        else:
            checks[name] = "checked"
    served, requested = observation.get("served_tier"), observation.get("requested_tier")
    if served is not None and served != requested:
        reasons.append("served tier mismatch: requested %s, served %s" %
                       (_shown_tier(requested), _shown_tier(served)))
    elif served is None and requested not in (None, "default"):
        reasons.append("served tier unavailable: requested %s" % _shown_tier(requested))
    if not profile.get("approval_policy"):
        reasons.append("approval policy unavailable")
    elif profile["approval_policy"] != approval_policy:
        reasons.append("approval policy mismatch")
    if approvals_reviewer == "none":
        if profile.get("approvals_reviewer") is not None:
            reasons.append("approval reviewer mismatch")
    elif not profile.get("approvals_reviewer"):
        reasons.append("approval reviewer unavailable")
    elif profile["approvals_reviewer"] != approvals_reviewer:
        reasons.append("approval reviewer mismatch")
    entries = restricted_profile(profile)
    if entries is None:
        reasons.append("effective restricted permission profile unavailable")
    else:
        require(type(write_roots) in (tuple, list) and len(write_roots) <= 10000)
        values = write_roots or (cwd,)
        require(all(type(value) is str or isinstance(value, Path) for value in values))
        require(all(len(str(value)) <= MAX_RECORD_BYTES for value in values), reason="too_large")
        roots = [Path(value) for value in values]
        require(all(value.is_absolute() and ".." not in value.parts and value.parent != value for value in roots))
        for entry in entries:
            if entry["access"] != "write":
                continue
            value = entry["path_or_special"]
            if entry["kind"] == "special":
                if value not in specials:
                    reasons.append("special write access was not requested: " + _shown(value))
            elif not bounded_write_path(value) or not any(
                    Path(value) == root or root in Path(value).parents for root in roots):
                reasons.append("write root is outside requested scope: " + _shown(value))
    result = {"state": "PROFILE_HOLD" if reasons else "PROFILE_MATCH", "reasons": reasons, "checks": checks,
              "native_execution_qualified": False, "observation": observation}
    if reasons:
        result["next_action"] = "Match the requested model, effort, directory, tier and restricted permissions, then retry."
    return result


@_boundary
def assess_role(observation, role, *, qualification_gate=None):
    require(type(role) is str and role in codex_roles())
    require(type(observation) is dict)
    require(qualification_gate is None or callable(qualification_gate))
    profile = _mapping(observation["profile"])
    entries = restricted_profile(profile)
    reasons = []
    if role == "root" and (entries is None or any(entry["access"] == "write" for entry in entries)):
        reasons.append("ROOT requires an effective read-only filesystem")
    entry = team_roles.registry()["roles"].get(role)
    fixed = team_roles.fixed_model_profile(entry) if entry is not None else None
    if fixed is not None and (profile.get("effort") != fixed["effort"] or observation["requested_tier"] != fixed.get("tier")):
        reasons.append("%s requires %s effort and %s configured tier" % (role, fixed["effort"], fixed.get("tier")))
    reasons.append(NATIVE_GAP)
    return {"state": "NATIVE_HOLD", "role": role, "reasons": reasons,
            "next_action": _NEXT["unqualified"], "native_execution_qualified": False, "observation": observation}


@_boundary
def text_or_absent(payload, key):
    require(type(payload) is dict and type(key) is str)
    value = payload.get(key)
    return value is None and key not in payload or isinstance(value, str)


@_boundary
def command_execution(payload, turn, source, witness):
    """One recorded shell execution; this helper never runs its command."""
    payload, witness = _mapping(payload), _mapping(witness)
    command, code = payload.get("command"), payload.get("exit_code")
    valid = (isinstance(command, str) and bool(command)) or (
        isinstance(command, list) and bool(command) and all(isinstance(part, str) for part in command))
    valid = valid and (code is None or (isinstance(code, int) and not isinstance(code, bool)))
    valid = valid and all(text_or_absent(payload, key) for key in ("aggregated_output", "stdout", "stderr", "status"))
    call = payload.get("call_id", payload.get("id"))
    require(valid and (call is None or isinstance(call, str)))
    return {"turn_id": turn, "call_id": call, "command": command,
            "command_text": command if isinstance(command, str) else shlex.join(command),
            "exit_code": code, "aggregated_output": payload.get("aggregated_output"),
            "stdout": payload.get("stdout"), "stderr": payload.get("stderr"), "status": payload.get("status"),
            "source": source, **witness}


@_boundary
def patch_apply(payload, turn, source, witness):
    """A recorded patch attempt; this helper never applies a patch."""
    payload, witness = _mapping(payload), _mapping(witness)
    changes = payload.get("changes")
    if source == "patch_apply_end":
        success = payload.get("success")
        valid = isinstance(success, bool) and isinstance(changes, dict)
        paths = sorted(changes) if isinstance(changes, dict) else []
    else:
        status = payload.get("status")
        require(type(status) is str)
        success = {"completed": True, "failed": False}.get(status)
        if isinstance(changes, dict):
            valid, paths = True, sorted(changes)
        else:
            valid = isinstance(changes, list) and all(
                isinstance(change, dict) and isinstance(change.get("path"), str) for change in changes)
            paths = [change["path"] for change in changes] if valid else []
    valid = valid and all(isinstance(path, str) for path in paths)
    valid = valid and all(text_or_absent(payload, key) for key in ("stdout", "stderr"))
    call = payload.get("call_id", payload.get("id"))
    require(valid and (call is None or isinstance(call, str)))
    return {"turn_id": turn, "call_id": call, "success": success, "paths": paths,
            "stdout": payload.get("stdout"), "stderr": payload.get("stderr"), "source": source,
            "declined": payload.get("status") == "declined", **witness}


@_boundary
def patch_input(payload):
    """Patch text as recorded; a plain non-JSON function argument stays text."""
    payload = _mapping(payload)
    if payload.get("type") == "custom_tool_call":
        value = payload.get("input")
        return value if isinstance(value, str) else None
    arguments = payload.get("arguments")
    if isinstance(arguments, str):
        parsed, value = _embedded_json(arguments)
        if not parsed:
            return arguments
        arguments = value
    if isinstance(arguments, dict):
        for key in ("input", "patch"):
            if isinstance(arguments.get(key), str):
                return arguments[key]
    return None


@_boundary
def patch_paths(text):
    require(type(text) is str)
    require(len(text) <= MAX_RECORD_BYTES, reason="too_large")
    return [line[len(header):].strip() for line in text.splitlines() for header in PATCH_HEADERS
            if line.startswith(header)]


@_boundary
def patch_output(payload):
    """Recorded output text and optional exit code; not an execution receipt."""
    payload = _mapping(payload)
    value, code = payload.get("output"), None
    if isinstance(value, dict):
        value = value.get("content", value.get("output"))
    if isinstance(value, str):
        _parsed, wrapped = _embedded_json(value)
        if isinstance(wrapped, dict) and isinstance(wrapped.get("output"), str):
            metadata = wrapped.get("metadata")
            code = metadata.get("exit_code") if isinstance(metadata, dict) else None
            value = wrapped["output"]
    if not isinstance(code, int) or isinstance(code, bool):
        code = None
    return (value if isinstance(value, str) else ""), code


@_boundary
def response_patch(call, output, turn, witness):
    call, witness = _mapping(call), _mapping(witness)
    text, code = patch_output(output) if output is not None else ("", None)
    if output is None:
        success = None
    elif code is not None:
        success = code == 0
    elif text.startswith("Success"):
        success = True
    else:
        success = False
    declined = "declined" in (call.get("status"), None if output is None else output.get("status"))
    return {"turn_id": turn, "call_id": call.get("call_id"), "success": success,
            "paths": patch_paths(patch_input(call) or ""), "stdout": None, "stderr": text,
            "source": call.get("type"), "declined": declined, "shape": UNCONFIRMED_SHAPE, **witness}
