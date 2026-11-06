#!/usr/bin/env python3
"""Observe Codex native records without turning local files into execution authority.

The current supported record format exposes identity/profile provenance, but not
an authenticated caller, effective tool allowlist or decision-only service.
`check` verifies a standalone maintenance profile; `admit` deliberately refuses
workflow admission until those independent native boundaries are implemented.
No command writes configuration, binds a session or launches an actor.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shlex
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import encoded, read_json, require, safe_path, strict_json  # noqa: E402


MAX_ROLLOUT_BYTES = 128 * 1024 * 1024
MAX_RECORD_BYTES = 16 * 1024 * 1024
REGISTRY = Path(__file__).resolve().parent / "hierarchy_templates" / "role-registry.json"


def codex_roles():
    """Every registry role with a session endpoint can run on Codex. operator stays for older callers: it names
    the journal role the job executor holds, and admission refuses it like every other role."""
    roles = read_json(REGISTRY).get("roles")
    require(isinstance(roles, dict), "role registry has no roles")
    return tuple(sorted({name for name, entry in roles.items()
                         if isinstance(entry, dict) and entry.get("endpoint") is not None} | {"operator"}))


ROLES = codex_roles()
NATIVE_GAP = "authenticated native identity and tool capabilities are unavailable"
EXEC_SCHEMA = "aegis.native-exec-events/v1"


def rollout_records(rollout, tolerant=False):
    """Yield (line number, raw bytes, record) from a bounded, complete, strict-JSON rollout.

    tolerant=True is for a rollout codex may still be writing: an unterminated final line is a record still
    being flushed, so it is left out instead of failing the read. A malformed line before the end still fails.
    """
    path = safe_path(rollout)
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise ValueError("rollout file is unavailable") from exc
    require(stat.S_ISREG(path.stat().st_mode), "rollout must be a regular file")
    require(size <= MAX_ROLLOUT_BYTES, "rollout exceeds observation byte limit")
    total = 0
    with path.open("rb") as stream:
        number = 0
        while True:
            raw = stream.readline(MAX_RECORD_BYTES + 1)
            if not raw:
                break
            number += 1
            total += len(raw)
            require(total <= MAX_ROLLOUT_BYTES, "rollout exceeds observation byte limit")
            require(len(raw) <= MAX_RECORD_BYTES, "rollout record exceeds observation byte limit")
            if not raw.endswith(b"\n") and tolerant:
                break
            require(raw.endswith(b"\n"), "rollout has an incomplete final record")
            try:
                record = strict_json(raw.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ValueError("malformed rollout JSON at line %d" % number) from exc
            require(isinstance(record, dict), "rollout record must be an object")
            yield path, number, raw, record


def witness_of(path, number, raw, record):
    return {"path": str(path), "line": number, "sha256": hashlib.sha256(raw).hexdigest(),
            "timestamp": record.get("timestamp")}


def event_type(record):
    payload = record.get("payload")
    if record.get("type") == "event_msg" and isinstance(payload, dict):
        return payload.get("type")
    return None


def turn_start(payload):
    turn = payload.get("turn_id")
    require(isinstance(turn, str) and bool(turn.strip()), "native turn start has no turn identity")
    return turn


def inspect_codex(rollout, cid, requested_tier="default", tolerant=False):
    """Read the latest actual turn context; quoted prompt settings are ignored.

    An explicit input path is diagnostic data, not a trusted attestation. Even
    matching runtime environment values cannot authenticate a caller: an ordinary
    process can set them. All qualification fields therefore remain false.

    The served tier is only in event_msg/thread_settings_applied. Settings follow the
    turn_context reset rule: each task_started clears them, so a resumed turn never
    reports an earlier turn's tier. Settings applied while no turn runs (before the
    first start or after task_complete or turn_aborted) are pending for the next start;
    settings that name a turn_id apply only to that turn. A turn that was stopped may
    leave no end record, and the resumed process may write its settings before its own
    task_started: so a second unnamed settings record inside one turn, which already has
    its own, is pending for the next start rather than the stopped turn's.
    """
    metadata, context = None, None
    started_turn, running = None, False
    applied, pending = None, None
    witnesses = {}
    for path, number, raw, record in rollout_records(rollout, tolerant):
        kind = record.get("type")
        payload = record.get("payload")
        event = event_type(record)
        if event == "task_started":
            started_turn, running = turn_start(payload), True
            # A resumed turn may be observed before its context is flushed.
            # Never qualify it using a preceding turn's model/permissions.
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
            require(isinstance(values, dict), "thread settings at line %d must be an object" % number)
            entry = ({"turn_id": payload.get("turn_id"), "values": values}, witness_of(path, number, raw, record))
            named = payload.get("turn_id")
            if running and (named == started_turn or (named is None and applied is None)):
                applied = entry
            else:
                pending = entry
            continue
        if kind not in {"session_meta", "turn_context"}:
            continue
        require(isinstance(payload, dict), "native record payload must be an object")
        witness = witness_of(path, number, raw, record)
        if kind == "session_meta":
            require(payload.get("id") == cid, "rollout identity does not match requested CID")
            metadata, witnesses["session_record"] = payload, witness
        else:
            context, witnesses["turn_record"] = payload, witness
    if started_turn is None and pending is not None:
        applied = pending
    require(metadata is not None, "no native session identity in rollout")
    if started_turn is not None:
        require(context is not None and context.get("turn_id") == started_turn,
                "latest started turn has no matching native context")
    require(context is not None, "no native turn context in rollout")
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
    return {"schema": "aegis.native-observation/v1", "cid": cid, "host": "codex-cli" if metadata.get("source") == "exec" else "codex",
            "recorded_source": metadata.get("source"), "profile": profile,
            "observed_permissions": observed_permissions(profile),
            "requested_tier": requested_tier, "served_tier": served, "served_tier_source": source,
            "applied_settings": applied_settings,
            "environment_cid_matches": os.environ.get("CODEX_THREAD_ID") == cid,
            "identity_authenticated": False, "tool_allowlist_verified": False,
            "native_execution_qualified": False, "qualification_blocker": NATIVE_GAP, **witnesses}


def observed_permissions(profile):
    """Report the recorded filesystem entries as data. Interpreting them is check_profile's job."""
    permission = profile.get("permission_profile")
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
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), dict) \
                or entry["path"].get("type") not in {"path", "special"}:
            return {**unsupported, "reasons": ["unsupported path at entry %d" % index]}
        if entry.get("access") not in {"read", "write"}:
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


def restricted_profile(profile):
    """Known filesystem entries of a network-restricted managed profile, or None."""
    observed = observed_permissions(profile)
    if not observed["supported"] or observed["network"] != "restricted":
        return None
    return observed["entries"]


def bounded_write_path(value):
    path = Path(value)
    return path.is_absolute() and str(path) == value and ".." not in path.parts and path.parent != path


def check_profile(observation, model, effort, cwd, *, write_roots=(), allow_tmpdir=False,
                  allow_special_writes=(), approval_policy="on-request", approvals_reviewer="auto_review"):
    """approvals_reviewer "none" expects no reviewer at all, as a provisioned approval_policy=never profile has."""
    specials = set(allow_special_writes) | ({"tmpdir"} if allow_tmpdir else set())
    require(all(isinstance(name, str) and name for name in specials), "special write names must be non-empty")
    require("root" not in specials, "root write access cannot be allowed")
    profile = observation["profile"]
    reasons = []
    checks = {}
    for name, actual, expected, reason in (("model", profile["model"], model, "model mismatch"),
                                           ("effort", profile["effort"], effort, "reasoning effort mismatch"),
                                           ("cwd", profile["cwd"], cwd, "working directory mismatch")):
        if expected is None:
            # Comparing an observed value with itself proves nothing, so an unrequested value holds.
            checks[name] = "unchecked"
            reasons.append("%s unchecked: no value was requested" % name)
        elif actual != expected:
            checks[name] = "mismatch"
            reasons.append(reason)
        else:
            checks[name] = "checked"
    served, requested = observation.get("served_tier"), observation.get("requested_tier")
    if served is not None and served != requested:
        reasons.append("served tier mismatch: requested %s, served %s" % (requested, served))
    elif served is None and requested not in (None, "default"):
        # Unknown telemetry passes only for the default tier; a requested tier must be seen to be served.
        reasons.append("served tier unavailable: requested %s" % requested)
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
        roots = [Path(value) for value in (write_roots or (cwd,))]
        require(all(value.is_absolute() and ".." not in value.parts and value.parent != value for value in roots),
                "expected write roots must be absolute bounded paths")
        for entry in entries:
            if entry["access"] != "write":
                continue
            value = entry["path_or_special"]
            if entry["kind"] == "special":
                if value not in specials:
                    reasons.append("special write access was not requested: " + value)
            elif not bounded_write_path(value) or not any(
                    Path(value) == root or root in Path(value).parents for root in roots):
                reasons.append("write root is outside requested scope: " + value)
    return {"state": "PROFILE_HOLD" if reasons else "PROFILE_MATCH", "reasons": reasons, "checks": checks,
            "native_execution_qualified": False, "observation": observation}


def assess_role(observation, role):
    require(role in ROLES, "unsupported operational role")
    profile = observation["profile"]
    entries = restricted_profile(profile)
    reasons = []
    if role == "root" and (entries is None or any(entry["access"] == "write" for entry in entries)):
        reasons.append("ROOT requires an effective read-only filesystem")
    if role == "router" and (profile.get("effort") != "medium" or observation["requested_tier"] != "ultrafast"):
        reasons.append("router requires medium effort and ultrafast configured tier")
    reasons.append(NATIVE_GAP)
    return {"state": "NATIVE_HOLD", "role": role, "reasons": reasons,
            "native_execution_qualified": False, "observation": observation}


def text_or_absent(payload, key):
    value = payload.get(key)
    return value is None and key not in payload or isinstance(value, str)


def command_execution(payload, turn, source, witness):
    """One shell execution as recorded: exec_command_end (rollout) or a command_execution item."""
    command = payload.get("command")
    code = payload.get("exit_code")
    valid = (isinstance(command, str) and bool(command)) or (
        isinstance(command, list) and bool(command) and all(isinstance(part, str) for part in command))
    valid = valid and (code is None or (isinstance(code, int) and not isinstance(code, bool)))
    valid = valid and all(text_or_absent(payload, key) for key in ("aggregated_output", "stdout", "stderr", "status"))
    call = payload.get("call_id", payload.get("id"))
    require(valid and (call is None or isinstance(call, str)),
            "malformed command execution at line %d" % witness["line"])
    return {"turn_id": turn, "call_id": call, "command": command,
            "command_text": command if isinstance(command, str) else shlex.join(command),
            "exit_code": code, "aggregated_output": payload.get("aggregated_output"),
            "stdout": payload.get("stdout"), "stderr": payload.get("stderr"), "status": payload.get("status"),
            "source": source, **witness}


def patch_apply(payload, turn, source, witness):
    """A patch attempt: patch_apply_end (rollout, changes keyed by path) or a file_change item (list of paths)."""
    changes = payload.get("changes")
    if source == "patch_apply_end":
        success = payload.get("success")
        valid = isinstance(success, bool) and isinstance(changes, dict)
        paths = sorted(changes) if isinstance(changes, dict) else []
    else:
        status = payload.get("status")
        success = {"completed": True, "failed": False}.get(status)
        # A list of {path} items (lane B's reading), or a map keyed by path as patch_apply_end has.
        if isinstance(changes, dict):
            valid = isinstance(status, str)
            paths = sorted(changes)
        else:
            valid = isinstance(status, str) and isinstance(changes, list) and all(
                isinstance(change, dict) and isinstance(change.get("path"), str) for change in changes)
            paths = [change["path"] for change in changes] if valid else []
    valid = valid and all(isinstance(path, str) for path in paths)
    valid = valid and all(text_or_absent(payload, key) for key in ("stdout", "stderr"))
    call = payload.get("call_id", payload.get("id"))
    require(valid and (call is None or isinstance(call, str)), "malformed patch apply at line %d" % witness["line"])
    return {"turn_id": turn, "call_id": call, "success": success, "paths": paths,
            "stdout": payload.get("stdout"), "stderr": payload.get("stderr"), "source": source,
            "declined": payload.get("status") == "declined", **witness}


# The apply_patch tool call as a response_item pair (call, then its output by call_id). The shape follows the
# Responses API; it is unconfirmed against a real host's rollout.
PATCH_CALLS = {"custom_tool_call": "custom_tool_call_output", "function_call": "function_call_output"}
PATCH_HEADERS = ("*** Add File: ", "*** Update File: ")
UNCONFIRMED_SHAPE = "unconfirmed against a real host"


def patch_input(payload):
    """The patch text of an apply_patch call, or None."""
    if payload.get("type") == "custom_tool_call":
        value = payload.get("input")
        return value if isinstance(value, str) else None
    arguments = payload.get("arguments")
    if isinstance(arguments, str):
        try:
            arguments = strict_json(arguments)
        except (ValueError, RecursionError):
            return arguments
    if isinstance(arguments, dict):
        for key in ("input", "patch"):
            if isinstance(arguments.get(key), str):
                return arguments[key]
    return None


def patch_paths(text):
    return [line[len(header):].strip() for line in text.splitlines() for header in PATCH_HEADERS
            if line.startswith(header)]


def patch_output(payload):
    """(text, exit code or None) of an apply_patch output record; the text may wrap {output, metadata}."""
    value, code = payload.get("output"), None
    if isinstance(value, dict):
        value = value.get("content", value.get("output"))
    if isinstance(value, str):
        try:
            wrapped = strict_json(value)
        except (ValueError, RecursionError):
            wrapped = None
        if isinstance(wrapped, dict) and isinstance(wrapped.get("output"), str):
            metadata = wrapped.get("metadata")
            code = metadata.get("exit_code") if isinstance(metadata, dict) else None
            value = wrapped["output"]
    if not isinstance(code, int) or isinstance(code, bool):
        code = None
    return (value if isinstance(value, str) else ""), code


def response_patch(call, output, turn, witness):
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


def exec_events(rollout, cid, scope="current", tolerant=False):
    """Shell executions and patch applications recorded in the rollout, never model text.

    Read shapes: event_msg exec_command_end and patch_apply_end, event_msg item_completed with a
    CommandExecution or FileChange item, item.* stream records with command_execution or file_change items, and
    response_item custom_tool_call / function_call named apply_patch paired with its output by call_id (that last
    shape is unconfirmed against a real host; its entries say so in "shape"). A declined patch is marked declined.

    An event's own turn_id wins; otherwise it belongs to the turn started last before it. With scope "current"
    only the latest started turn is listed, so a new task_started hides every earlier attempt. This is the
    evidence a probe matches; it proves what the host recorded, not why.
    """
    require(scope in {"current", "all"}, "turn scope must be current or all")
    metadata, started_turn = None, None
    executions, patches = [], []
    calls = {}
    for path, number, raw, record in rollout_records(rollout, tolerant):
        kind, payload, event = record.get("type"), record.get("payload"), event_type(record)
        if kind == "response_item" and isinstance(payload, dict):
            call = payload.get("call_id")
            if payload.get("type") in PATCH_CALLS and payload.get("name") == "apply_patch" and isinstance(call, str):
                calls[call] = (payload, started_turn, witness_of(path, number, raw, record))
            elif payload.get("type") in PATCH_CALLS.values() and isinstance(call, str) and call in calls:
                found, turn, opened = calls.pop(call)
                if PATCH_CALLS[found["type"]] == payload["type"]:
                    patches.append(response_patch(found, payload, turn, {
                        **witness_of(path, number, raw, record), "call_line": opened["line"]}))
            continue
        if kind == "session_meta":
            require(isinstance(payload, dict), "native record payload must be an object")
            require(payload.get("id") == cid, "rollout identity does not match requested CID")
            metadata = payload
            continue
        if event == "task_started":
            started_turn = turn_start(payload)
            continue
        witness = witness_of(path, number, raw, record)
        if event in {"exec_command_end", "patch_apply_end"}:
            turn = payload.get("turn_id", started_turn)
            require(turn is None or isinstance(turn, str),
                    "malformed %s at line %d" % ("command execution" if event == "exec_command_end"
                                                 else "patch apply", number))
            if event == "exec_command_end":
                executions.append(command_execution(payload, turn, event, witness))
            else:
                patches.append(patch_apply(payload, turn, event, witness))
        elif event == "item_completed" and isinstance(payload.get("item"), dict) \
                and payload["item"].get("type") in {"CommandExecution", "FileChange"}:
            # The rollout shape (0.166, per lane B; unconfirmed here): the item rides in an event_msg.
            entry = payload["item"]
            turn = payload.get("turn_id", started_turn)
            shell = entry["type"] == "CommandExecution"
            require(turn is None or isinstance(turn, str),
                    "malformed %s at line %d" % ("command execution" if shell else "patch apply", number))
            if shell:
                executions.append(command_execution(entry, turn, event, witness))
            else:
                patches.append(patch_apply(entry, turn, event, witness))
        elif kind in {"item.started", "item.updated", "item.completed"} and isinstance(record.get("item"), dict):
            entry = record["item"]
            if entry.get("type") == "command_execution":
                executions.append(command_execution(entry, started_turn, kind, witness))
            elif entry.get("type") == "file_change":
                patches.append(patch_apply(entry, started_turn, kind, witness))
    for found, turn, opened in calls.values():
        patches.append(response_patch(found, None, turn, opened))
    require(metadata is not None, "no native session identity in rollout")
    if scope == "current" and started_turn is not None:
        executions = [entry for entry in executions if entry["turn_id"] == started_turn]
        patches = [entry for entry in patches if entry["turn_id"] == started_turn]
    return {"schema": EXEC_SCHEMA, "cid": cid, "turn_scope": scope, "current_turn_id": started_turn,
            "command_executions": executions, "patch_applies": patches,
            "native_execution_qualified": False, "qualification_blocker": NATIVE_GAP}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rollout", required=True, help="Absolute path to the native session record")
    parser.add_argument("--cid", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "check", "admit", "events"):
        command = commands.add_parser(name)
        if name == "events":
            command.add_argument("--turn", choices=("current", "all"), default="current",
                                 help="List the latest started turn's attempts, or every turn's")
            continue
        command.add_argument("--requested-tier", default="default")
        if name == "check":
            command.add_argument("--model", required=True)
            command.add_argument("--effort", required=True)
            command.add_argument("--cwd", required=True)
            command.add_argument("--write-root", action="append", default=[],
                                 help="Expected write root; repeat for each root, defaults to the expected cwd")
            command.add_argument("--allow-tmpdir", action="store_true", help="Same as --allow-special-write tmpdir")
            command.add_argument("--allow-special-write", action="append", default=[], metavar="NAME",
                                 help="A special path (tmpdir, slash_tmp) that may be written; repeat for each")
            command.add_argument("--approval-policy", default="on-request")
            command.add_argument("--approvals-reviewer", default="auto_review",
                                 help="Expected reviewer; none expects no reviewer recorded")
        if name == "admit":
            command.add_argument("--role", required=True, choices=ROLES)
    args = parser.parse_args(argv)
    try:
        if args.command == "events":
            print(encoded(exec_events(args.rollout, args.cid, args.turn)).decode())
            return 0
        observation = inspect_codex(args.rollout, args.cid, args.requested_tier)
        if args.command == "check":
            result = check_profile(observation, args.model, args.effort, args.cwd, write_roots=args.write_root,
                                   allow_tmpdir=args.allow_tmpdir,
                                   allow_special_writes=args.allow_special_write, approval_policy=args.approval_policy,
                                   approvals_reviewer=args.approvals_reviewer)
            code = 2 if result["reasons"] else 0
        elif args.command == "admit":
            result, code = assess_role(observation, args.role), 2
        else:
            result, code = observation, 0
    except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
        result, code = {"state": "NATIVE_HOLD", "native_execution_qualified": False, "error": str(exc)}, 2
    print(encoded(result).decode())
    return code


if __name__ == "__main__":
    sys.exit(main())
