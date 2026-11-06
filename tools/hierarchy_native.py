#!/usr/bin/env python3
"""Observe Codex native records without turning local files into execution authority.

The current supported record format exposes identity/profile provenance, but not
an authenticated caller, effective tool allowlist or decision-only service.
`check` verifies a standalone maintenance profile; `admit` deliberately refuses
workflow admission until those independent native boundaries are implemented.
`multi-agent` reports whether the session was offered Codex sub-agent tools.
No command writes configuration, binds a session or launches an actor.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
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
MULTI_AGENT_SCHEMA = "aegis.native-multi-agent/v1"
# What Codex multi-agent v2 offered in additional_tools (codex-cli 0.166.0, every role of the M1 run of 2026-11-06).
AGENT_NAMESPACE = "collaboration"
AGENT_TOOL_NAMES = ("followup_task", "interrupt_agent", "list_agents", "send_message", "spawn_agent", "wait_agent")


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


# Codex code mode, confirmed by native probe run 1: the model sends a custom_tool_call named "exec" whose input is
# a JavaScript cell. The cell calls tools.exec_command({cmd}) and tools.apply_patch("…") and prints each result
# with text(). The custom_tool_call_output with the same call_id is a list of input_text parts: a "Script
# completed" or "Script failed" header, one part per text() call, and after a failure a last "Script error:\n…"
# part. The host adds an item_completed CommandExecution or FileChange for only some of those calls.
CODE_MODE = "code_mode"
CODE_MODE_SHAPE = "confirmed by native probe run 1 (codex-cli 0.166.0)"
CODE_MODE_TOOLS = ("exec_command", "apply_patch")
# exec_command options that change neither the shell nor the sandbox. Any other (shell, workdir, login, an
# escalation request) leaves the record untrusted: the model then chose what ran the command.
CODE_MODE_SAFE_OPTIONS = ("yield_time_ms", "max_output_tokens")
CODE_MODE_ERROR = "Script error:\n"
CODE_MODE_HEADERS = {"Script completed\n": "completed", "Script failed\n": "failed"}
# Every alternative consumes what it starts, an unterminated literal or comment up to its line or the cell's end, so
# a cell full of stray quotes is read in linear time; an unterminated literal never decodes.
JS_TOKEN = re.compile(r'\s+|//[^\n]*|/\*.*?(?:\*/|\Z)|("(?:[^"\\\n]|\\.)*"?)'
                      r'|(\'(?:[^\'\\\n]|\\.)*\'?|`(?:[^`\\]|\\.)*`?)|([A-Za-z_$][\w$]*)|(\d+)|(.)', re.S)


class Unrecognized(Exception):
    """A code-mode cell, or one call in it, that is not one of the shapes whose printed output is known."""


def js_tokens(source):
    """(kind, text) tokens of a cell; whitespace and comments are dropped. A single-quoted or template literal is
    kind "other": only a double-quoted literal is ever decoded."""
    tokens = []
    for match in JS_TOKEN.finditer(source):
        for kind, value in zip(("string", "other", "name", "number", "punct"), match.groups()):
            if value is not None:
                tokens.append((kind, value))
    return tokens


def js_string(token):
    """A double-quoted literal decoded as JSON, so an escape JSON does not share (\\x41, \\') leaves it unparsed."""
    if token[0] != "string":
        raise Unrecognized("not a double-quoted string literal")
    try:
        value = strict_json(token[1])
    except (ValueError, RecursionError) as exc:
        raise Unrecognized("a string literal JSON cannot decode") from exc
    return value


class JsCursor:
    def __init__(self, tokens, at=0):
        self.tokens, self.at = tokens, at

    def done(self):
        return self.at >= len(self.tokens)

    def accept(self, *texts):
        """Consume these exact name or punctuation tokens if they come next; a literal never matches."""
        found = self.tokens[self.at:self.at + len(texts)]
        if len(found) == len(texts) and all(kind in ("name", "punct") and value == text
                                            for (kind, value), text in zip(found, texts)):
            self.at += len(texts)
            return True
        return False

    def need(self, *texts):
        if not self.accept(*texts):
            raise Unrecognized("expected " + " ".join(texts))

    def ahead(self, *texts):
        return not self.done() and self.tokens[self.at][0] == "punct" and self.tokens[self.at][1] in texts

    def take(self, *kinds):
        if self.done() or self.tokens[self.at][0] not in kinds:
            raise Unrecognized("expected a " + " or ".join(kinds))
        self.at += 1
        return self.tokens[self.at - 1]


def js_call(cursor, bound):
    """tools.exec_command({cmd: "…"}) or tools.apply_patch("…") at the cursor, as one call. A cmd naming a loop
    variable in bound gives a list of commands, one per element of its array."""
    cursor.need("tools", ".")
    tool = cursor.take("name")[1]
    if tool not in CODE_MODE_TOOLS:
        raise Unrecognized("not exec_command or apply_patch")
    cursor.need("(")
    if tool == "apply_patch":
        patch = js_string(cursor.take("string"))
        cursor.need(")")
        return {"tool": tool, "patch": patch, "paths": patch_paths(patch)}
    cursor.need("{")
    command, options = None, []
    while not cursor.accept("}"):
        kind, key = cursor.take("name", "string")
        if kind == "string":
            key = js_string((kind, key))
        if kind == "name" and cursor.ahead(",", "}"):
            value = ("name", key)  # the shorthand {cmd}: the variable cmd
        else:
            cursor.need(":")
            value = cursor.take("string", "number", "name")
        if key == "cmd":
            command = js_string(value) if value[0] == "string" else bound.get(value[1])
            if not isinstance(command, (str, list)) or not command:
                raise Unrecognized("cmd is not a string literal")
        elif value[0] == "name" and value[1] not in ("true", "false"):
            raise Unrecognized("an option is not a literal")
        else:
            options.append(key)
        if not cursor.accept(","):
            cursor.need("}")
            break
    cursor.need(")")
    if command is None:
        raise Unrecognized("exec_command has no cmd")
    return {"tool": tool, "command": command, "options": sorted(options)}


def js_print(cursor, bound):
    cursor.need("text", "(", "await")
    call = js_call(cursor, bound)
    cursor.need(")")
    cursor.accept(";")
    return call


def js_statement(cursor, bound):
    """text(await CALL); or try { text(await CALL); } catch (E) { text(String(E)); }; inside a loop over cmd the
    catch may print {cmd, error: String(E)}. Each prints exactly one part, whether the call returns or throws."""
    if not cursor.accept("try", "{"):
        return {**js_print(cursor, bound), "caught": None}
    call = js_print(cursor, bound)
    cursor.need("}", "catch", "(")
    error = cursor.take("name")[1]
    cursor.need(")", "{", "text", "(")
    if cursor.accept("String", "(", error, ")"):
        caught = "string"
    elif "cmd" in bound and cursor.accept("{", "cmd", ",", "error", ":", "String", "(", error, ")"):
        cursor.accept(",")
        cursor.need("}")
        caught = "object"
    else:
        raise Unrecognized("a catch that prints something else")
    cursor.need(")")
    cursor.accept(";")
    cursor.need("}")
    return {**call, "caught": caught}


def js_array(cursor):
    """NAME = ["…", …] after const or let: (NAME, its strings)."""
    name = cursor.take("name")[1]
    cursor.need("=", "[")
    values = []
    while not cursor.accept("]"):
        values.append(js_string(cursor.take("string")))
        if not cursor.accept(","):
            cursor.need("]")
            break
    if not values or not all(isinstance(value, str) for value in values):
        raise Unrecognized("an array that is not strings")
    return name, values


def js_loop(cursor):
    """const VARIABLE of NAME) after for (: (VARIABLE, NAME)."""
    if not (cursor.accept("const") or cursor.accept("let")):
        raise Unrecognized("a loop without const or let")
    variable = cursor.take("name")[1]
    cursor.need("of")
    name = cursor.take("name")[1]
    cursor.need(")")
    return variable, name


def expanded(call):
    if call["tool"] == "exec_command" and isinstance(call["command"], list):
        return [{**call, "command": command} for command in call["command"]]
    return [call]


def js_cell(tokens):
    """The cell's calls in run order, if the whole cell is the statements js_statement reads, string arrays
    (const NAME = ["…", …];) and loops over them (for (const cmd of NAME) STATEMENT)."""
    cursor, arrays, calls = JsCursor(tokens), {}, []
    while not cursor.done():
        if cursor.accept("const") or cursor.accept("let"):
            name, values = js_array(cursor)
            arrays[name] = values
            cursor.accept(";")
        elif cursor.accept("for", "("):
            variable, name = js_loop(cursor)
            if name not in arrays:
                raise Unrecognized("a loop over an unknown array")
            braced = cursor.accept("{")
            call = js_statement(cursor, {variable: arrays[name]})
            if braced:
                cursor.need("}")
            if not isinstance(call.get("command"), list):
                raise Unrecognized("a loop whose call does not use its variable")
            calls += expanded(call)
        else:
            calls.append(js_statement(cursor, {}))
    return calls


def js_scan(tokens):
    """Every exec_command and apply_patch call of a cell js_cell cannot read: (calls, unparsed). Their output cannot
    be tied to them; a call whose argument is not a strict literal is listed in unparsed with the reason."""
    arrays, loops = {}, {}
    for at in range(len(tokens)):
        cursor = JsCursor(tokens, at)
        try:
            if cursor.accept("const") or cursor.accept("let"):
                name, values = js_array(cursor)
                arrays[name] = values
            elif cursor.accept("for", "("):
                variable, name = js_loop(cursor)
                loops[variable] = name
        except Unrecognized:
            continue
    bound = {variable: arrays[name] for variable, name in loops.items() if name in arrays}
    calls, unparsed = [], []
    for at in range(len(tokens) - 3):
        tool = tokens[at + 2][1]
        if tokens[at] != ("name", "tools") or tokens[at + 1] != ("punct", ".") or tool not in CODE_MODE_TOOLS \
                or tokens[at + 3] != ("punct", "("):
            continue
        try:
            calls += expanded({**js_call(JsCursor(tokens, at), bound), "caught": None})
        except Unrecognized as exc:
            unparsed.append({"tool": tool, "reason": str(exc)})
    return calls, unparsed


def code_mode_calls(source):
    """(calls, paired, unparsed) of one cell: paired says each call prints exactly one output part in order."""
    tokens = js_tokens(source)
    try:
        return js_cell(tokens), True, []
    except Unrecognized:
        calls, unparsed = js_scan(tokens)
        return calls, False, unparsed


def code_mode_parts(payload):
    """(header, printed parts, script error or None) of an exec output, or None when it is not that shape (a
    "Script running" cell, a header that disagrees with the error part)."""
    value = payload.get("output")
    if isinstance(value, str):
        texts = [value]
    elif isinstance(value, list) and value and all(
            isinstance(part, dict) and part.get("type") == "input_text" and isinstance(part.get("text"), str)
            for part in value):
        texts = [part["text"] for part in value]
    else:
        return None
    header = next((state for prefix, state in CODE_MODE_HEADERS.items() if texts[0].startswith(prefix)), None)
    body, error = texts[1:], None
    if body and body[-1].startswith(CODE_MODE_ERROR):
        error = body.pop()[len(CODE_MODE_ERROR):]
    if header is None or (header == "failed") != (error is not None):
        return None
    return header, body, error


def json_object(text):
    try:
        value = strict_json(text)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def exec_chunk(text):
    """An exec_command result as code mode prints it: {chunk_id, exit_code or session_id, output, …}, or None."""
    value = json_object(text)
    if value is None or "error" in value or not isinstance(value.get("chunk_id"), str) \
            or not isinstance(value.get("output"), str):
        return None
    code = value.get("exit_code")
    if code is None and "session_id" not in value or code is not None and (
            not isinstance(code, int) or isinstance(code, bool)):
        return None
    return value


def code_mode_results(calls, parts):
    """One result per call, in order: ("result", text), ("error", message) or "not_run" (after a Script error
    ends the cell), or None when the parts cannot be tied one-to-one to the calls."""
    _, body, error = parts
    results, used, thrown = [], 0, False
    for call in calls:
        if used < len(body):
            text, printed = body[used], json_object(body[used])
            used += 1
            if call["caught"] is None:
                results.append(("result", text))
            elif call["tool"] == "exec_command" and exec_chunk(text) is not None:
                results.append(("result", text))
            elif call["tool"] == "apply_patch" and printed is not None:
                results.append(("result", text))
            elif call["caught"] == "string" and printed is None:
                results.append(("error", text))
            elif call["caught"] == "object" and printed is not None and set(printed) == {"cmd", "error"} \
                    and printed["cmd"] == call["command"] and isinstance(printed["error"], str):
                results.append(("error", printed["error"]))
            else:
                return None
        elif error is not None and not thrown and call["caught"] is None:
            results.append(("error", error))
            thrown = True
        elif thrown:
            results.append("not_run")
        else:
            return None
    if used != len(body) or (error is not None and not thrown):
        return None
    return results


def code_mode_entry(call, result, turn, call_id, witness):
    """A command_executions or patch_applies entry for one code-mode call and its result (None: not tied)."""
    entry = {"turn_id": turn, "call_id": call_id, "source": CODE_MODE, "shape": CODE_MODE_SHAPE, "stdout": None,
             "stderr": None, "status": "unpaired"}
    if result is not None and result[0] == "error":
        entry["stderr"] = result[1]
        entry["status"] = ("unavailable" if result[1].strip() == "TypeError: tools.%s is not a function" % call["tool"]
                           else "failed")
    if call["tool"] == "apply_patch":
        entry.update(success=None, paths=call["paths"], declined=False)
        if result is not None and result[0] == "error":
            entry["success"] = False
        elif result is not None and json_object(result[1]) == {}:
            # Run 1 printed {} for a patch that applied (its FileChange item says completed).
            entry.update(success=True, stdout=result[1], status="completed")
        elif result is not None:
            entry.update(stdout=result[1], status="unknown")
        return {**entry, **witness}
    entry.update(command=call["command"], command_text=call["command"], exit_code=None, aggregated_output=None,
                 options=call["options"])
    if result is not None and result[0] == "result":
        chunk = exec_chunk(result[1])
        code = None if chunk is None else chunk.get("exit_code")
        entry["status"] = ("unknown" if chunk is None else "running" if code is None else
                           "completed" if code == 0 else "failed")
        if chunk is not None:
            entry.update(exit_code=code, aggregated_output=chunk["output"])
    return {**entry, **witness}


def typed_text(entry):
    """The command a typed CommandExecution ran: its string, or the CMD of a [shell, -c|-lc, CMD] argv."""
    command = entry.get("command")
    if isinstance(command, str):
        return command
    if isinstance(command, list) and len(command) == 3 and command[1] in ("-c", "-lc"):
        return command[2]
    return None


def cover(open_cells, typed, shell):
    """A typed item_completed record wins over the code-mode parse: mark the first open cell call of its turn that
    it records (same command, or same paths) as covered, so the cell adds no second entry for it."""
    for cell in open_cells.values():
        if cell["turn"] != typed["turn_id"]:
            continue
        for index, call in enumerate(cell["calls"]):
            if index in cell["covered"] or call["tool"] != ("exec_command" if shell else "apply_patch"):
                continue
            if (shell and typed_text(typed) == call["command"]) or (
                    not shell and sorted(set(typed["paths"])) == sorted(set(call["paths"]))):
                cell["covered"].add(index)
                return


def code_mode_close(cell, payload, witness, executions, patches):
    results = None
    if payload is not None and cell["paired"]:
        parts = code_mode_parts(payload)
        results = None if parts is None else code_mode_results(cell["calls"], parts)
    for index, call in enumerate(cell["calls"]):
        result = None if results is None else results[index]
        if index in cell["covered"] or result == "not_run":
            continue
        entry = code_mode_entry(call, result, cell["turn"], cell["call_id"], {**witness, "call_line": cell["line"]})
        (executions if call["tool"] == "exec_command" else patches).append(entry)


def exec_events(rollout, cid, scope="current", tolerant=False):
    """Shell executions and patch applications recorded in the rollout, never model text.

    Read shapes: event_msg exec_command_end and patch_apply_end, event_msg item_completed with a
    CommandExecution or FileChange item, item.* stream records with command_execution or file_change items,
    Codex code mode (a custom_tool_call named exec, one entry per tools.exec_command or tools.apply_patch call in
    its cell, source "code_mode"), and response_item custom_tool_call / function_call named apply_patch paired with
    its output by call_id (that last shape is unconfirmed against a real host; its entries say so in "shape"). A
    declined patch is marked declined.

    A code-mode call pairs with its output by call_id; its printed parts are tied to its calls only when the whole
    cell is a known statement shape, otherwise each call is listed with status "unpaired" and no result. A call to a
    tool the session lacks is status "unavailable". A typed item_completed record for a call wins over the parse.
    Calls whose argument is not a strict literal are listed in "code_mode_unparsed".

    An event's own turn_id wins; otherwise it belongs to the turn started last before it. With scope "current"
    only the latest started turn is listed, so a new task_started hides every earlier attempt. This is the
    evidence a probe matches; it proves what the host recorded, not why.
    """
    require(scope in {"current", "all"}, "turn scope must be current or all")
    metadata, started_turn = None, None
    executions, patches, unparsed = [], [], []
    calls, cells = {}, {}
    for path, number, raw, record in rollout_records(rollout, tolerant):
        kind, payload, event = record.get("type"), record.get("payload"), event_type(record)
        if kind == "response_item" and isinstance(payload, dict):
            call = payload.get("call_id")
            if payload.get("type") == "custom_tool_call" and payload.get("name") == "exec" and isinstance(call, str) \
                    and isinstance(payload.get("input"), str):
                found, paired, skipped = code_mode_calls(payload["input"])
                unparsed += [{**entry, "turn_id": started_turn, "call_id": call, "line": number} for entry in skipped]
                if found:
                    cells[call] = {"calls": found, "paired": paired, "turn": started_turn, "call_id": call,
                                   "line": number, "covered": set(), "witness": witness_of(path, number, raw, record)}
            elif payload.get("type") == "custom_tool_call_output" and isinstance(call, str) and call in cells:
                code_mode_close(cells.pop(call), payload, witness_of(path, number, raw, record), executions, patches)
            elif payload.get("type") in PATCH_CALLS and payload.get("name") == "apply_patch" and isinstance(call, str):
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
            # The rollout shape (codex-cli 0.166, confirmed by native probe run 1): the item rides in an event_msg.
            entry = payload["item"]
            turn = payload.get("turn_id", started_turn)
            shell = entry["type"] == "CommandExecution"
            require(turn is None or isinstance(turn, str),
                    "malformed %s at line %d" % ("command execution" if shell else "patch apply", number))
            if shell:
                executions.append(command_execution(entry, turn, event, witness))
            else:
                patches.append(patch_apply(entry, turn, event, witness))
            cover(cells, (executions if shell else patches)[-1], shell)
        elif kind in {"item.started", "item.updated", "item.completed"} and isinstance(record.get("item"), dict):
            entry = record["item"]
            if entry.get("type") == "command_execution":
                executions.append(command_execution(entry, started_turn, kind, witness))
            elif entry.get("type") == "file_change":
                patches.append(patch_apply(entry, started_turn, kind, witness))
    for found, turn, opened in calls.values():
        patches.append(response_patch(found, None, turn, opened))
    for cell in cells.values():
        # A cell with no output yet (a cut or still running turn): its calls are listed, none tied to a result.
        code_mode_close(cell, None, cell["witness"], executions, patches)
    require(metadata is not None, "no native session identity in rollout")
    if scope == "current" and started_turn is not None:
        executions = [entry for entry in executions if entry["turn_id"] == started_turn]
        patches = [entry for entry in patches if entry["turn_id"] == started_turn]
        unparsed = [entry for entry in unparsed if entry["turn_id"] == started_turn]
    return {"schema": EXEC_SCHEMA, "cid": cid, "turn_scope": scope, "current_turn_id": started_turn,
            "command_executions": executions, "patch_applies": patches, "code_mode_unparsed": unparsed,
            "native_execution_qualified": False, "qualification_blocker": NATIVE_GAP}


def offered_agent_tools(payload, number):
    """Agent tools in one additional_tools payload, as <namespace>.<name>, or a bare name outside a namespace."""
    malformed = "malformed additional_tools record at line %d" % number
    entries = payload.get("tools")
    require(isinstance(entries, list), malformed)
    found = []
    for entry in entries:
        require(isinstance(entry, dict) and isinstance(entry.get("name"), str), malformed)
        if entry.get("type") != "namespace":
            if entry["name"] in AGENT_TOOL_NAMES:
                found.append(entry["name"])
            continue
        require(isinstance(entry.get("tools"), list), malformed)
        for tool in entry["tools"]:
            require(isinstance(tool, dict) and isinstance(tool.get("name"), str), malformed)
            if entry["name"] == AGENT_NAMESPACE or tool["name"] in AGENT_TOOL_NAMES:
                found.append(entry["name"] + "." + tool["name"])
    return found


def multi_agent_state(rollout, cid=None, tolerant=False):
    """Whether a Codex session was offered sub-agent tools, read from its rollout.

    agent_tools is the evidence: every tool an additional_tools record offered in the collaboration namespace, or
    under a multi-agent v2 tool name anywhere. version is the latest turn_context's multi_agent_version (None when
    absent) and is reported only, because Codex may record a version with the tools off. turns counts turn_context
    records and tool_records the additional_tools records; with no tools record the rollout says nothing about the
    tools either way. With cid, the rollout's session identity must match it.
    """
    metadata, version, turns, records, offered = None, None, 0, 0, set()
    for _path, number, _raw, record in rollout_records(rollout, tolerant):
        kind, payload = record.get("type"), record.get("payload")
        if kind == "session_meta":
            require(isinstance(payload, dict), "native record payload must be an object")
            require(cid is None or payload.get("id") == cid, "rollout identity does not match requested CID")
            metadata = payload
        elif kind == "turn_context" and isinstance(payload, dict):
            turns += 1
            version = payload.get("multi_agent_version")
        elif kind == "response_item" and isinstance(payload, dict) and payload.get("type") == "additional_tools":
            records += 1
            offered.update(offered_agent_tools(payload, number))
    require(cid is None or metadata is not None, "no native session identity in rollout")
    return {"schema": MULTI_AGENT_SCHEMA, "cid": None if metadata is None else metadata.get("id"), "version": version,
            "agent_tools": sorted(offered), "turns": turns, "tool_records": records}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rollout", required=True, help="Absolute path to the native session record")
    parser.add_argument("--cid", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "check", "admit", "events", "multi-agent"):
        command = commands.add_parser(name)
        if name == "events":
            command.add_argument("--turn", choices=("current", "all"), default="current",
                                 help="List the latest started turn's attempts, or every turn's")
            continue
        if name == "multi-agent":
            command.description = "Exit 2 when the session was offered sub-agent tools; the version alone is reported"
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
        if args.command == "multi-agent":
            state = multi_agent_state(args.rollout, args.cid)
            print(encoded(state).decode())
            return 2 if state["agent_tools"] else 0
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
