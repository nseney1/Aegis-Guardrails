"""Observe Codex code-mode scripts without evaluating input.

Only a complete strict scan can contribute script observations.
"""
from collections import Counter, OrderedDict, deque
import json
import re

from aegis_core.primitives import json_preflight
from aegis_core.team_mailbox_primitives import (
    MAX_JSON_DEPTH, MAX_JSON_ITEMS, MAX_JSON_NODES, MailboxRefusal, bounded_tree, strict_json,
)
from aegis_core.team_native_rollout import MAX_RECORD_BYTES, NativeRolloutRefusal, patch_paths

__all__ = [
    "CODE_MODE", "CODE_MODE_SAFE_OPTIONS", "CODE_MODE_MAX_CALLS", "Unrecognized", "CodeModeLimit",
    "MAX_CODE_MODE_TOKENS", "CodeModeMatches", "scan_code_mode", "code_mode_calls", "code_mode_close",
    "evidence_text_bytes",
]


# Native probe run 1 established the custom call and printed result formats.
CODE_MODE = "code_mode"
CODE_MODE_SHAPE = "confirmed by native probe run 1 (codex-cli 0.166.0)"
CODE_MODE_TOOLS = ("exec_command", "apply_patch")
# Only these options preserve the host shell and sandbox.
CODE_MODE_SAFE_OPTIONS = ("yield_time_ms", "max_output_tokens")
CODE_MODE_MAX_CALLS = 1000
MAX_CODE_MODE_TOKENS = 4 * MAX_JSON_NODES
# Bindings in the recognized subset must not be JavaScript reserved words or shadow the called helpers.
JS_RESERVED_BINDINGS = frozenset((
    "await break case catch class const continue debugger default delete do else enum export extends false finally "
    "for function if implements import in instanceof interface let new null package private protected public return "
    "static super switch this throw true try typeof var void while with yield eval arguments tools text String"
).split())
CODE_MODE_ERROR = "Script error:\n"
CODE_MODE_HEADERS = {"Script completed\n": "completed", "Script failed\n": "failed"}
# Frozen native scanner token pattern. In particular, only LF ends a line comment.
_JS_TOKEN = re.compile(r'\s+|//[^\n]*|/\*.*?(?:\*/|\Z)|("(?:[^"\\\n]|\\.)*"?)'
                       r'|(\'(?:[^\'\\\n]|\\.)*\'?|`(?:[^`\\]|\\.)*`?)|([A-Za-z_$][\w$]*)|(\d+)|(.)', re.S)
_ESCAPE = re.compile(
    r'\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{0*([0-9a-fA-F]{1,6})\}'
    r'|0(?![0-9])|\r\n|[^0-9ux])|\\'
)
_SURROGATE = re.compile("[\ud800-\udfff]")
_JSON_START = re.compile(r"[ \t\r\n]*[\[{]")
_JSON_OBJECT_START = re.compile(r'[ \t\r\n]*["}]')
_JSON_ARRAY_LEAF = re.compile(r"[^ \t\r\n\[]")
_JSON_ARRAY_VALUE = re.compile(r'["\]\-0-9]|\{[ \t\r\n]*["}]|(?:true|false|null)(?=[ \t\r\n,\]])')
_UNCERTAIN_OPTION = "code_mode_unparsed"


class Unrecognized(ValueError):
    code = 2
    next_action = "Use the documented code-mode statement and literal forms, then retry."

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class CodeModeLimit(Unrecognized):
    next_action = "Reduce the code-mode script to the observation limits, then retry."


class _JsCursor:
    def __init__(self, tokens, at=0):
        self.tokens, self.at = tokens, at

    def done(self):
        return self.at >= len(self.tokens)

    def accept(self, *texts):
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


def _call_limit():
    return CodeModeLimit("code-mode script exceeds %d calls" % CODE_MODE_MAX_CALLS)


def _diagnostic(tool, error):
    return {"tool": tool, "reason": error.reason, "code": error.code, "next_action": error.next_action}


def _decode(value):
    return strict_json(value, limit=MAX_RECORD_BYTES, max_atom=MAX_RECORD_BYTES, source_bytes=True)


def _js_tokens(source):
    if type(source) is not str:
        raise Unrecognized("code-mode input must be text")
    try:
        bounded_tree(source, limit=MAX_RECORD_BYTES + 2, source_bytes=True)
    except MailboxRefusal:
        raise CodeModeLimit("code-mode input exceeds observation byte limit") from None
    tokens = []
    kinds = ("invalid", "string", "other", "name", "number", "punct")
    for match in _JS_TOKEN.finditer(source):
        group = match.lastindex
        if group is None and not (source.startswith("/*", match.start())
                                  and not source.endswith("*/", match.start(), match.end())):
            continue
        if len(tokens) == MAX_CODE_MODE_TOKENS:
            raise CodeModeLimit("code-mode input exceeds token limit")
        tokens.append((kinds[group or 0], match.group(group or 0)))
    return tokens


def _js_string(token):
    if token[0] != "string":
        raise Unrecognized("not a double-quoted string literal")
    try:
        return _decode(token[1])
    except MailboxRefusal:
        raise Unrecognized("a string literal JSON cannot decode") from None


def _option_string(text):
    if len(text) < 2 or text[-1] != '"':
        raise Unrecognized("an option is not a literal")
    for escape in _ESCAPE.finditer(text, 1, len(text) - 1):
        point = escape[1]
        if escape.end() - escape.start() == 1 or (point is not None and int(point, 16) > 0x10FFFF):
            raise Unrecognized("an option is not a literal")


def _js_call(cursor, lookup):
    cursor.need("tools", ".")
    tool = cursor.take("name")[1]
    if tool not in CODE_MODE_TOOLS:
        raise Unrecognized("not exec_command or apply_patch")
    cursor.need("(")
    if tool == "apply_patch":
        patch = _js_string(cursor.take("string"))
        cursor.need(")")
        return {"tool": tool, "patch": patch, "paths": patch_paths(patch)}
    cursor.need("{")
    command, options, seen = None, [], set()
    while not cursor.accept("}"):
        kind, key = cursor.take("name", "string")
        if kind == "string":
            key = _js_string((kind, key))
        if key in seen:
            raise Unrecognized("duplicate command option")
        seen.add(key)
        if kind == "name" and cursor.ahead(",", "}"):
            if key != "cmd" or not lookup(key):
                raise Unrecognized("unsupported shorthand property")
            value = ("name", key)
        else:
            cursor.need(":")
            value = cursor.take("string", "number", "name")
        if key == "cmd":
            command = _js_string(value) if value[0] == "string" else lookup(value[1])
            if not isinstance(command, (str, list)) or not command:
                raise Unrecognized("cmd is not a string literal")
        elif value[0] == "name" and value[1] not in ("true", "false"):
            raise Unrecognized("an option is not a literal")
        else:
            if value[0] == "string":
                _option_string(value[1])
            if value[0] == "number" and len(value[1]) > 1 and value[1].startswith("0"):
                raise Unrecognized("an option is not a literal")
            options.append(key)
        if not cursor.accept(","):
            cursor.need("}")
            break
    cursor.need(")")
    if command is None:
        raise Unrecognized("exec_command has no cmd")
    return {"tool": tool, "command": command, "options": sorted(options)}


def _js_print(cursor, bound):
    cursor.need("text", "(", "await")
    call = _js_call(cursor, bound.get)
    cursor.need(")")
    if not cursor.done() and not cursor.ahead("}"):
        cursor.need(";")
    return call


def _catch_error_print(cursor, error, bound):
    if not cursor.accept("text", "("):
        return None
    if cursor.accept("String", "(", error, ")"):
        return "string"
    if "cmd" in bound and cursor.accept("{", "cmd", ",", "error", ":", "String", "(", error, ")"):
        cursor.accept(",")
        cursor.need("}")
        return "object"
    return None


def _js_statement(cursor, bound):
    if not cursor.accept("try", "{"):
        return {**_js_print(cursor, bound), "caught": None}
    call = _js_print(cursor, bound)
    cursor.need("}", "catch", "(")
    error = cursor.take("name")[1]
    if error in JS_RESERVED_BINDINGS or error in bound:
        raise Unrecognized("unsupported catch binding")
    cursor.need(")", "{")
    caught = _catch_error_print(cursor, error, bound)
    if caught is None:
        raise Unrecognized("a catch that prints something else")
    cursor.need(")")
    cursor.accept(";")
    cursor.need("}")
    return {**call, "caught": caught}


def _js_array(cursor):
    name = cursor.take("name")[1]
    if name in JS_RESERVED_BINDINGS:
        raise Unrecognized("unsupported array binding")
    cursor.need("=", "[")
    values = []
    while not cursor.accept("]"):
        values.append(_js_string(cursor.take("string")))
        if not cursor.accept(","):
            cursor.need("]")
            break
    if not values or not all(isinstance(value, str) for value in values):
        raise Unrecognized("an array that is not strings")
    return name, values


def _js_loop(cursor):
    if not (cursor.accept("const") or cursor.accept("let")):
        raise Unrecognized("a loop without const or let")
    variable = cursor.take("name")[1]
    cursor.need("of")
    name = cursor.take("name")[1]
    cursor.need(")")
    if variable in JS_RESERVED_BINDINGS or variable == name:
        raise Unrecognized("unsupported loop binding")
    return variable, name


def _expanded(call, available):
    count = len(call["command"]) if isinstance(call.get("command"), list) else 1
    if count > available:
        raise _call_limit()
    if call["tool"] == "exec_command" and isinstance(call["command"], list):
        return [{**call, "command": command} for command in call["command"]]
    return [call]


def _js_script(cursor, calls):
    arrays = {}
    while not cursor.done():
        if cursor.accept("const") or cursor.accept("let"):
            name, values = _js_array(cursor)
            if name in arrays:
                raise Unrecognized("duplicate array binding")
            arrays[name] = values
            cursor.need(";")
        elif cursor.accept("for", "("):
            variable, name = _js_loop(cursor)
            if name not in arrays:
                raise Unrecognized("a loop over an unknown array")
            braced = cursor.accept("{")
            call = _js_statement(cursor, {variable: arrays[name]})
            if braced:
                cursor.need("}")
            if not isinstance(call.get("command"), list):
                raise Unrecognized("a loop whose call does not use its variable")
            calls += _expanded(call, CODE_MODE_MAX_CALLS - len(calls))
        else:
            call = _js_statement(cursor, {})
            calls += _expanded(call, CODE_MODE_MAX_CALLS - len(calls))
    return calls


def scan_code_mode(source):
    """Strict grammar scan. Unknown shapes and excess input raise typed refusals."""
    return _js_script(_JsCursor(_js_tokens(source)), [])


def code_mode_calls(source):
    """Return proposals, pairing eligibility, diagnostics and unknown attribution."""
    try:
        return scan_code_mode(source), True, [], False
    except Unrecognized as exc:
        return [], False, [_diagnostic("exec", exc)], True


def _code_mode_parts(payload):
    value = payload.get("output")
    if isinstance(value, list) and len(value) > CODE_MODE_MAX_CALLS + 2:
        raise NativeRolloutRefusal("too_large")
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


def _json_candidate(text):
    start = _JSON_START.match(text)
    if start is None:
        return False
    at, end = start.end(), len(text)
    while end > at and text[end - 1] in " \t\r\n":
        end -= 1
    if text[at - 1] == "{":
        return text[end - 1] == "}" and _JSON_OBJECT_START.match(text, at) is not None
    if text[end - 1] != "]":
        return False
    # Distinguish leading brackets in plain errors from a JSON array leaf.
    leaf = _JSON_ARRAY_LEAF.search(text, at)
    return leaf is not None and _JSON_ARRAY_VALUE.match(text, leaf.start()) is not None


def _json_object(text):
    if not _json_candidate(text):
        return None
    try:
        value = _decode(text)
    except MailboxRefusal as error:
        if error.reason == "too_large":
            raise NativeRolloutRefusal("too_large") from None
        # The shared parser conflates lexical errors and integer bounds.
        try:
            json_preflight(_SURROGATE.sub("\ufffd", text), max_bytes=MAX_RECORD_BYTES, max_depth=MAX_JSON_DEPTH,
                           max_nodes=MAX_JSON_NODES, max_items=MAX_JSON_ITEMS, max_string=MAX_RECORD_BYTES,
                           max_atom=MAX_RECORD_BYTES)
        except ValueError as limit:
            if str(limit) in ("size", "nesting", "nodes", "container", "string", "atom"):
                raise NativeRolloutRefusal("too_large") from None
        else:
            try:
                json.loads(text, parse_int=_probe_integer_bound, parse_float=lambda _: None,
                           object_hook=lambda _: None)
            except NativeRolloutRefusal:
                raise
            except ValueError:
                pass
        return None
    return value if isinstance(value, dict) else None


def _probe_integer_bound(literal):
    sign = literal.startswith("-")
    width = len(literal) - sign
    if width > 20 or (width == 20 and literal[sign:] > "18446744073709551615"):
        raise NativeRolloutRefusal("too_large") from None


def _chunk_fields(value):
    if value is None or "error" in value or not isinstance(value.get("chunk_id"), str) \
            or not isinstance(value.get("output"), str):
        return None
    code = value.get("exit_code")
    if code is None and "session_id" not in value or code is not None and (
            not isinstance(code, int) or isinstance(code, bool)):
        return None
    return code, value["output"]


def _code_mode_results(calls, parts):
    _, body, error = parts
    results, used, thrown = [], 0, False
    for call in calls:
        if used < len(body):
            text = body[used]
            used += 1
            printed = _json_object(text)
            success_shape = (_chunk_fields(printed) if call["tool"] == "exec_command"
                             else printed == {} if printed is not None else None)
            if call["caught"] is None or success_shape is not None:
                results.append(("result", text, success_shape))
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


def _code_mode_entry(call, result, turn, call_id, witness):
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
        elif result is not None and result[2] is True:
            entry.update(success=True, stdout=result[1], status="completed")
        elif result is not None:
            entry.update(stdout=result[1], status="unknown")
        return {**entry, **witness}
    entry.update(command=call["command"], command_text=call["command"], exit_code=None, aggregated_output=None,
                 options=call["options"])
    if result is not None and result[0] == "result":
        chunk = result[2]
        code = None if chunk is None else chunk[0]
        entry["status"] = ("unknown" if chunk is None else "running" if code is None else
                           "completed" if code == 0 else "failed")
        if chunk is not None:
            entry.update(exit_code=code, aggregated_output=chunk[1])
    return {**entry, **witness}


def _typed_text(entry):
    command = entry.get("command")
    if isinstance(command, str):
        return command
    if isinstance(command, list) and len(command) == 3 and command[1] in ("-c", "-lc"):
        return command[2]
    return None


def evidence_text_bytes(text):
    """UTF-8 width including escaped surrogate values, without an encoded copy."""
    if text.isascii():
        return len(text)
    return sum(1 + (code > 0x7F) + (code > 0x7FF) + (code > 0xFFFF) for code in map(ord, text))


class _PendingMatch:
    def __init__(self):
        self.queue = OrderedDict()
        self.by_script = {}
        self.counts = Counter()
        self.option_bytes = 0
        self.views = {}

    def add(self, script_id, index, options):
        if script_id not in self.by_script:
            self.queue[script_id] = deque()
            self.by_script[script_id] = set()
        self.queue[script_id].append(index)
        distinct = self.by_script[script_id]
        for option in options:
            if option not in distinct:
                distinct.add(option)
                if option not in self.counts:
                    self.option_bytes += 8 + evidence_text_bytes(option)
                    self.views.clear()
                self.counts[option] += 1

    def remove(self, script_id):
        self.queue.pop(script_id, None)
        for option in self.by_script.pop(script_id):
            self.counts[option] -= 1
            if self.counts[option] == 0:
                del self.counts[option]
                self.option_bytes -= 8 + evidence_text_bytes(option)
                self.views.clear()

    def cover_first(self, scripts):
        if self.queue:
            script_id, indices = next(iter(self.queue.items()))
            scripts[script_id]["covered"].add(indices.popleft())
            if not indices:
                self.queue.popitem(last=False)

    def options(self, uncertain, reserve):
        append_marker = uncertain and _UNCERTAIN_OPTION not in self.counts
        size = self.option_bytes + (8 + len(_UNCERTAIN_OPTION) if append_marker else 0)
        if size and reserve(8 + size):
            if append_marker not in self.views:
                options = (self.counts.keys() | {_UNCERTAIN_OPTION}) if append_marker else self.counts
                self.views[append_marker] = sorted(options)
            return self.views[append_marker]
        return ()


class CodeModeMatches:
    """Index coverage by turn and command or path set. Option views are shared."""
    def __init__(self):
        self.groups = {}
        self.uncertain_turns = set()
        self.uncertain_options = [_UNCERTAIN_OPTION]

    def admit(self, script, unknown, recorded_turn):
        turn, script_id = script["turn"], script["call_id"]
        if unknown:
            self.uncertain_turns.update((turn, recorded_turn))
        keys = set()
        for index, call in enumerate(script["calls"]):
            shell = call["tool"] == "exec_command"
            value = call["command"] if shell else frozenset(call["paths"])
            key = turn, shell, value
            if key not in self.groups:
                self.groups[key] = _PendingMatch()
            self.groups[key].add(script_id, index, call.get("options", ()))
            keys.add(key)
        script["match_keys"] = keys

    def release(self, script):
        for key in script["match_keys"]:
            group = self.groups[key]
            group.remove(script["call_id"])
            if not group.by_script:
                del self.groups[key]

    def cover(self, scripts, typed, shell, *, active_turn, completed, reserve):
        turn = typed["turn_id"]
        key = turn, shell, _typed_text(typed) if shell else frozenset(typed["paths"])
        group = self.groups.get(key)
        uncertain = turn in self.uncertain_turns or (turn is None and active_turn in self.uncertain_turns)
        if group is not None and completed:
            group.cover_first(scripts)
            options = group.options(uncertain, reserve)
        elif uncertain and reserve(16 + len(_UNCERTAIN_OPTION)):
            options = self.uncertain_options
        else:
            options = ()
        if options:
            typed["options"] = options


def code_mode_close(script, payload, witness, emit):
    results = None
    if payload is not None:
        parts = _code_mode_parts(payload)
        if parts is not None and script["paired"]:
            results = _code_mode_results(script["calls"], parts)
    for index, call in enumerate(script["calls"]):
        result = None if results is None else results[index]
        if index in script["covered"] or result == "not_run":
            continue
        entry = _code_mode_entry(call, result, script["turn"], script["call_id"], {**witness, "call_line": script["line"]})
        emit(entry, call["tool"] == "exec_command")
