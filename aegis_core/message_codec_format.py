"""Canonical aegis.msg/1 format, schemas and bounded encoding (stdlib only).
Selection and storage share CodecError and Budget from this module.
"""
import hashlib
import json
import math
import re
from types import MappingProxyType
import unicodedata
from . import message_codec_views as _views


__all__ = [
    "CodecError", "Budget", "canonical", "parse", "compose", "record_id", "KIND_SCHEMAS",
    "MAX_BYTES", "MAX_NODES", "MAX_SELECTORS", "MAX_REFS", "MAX_SPANS",
    "MAX_WORK_BYTES", "MAX_REF_BYTES", "MAX_OUTPUT_CHARS", "MAX_SELECTION_VISITS",
    "REF_NAME", "NAME", "INDEX", "KEYS", "STRING", "INTEGER", "HANDLE", "SHA",
    "require", "object_schema", "array_schema", "KEY_MARKER", "CURSOR_PATTERN",
    "json_chunks", "escape_char", "neutral_text", "FRONTEND_MESSAGES", "frontend_error",
]


SCHEMA = "aegis.msg/1"
MAX_BYTES = 262144
MAX_DEPTH = 32
MAX_NODES = 10000
MAX_SELECTORS = 16
MAX_REFS = 64
MAX_SPANS = 64
MAX_NUMBER_CHARS = 64
MAX_WORK_BYTES = 2 * MAX_BYTES
MAX_REF_BYTES = MAX_REFS * MAX_BYTES
_SURROGATE = re.compile("[\ud800-\udfff]")
_QUOTED = re.compile(r'["\\\x00-\x1f\x7f-\U0010ffff]')
MAX_OUTPUT_CHARS = MAX_REFS * MAX_BYTES
_EXPLICIT = re.compile("[\u034f\u115f\u1160\u17b4\u17b5\u2800\u3164\uffa0\u180b-\u180f\ufe00-\ufe0f\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
_DISPLAY = re.compile(r"[\x00-\x1f\x7f-\x9f]|[^\x00-\x7f]")
_TOKEN = re.compile(r'(?P<space>[ \n\r\t]+)|(?P<mark>[{}\[\],:])|(?P<atom>[^ \n\r\t{}\[\],:"]+)')
_STRING_END = re.compile(r'["\\]')
_BODY_LINE = re.compile(r'[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+\Z')
CURSOR_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,4}):[0-9a-f]{64}")
MAX_SELECTION_VISITS = MAX_SELECTORS * MAX_NODES
KEY_MARKER = object()
REF_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
ERROR_MESSAGES = MappingProxyType({
    "E_FORMAT": "invalid canonical message record",
    "E_HASH": "record integrity check failed",
    "E_LIMIT": "limit exceeded; narrow the selectors",
    "E_SELECTOR": "invalid selector or cursor; check grammar or re-read without since",
    "E_REF": "invalid, unresolved or ambiguous reference; bind a store or select body/fields without refs",
    "E_SPAN": "invalid span selection",
    "E_AUTH": "store access refused: unsafe directory or platform lacks anchored file operations; use a supported real directory",
})
FRONTEND_MESSAGES = MappingProxyType({
    "arguments": "invalid arguments; see aegis msg ACTION --help",
    "workspace": "workspace is not initialized; run aegis init",
    "binding": "workspace binding refused; check --workspace / AEGIS_WORKSPACE",
    "root": "workspace root refused; choose a project directory",
    "attachment": "workspace attachment unavailable; check permissions",
    "input": "input file unreadable",
    "write_ref": "write reference must be a full 64-hex id present in the target store",
})
_SPECIAL_MESSAGES = MappingProxyType({"operation":
    "store operation unavailable; check permissions, free space, write access and file descriptor limits",
    "format": "invalid format; choose json, md or tsv",
    "private": "store access refused; use a private store directory",
    "path": "store access refused; pass a canonical absolute path",
    "resolution": "reference not found or ambiguous; use the full id or a longer handle",
    "record": "record exceeds the size, depth, node or ref limit; split the record",
    "number": "number cannot be preserved verbatim; use canonical numeric text",
    "option": "unknown option", "handle": "handle must be 16-64 lowercase hex"})
SHA = re.compile(r"[0-9a-f]{64}")
HANDLE = re.compile(r"[0-9a-f]{16,64}")
NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
INDEX = re.compile(r"0|[1-9][0-9]*")
KEYS = frozenset(("schema", "kind", "meta", "fields", "body", "spans", "refs"))

_SELECTOR_REFUSAL = (
    "invalid selector or cursor; fields (--fields): at most 16 selectors of 1-1024 characters, depth 8; "
    "dotted names and zero-based indices, one-level *; final row projection "
    "findings.*.{id,severity,file,line}; one selector per MCP array entry; "
    "CLI entries may be comma-separated or repeated; no regex or recursive wildcard; "
    "paths start in fields unless prefixed by schema,kind,meta,fields,body,spans,refs; "
    "spans (--spans): at most 64 zero-based indices, each below 10000 and present in the body outline; "
    "expand (--expand): at most 64 named refs, one level within max_chars (--max-chars); "
    "since (--since): 0 starts log rows, otherwise n:sha256(canonical rows[:n]); re-read without since if stale"
)


class CodecError(ValueError):
    """Fixed public error; callers serialize as_dict(), never exception context."""

    def __init__(self, code, *, detail=None):
        self.code = code if type(code) is str and code in ERROR_MESSAGES else "E_FORMAT"
        self.detail = detail if type(detail) is str else ""
        super().__init__(_SPECIAL_MESSAGES.get(self.detail, ERROR_MESSAGES[self.code]))

    def as_dict(self):
        return {"error": {"code": self.code, "message": str(self)}}


def frontend_error(error, *, detail=None):
    """Explicit front-end next actions, leaving codec failures host-neutral."""
    value = error.as_dict()
    if error.code == "E_SELECTOR":
        value["error"]["message"] = _SELECTOR_REFUSAL
    if type(detail) is str and detail in FRONTEND_MESSAGES:
        value["error"]["message"] = FRONTEND_MESSAGES[detail]
    return value


def require(condition, code="E_FORMAT", *, detail=None):
    if not condition:
        raise CodecError(code, detail=detail)


def object_schema(required, optional=None):
    return {"type": "object", "required": required, "optional": optional or {}}


def array_schema(items):
    return {"type": "array", "items": items}


def _enum(*values):
    return {"type": "string", "enum": values}


STRING, INTEGER, BOOLEAN, OPAQUE = ({"type": t} for t in ("string", "integer", "boolean", "json"))
STRINGS = array_schema(STRING)
VERDICT = _enum("ACCEPT", "REQUEST_CHANGES", "CANNOT_REVIEW")
FINDING_REQUIRED = {
    "id": STRING, "severity": _enum("P0", "P1", "P2", "P3"), "blocking": BOOLEAN,
    "category": _enum("CORRECTNESS", "SECURITY", "FAIL_OPEN", "CONCURRENCY", "PERFORMANCE",
                      "TEST_GAP", "CONTRACT", "DOCS", "OTHER"),
    "file": STRING, "line": INTEGER, "quote": STRING, "scenario": STRING, "fix": STRING,
    "evidence": _enum("VERIFIED", "PLAUSIBLE", "SPECULATIVE"), "related": STRINGS,
}
PRIOR = array_schema(object_schema({"id": STRING, "state": _enum("FIXED", "NOT_FIXED", "PARTIAL", "NOT_APPLICABLE"),
                         "note": STRING}))
REVIEW_REQUIRED = {"reasoning_summary": STRING, "findings": array_schema(object_schema(FINDING_REQUIRED)),
                   "checked": STRINGS, "coverage_gaps": STRING, "verdict": VERDICT}
KIND_SCHEMAS = {
    "text": object_schema({}),
    "record": object_schema({"value": OPAQUE}),
    "log": object_schema({"rows": array_schema(object_schema({"text": STRING},
                                         {"time": STRING, "level": STRING, "data": OPAQUE}))}),
    "blob": object_schema({}, {"media_type": STRING, "filename": STRING}),
    "review.v1": object_schema(dict(REVIEW_REQUIRED, prior_findings=PRIOR)),
    "prereview.v1": object_schema(dict(REVIEW_REQUIRED,
        lens=_enum("WHOLE_CHANGE", "CORRECTNESS", "SECURITY", "FAIL_OPEN", "OTHER"),
        findings=array_schema(object_schema(dict(FINDING_REQUIRED, sibling_of=STRING))))),
    "handoff.v1": object_schema({
        "reasoning_summary": STRING, "base_head": STRING,
        "files_changed": array_schema(object_schema({"path": STRING, "change": _enum("ADDED", "MODIFIED", "DELETED"),
                                          "summary": STRING})),
        "tests": array_schema(object_schema({"phase": _enum("RED", "GREEN", "OTHER"), "command": STRING,
                                  "passed": INTEGER, "failed": INTEGER})),
        "findings_addressed": PRIOR, "assumptions": STRINGS, "open_questions": STRINGS,
        "hold_kind": _enum("NONE", "PRODUCTION_SCOPE", "ASSERTION_CONFLICT", "HASH_PINNED",
                           "DEFECT_NOT_UNDERSTOOD", "BUDGET", "OTHER"),
        "hold_reason": STRING, "status": _enum("READY_FOR_FULL", "HOLD"),
    }),
    "leadreport.v1": object_schema({
        "reasoning_summary": STRING, "head": STRING,
        "reviews": array_schema(object_schema({"lens": _enum("CORRECTNESS", "SECURITY", "OTHER"),
                                    "verdict": _enum("ACCEPT", "REQUEST_CHANGES", "INCOMPLETE"),
                                    "head": STRING, "report_path": STRING})),
        "hold_kind": _enum("NONE", "ASSERTION_CHANGE", "SCOPE", "HASH_PINNED", "CROSS_LANE",
                           "UNATTRIBUTED_RED_FULL", "BUDGET", "OTHER"),
        "hold_reason": STRING, "next_action": STRING,
        "status": _enum("LANE_READY", "LANE_HOLD", "LANE_DONE"),
    }),
}


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    return tuple(_freeze(child) for child in value) if type(value) in (list, tuple) else value


KIND_SCHEMAS = _freeze(KIND_SCHEMAS)


def _text(value):
    require(type(value) is str)
    require(len(value) <= MAX_BYTES, "E_LIMIT", detail="record")
    require(_SURROGATE.search(value) is None)


class Budget:
    """Independent output, selection staging, visit-work and I/O accounting."""
    def __init__(self, limit, parent=None, detail=None):
        require(type(limit) is int and limit >= 0, "E_LIMIT")
        self.limit, self.used, self.visits = limit, 0, 0
        self.parent, self.detail = parent, detail

    def check(self, count):
        require(self.used + count <= self.limit, "E_LIMIT", detail=self.detail)
        if self.parent is not None:
            self.parent.check(count)

    def charge(self, count):
        self.check(count)
        self.used += count
        if self.parent is not None:
            self.parent.charge(count)

    stage = charge

    def visit(self):
        self.visits += 1
        require(self.visits <= MAX_SELECTION_VISITS, "E_LIMIT")


def _number(value):
    if type(value) is int:
        require(-10 ** 63 < value < 10 ** 64, "E_LIMIT", detail="record")
    if type(value) is float:
        require(math.isfinite(value))
    token = json.dumps(value, allow_nan=False)
    require(len(token) <= MAX_NUMBER_CHARS, "E_LIMIT", detail="record")
    return token


def _estimated_text(value, budget):
    require(type(value) is str)
    cost = len(value) + 2
    budget.check(cost)
    _text(value)
    for match in _QUOTED.finditer(value):
        char = match[0]
        cost += 1 if char in '"\\\b\f\n\r\t' else 5 if ord(char) <= 0xFFFF else 11
        budget.check(cost)
    budget.charge(cost)


def _tree(value):
    pending, nodes, budget = [(value, 1)], 0, Budget(MAX_BYTES, detail="record")
    while pending:
        current, depth = pending.pop()
        nodes += 1
        require(depth <= MAX_DEPTH and nodes <= MAX_NODES, "E_LIMIT", detail="record")
        if type(current) in (dict, list):
            children = current.values() if type(current) is dict else current
            require(nodes + len(pending) + len(current) <= MAX_NODES, "E_LIMIT", detail="record")
            budget.charge(2 + max(0, len(current) - 1))
            if type(current) is dict:
                for key in current:
                    _estimated_text(key, budget)
                    budget.charge(1)
            pending.extend((child, depth + 1) for child in children)
        elif type(current) is str:
            _estimated_text(current, budget)
        else:
            require(current is None or type(current) in (int, float, bool))
            token = ("null" if current is None else "true" if current is True else
                     "false" if current is False else _number(current))
            budget.charge(len(token))
    return nodes, budget.used


def _validate_type(value, schema):
    kind = schema["type"]
    if kind == "json":
        return
    if kind == "object":
        require(type(value) is dict)
        required, optional = schema["required"], schema["optional"]
        require(required.keys() <= value.keys() and value.keys() <= required.keys() | optional.keys())
        for key, child in value.items():
            _validate_type(child, required[key] if key in required else optional[key])
    elif kind == "array":
        require(type(value) is list)
        for child in value:
            _validate_type(child, schema["items"])
    else:
        require(type(value) is {"string": str, "integer": int, "boolean": bool}[kind])
        if "enum" in schema:
            require(value in schema["enum"])


def _validate(value):
    size = _tree(value)
    require(type(value) is dict and value.keys() == KEYS)
    require(value["schema"] == SCHEMA and type(value["kind"]) is str)
    require(value["kind"] in KIND_SCHEMAS)
    _validate_type(value["meta"], object_schema({k: STRING for k in ("from", "host", "session", "created_at")}))
    _validate_type(value["fields"], KIND_SCHEMAS[value["kind"]])
    require(type(value["body"]) is str and type(value["spans"]) is list and type(value["refs"]) is dict)
    require(len(value["refs"]) <= MAX_REFS, "E_LIMIT", detail="record")
    for name, rid in value["refs"].items():
        require(REF_NAME.fullmatch(name) is not None)
        require(type(rid) is str and SHA.fullmatch(rid) is not None)
    for span in value["spans"]:
        require(type(span) is list and len(span) == 3)
        start, end, title = span
        require(type(start) is int and type(end) is int and type(title) is str)
        require(0 <= start <= end <= len(value["body"]))
    return size


def escape_char(char):
    # Cn stays escaped fail-closed even when Unicode database versions differ.
    if unicodedata.category(char) not in {"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"} and not _EXPLICIT.fullmatch(char):
        return char
    return "\\u%04x" % ord(char) if ord(char) <= 0xFFFF else json.dumps(char, ensure_ascii=True)[1:-1]


def neutral_text(text):
    if text.isascii() and text.isprintable() or text.isprintable() and not _EXPLICIT.search(text):
        return text
    return _DISPLAY.sub(lambda m: escape_char(m[0]), text)


def _strings(value, ascii=True, display=False, budget=None):
    # ASCII needs at most six bytes per character; supplementary escapes need
    # twelve. Only canonical collection supplies its live remaining budget.
    if budget is not None and ascii and not display:
        worst = (6 if value.isascii() else 12) * len(value) + 2
        if worst <= budget.limit - budget.used:
            yield json.dumps(value, ensure_ascii=True, allow_nan=False)
            return
    yield '"'
    for start in range(0, len(value), 128):
        text = json.dumps(value[start:start + 128], ensure_ascii=ascii, allow_nan=False)[1:-1]
        yield neutral_text(text) if display else text
    yield '"'


def _put(text, position):
    position[0] += len(text)
    yield text


def json_chunks(value, ascii=True, display=False, ranges=None, path=(), position=None, budget=None):
    position = [0] if position is None else position
    start = position[0]
    if type(value) is dict:
        yield from _put("{", position)
        for index, key in enumerate(sorted(value) if ascii else value):
            if index:
                yield from _put(",", position)
            key_start = position[0]
            for chunk in _strings(key, ascii, display, budget):
                yield from _put(chunk, position)
            if ranges is not None and path + (KEY_MARKER, key) in ranges:
                ranges[path + (KEY_MARKER, key)] = (key_start, position[0])
            yield from _put(":", position)
            yield from json_chunks(value[key], ascii, display, ranges, path + (key,), position, budget)
        yield from _put("}", position)
    elif type(value) is list or isinstance(value, _views.Rows):
        yield from _put("[", position)
        for index, child in enumerate(value):
            if index:
                yield from _put(",", position)
            yield from json_chunks(child, ascii, display, ranges, path + (index,), position, budget)
        yield from _put("]", position)
    else:
        pieces = _strings(value, ascii, display, budget) if type(value) is str else (
            ("null" if value is None else "true" if value is True else "false" if value is False
             else _number(value)),)
        for chunk in pieces:
            yield from _put(chunk, position)
    if ranges is not None and path in ranges:
        ranges[path] = (start, position[0])


def _collect(chunks, budget):
    result = []
    for chunk in chunks:
        budget.charge(len(chunk))
        result.append(chunk)
    return "".join(result)


def canonical(value):
    """Validate, then encode budgeted strings whole or in bounded scalar chunks."""
    _validate(value)
    budget = Budget(MAX_BYTES, detail="record")
    return _collect(json_chunks(value, budget=budget), budget).encode("utf-8")


def _tokens(text, *, verbatim_numbers=False):
    index = 0
    while index < len(text):
        if text[index] == '"':
            start, index = index, index + 1
            while True:
                match = _STRING_END.search(text, index)
                require(match is not None)
                index = match.end()
                if match[0] == '"':
                    break
                require(index < len(text))
                index += 1  # Skip an escaped character without a regex backtracking stack.
            yield "string", start, index
            continue
        match = _TOKEN.match(text, index)
        require(match is not None)
        kind, start, index = match.lastgroup, index, match.end()
        if kind == "space":
            continue
        token = match[0]
        if kind == "atom":
            require(token in ("null", "true", "false") or NUMBER.fullmatch(token) is not None)
            require(token[0] not in "-0123456789" or len(token) <= MAX_NUMBER_CHARS, "E_LIMIT", detail="record")
            if verbatim_numbers and token[0] in "-0123456789":
                value = float(token) if "." in token or "e" in token or "E" in token else int(token)
                require(_number(value) == token, "E_FORMAT", detail="number")
        yield token if kind == "mark" else "scalar", start, index


def _preflight(text, *, verbatim_numbers=False):
    """Bound value starts/ref keys before json.loads builds any containers."""
    stack, nodes, seen = [], 0, False
    for token, start, stop in _tokens(text, verbatim_numbers=verbatim_numbers):
        frame = stack[-1] if stack else None
        state = frame["state"] if frame else None
        if token in ("}", "]"):
            require(frame is not None and frame["op"] == ("{" if token == "}" else "["))
            require(state in ("after", "first_key", "first_value"))
            stack.pop()
            continue
        if token == ",":
            require(frame is not None and state == "after")
            frame["state"] = "key" if frame["op"] == "{" else "value"
            continue
        if token == ":":
            require(frame is not None and state == "colon")
            frame["state"] = "value"
            continue
        if frame and state in ("key", "first_key"):
            require(token == "string")
            frame["count"] += 1
            require(not frame["refs"] or frame["count"] <= MAX_REFS, "E_LIMIT", detail="record")
            key = json.decoder.scanstring(text, start + 1, True)[0]
            _text(key)
            frame["key"], frame["state"] = key, "colon"
            continue
        require((frame is not None and state in ("value", "first_value")) or (frame is None and not seen))
        nodes += 1
        require(nodes <= MAX_NODES and len(stack) + 1 <= MAX_DEPTH, "E_LIMIT", detail="record")
        seen = True
        if frame:
            frame["state"] = "after"
        if token in ("{", "["):
            is_refs = len(stack) == 1 and frame["op"] == "{" and frame.get("key") == "refs"
            stack.append({"op": token, "state": "first_key" if token == "{" else "first_value",
                          "refs": is_refs, "count": 0})
    require(seen and not stack)


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def _nonfinite(_value):
    raise CodecError("E_FORMAT")


def _decode(data, *, verbatim_numbers=False):
    """One bounded decoder for stored records and caller-authored content."""
    require(type(data) is bytes)
    require(len(data) <= MAX_BYTES, "E_LIMIT", detail="record")
    try:
        text = data.decode("utf-8")
        _preflight(text, verbatim_numbers=verbatim_numbers)
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)
    except (UnicodeError, ValueError, OverflowError) as exc:
        if isinstance(exc, CodecError):
            raise
        raise CodecError("E_FORMAT") from None


def parse(data):
    """Bytes only; byte/node/ref/depth/numeric bounds precede container decoding."""
    value = _decode(data)
    require(canonical(value) == data)
    return value


def _span_end(spans, end, budget):
    if spans:
        budget.charge(len(str(end)) - len(str(spans[-1][1])))
        spans[-1][1] = end


def _append_span(spans, body, offset, start, end, nodes, budget):
    """Charge the four nodes and exact canonical bytes before slicing a title."""
    nodes.charge(4)
    _span_end(spans, offset, budget)
    budget.charge(4 + 2 * len(str(offset)) + bool(spans) + end - start + 2)
    for match in _QUOTED.finditer(body, start, end):
        char = match[0]
        budget.charge(1 if char in '"\\\b\f\n\r\t' else 5 if ord(char) <= 0xFFFF else 11)
    spans.append([offset, offset, body[start:end]])


def _body_spans(body, nodes, budget):
    """Lazy CommonMark lines; ATX headings and fences use body-character offsets."""
    spans, fence, fence_size = [], None, 0
    for line in _BODY_LINE.finditer(body):
        offset, end = line.span()
        while end > offset and body[end - 1] in "\r\n":
            end -= 1
        start = offset
        while start < min(end, offset + 4) and body[start] == " ":
            start += 1
        if start == end or start - offset > 3:
            continue
        marker, stop = body[start], start
        if marker in ("`", "~", "#"):
            while stop < end and body[stop] == marker:
                stop += 1
        run = stop - start
        if marker in ("`", "~") and run >= 3:
            if fence is None:
                if marker == "~" or body.find("`", stop, end) == -1:
                    fence, fence_size = marker, run
            elif marker == fence and run >= fence_size and all(body[n] in " \t" for n in range(stop, end)):
                fence = None
            continue
        if fence is None and marker == "#" and run <= 6 and (stop == end or body[stop] in " \t"):
            while stop < end and body[stop] in " \t":
                stop += 1
            while end > stop and body[end - 1] in " \t":
                end -= 1
            closing = end
            while closing > stop and body[closing - 1] == "#":
                closing -= 1
            if closing == stop or (closing < end and body[closing - 1] in " \t"):
                end = closing
                while end > stop and body[end - 1] in " \t":
                    end -= 1
            _append_span(spans, body, offset, stop, end, nodes, budget)
    _span_end(spans, len(body), budget)
    return spans


def compose(kind, content_bytes, meta):
    """Compose a canonical record from bounded content and code-authored metadata.

    Caller content contains exactly fields/body/refs. Record limits, rather than
    the read-selection limit, bound the generated fence-aware heading spans.
    """
    require(type(kind) is str and kind in KIND_SCHEMAS and type(meta) is dict)
    content = _decode(content_bytes, verbatim_numbers=True)
    require(type(content) is dict and content.keys() == {"fields", "body", "refs"})
    require(type(content["body"]) is str)
    require(type(content["refs"]) is dict)
    require(all(type(rid) is str and SHA.fullmatch(rid) for rid in content["refs"].values()), "E_REF")
    value = dict(content, schema=SCHEMA, kind=kind, meta=meta, spans=[])
    nodes, size = _validate(value)
    value["meta"] = dict(meta)
    value["spans"] = _body_spans(content["body"], Budget(MAX_NODES - nodes, detail="record"),
                                Budget(MAX_BYTES - size, detail="record"))
    canonical(value)
    return value


def record_id(value):
    return hashlib.sha256(canonical(value)).hexdigest()
