"""Stdlib-only aegis.msg/1; CodecError.as_dict is the fixed data-error shape.
Code supplies meta and [start,end,title] body-character spans; schemas follow S4/A1.
Selection/expansion work is 2*MAX_BYTES; descriptor I/O admits 64 maximal records.
Every store read/description verifies bytes. Missing array leaves use positional
null plus {path,count}; projections retain presence. Coverage unions intervals.
since is '<n>:<sha256(canonical rows[:n])>'; '0' starts; row_limit pages first.
Unsafe/closed/unsupported stores refuse E_AUTH; Windows support is deferred.
JSON is default; MD fences that JSON; TSV marks data and uses JSON cells.
"""
from contextlib import contextmanager, suppress
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from threading import Lock
from types import MappingProxyType
import uuid
import unicodedata
import weakref


__all__ = ["CodecError", "Store", "canonical", "parse", "record_id", "read_view",
           "KIND_SCHEMAS", "MAX_BYTES"]

SCHEMA = "aegis.msg/1"
MAX_BYTES = 262144
MAX_DEPTH = 32
MAX_NODES = 10000
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
_JSON_ESC = re.compile(r'\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})')
_TOKEN = re.compile(r'(?P<space>[ \n\r\t]+)|(?P<string>"(?:[^"\\]|\\.)*")|(?P<mark>[{}\[\],:])|(?P<atom>[^ \n\r\t{}\[\],:"]+)')
_CURSOR = re.compile(r"(?:0|[1-9][0-9]{0,4}):[0-9a-f]{64}")
MAX_SELECTION_VISITS = 2 * MAX_NODES
_KEY = object()
REF_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_JSON_SHORT = {"b": "0008", "f": "000c", "n": "000a", "r": "000d", "t": "0009"}
ERROR_MESSAGES = MappingProxyType({
    "E_FORMAT": "invalid canonical message record",
    "E_HASH": "record integrity check failed",
    "E_LIMIT": "limit exceeded; narrow the selectors",
    "E_SELECTOR": "invalid selector or cursor; check grammar or re-read without since",
    "E_REF": "invalid, unresolved or ambiguous reference; bind a store or select body/fields without refs",
    "E_SPAN": "invalid span selection",
    "E_AUTH": "store access refused: unsafe directory or platform lacks anchored file operations; use a supported real directory",
})
_SPECIAL_MESSAGES = MappingProxyType({"operation":
    "store operation unavailable; check permissions, free space, write access and file descriptor limits",
    "format": "invalid format; choose json, md or tsv",
    "private": "store access refused; use a private store directory",
    "path": "store access refused; pass a canonical absolute path",
    "resolution": "reference not found or ambiguous; use the full id or a longer handle"})
SHA = re.compile(r"[0-9a-f]{64}")
HANDLE = re.compile(r"[0-9a-f]{16,64}")
NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
INDEX = re.compile(r"0|[1-9][0-9]*")
KEYS = frozenset(("schema", "kind", "meta", "fields", "body", "spans", "refs"))


class CodecError(ValueError):
    """Fixed public error; callers serialize as_dict(), never exception context."""

    def __init__(self, code, *, detail=None):
        self.code = code if type(code) is str and code in ERROR_MESSAGES else "E_FORMAT"
        super().__init__(_SPECIAL_MESSAGES.get(detail if type(detail) is str else "", ERROR_MESSAGES[self.code]))

    def as_dict(self):
        return {"error": {"code": self.code, "message": str(self)}}


def _store_error(error, reference=False):
    if reference and isinstance(error, FileNotFoundError):
        return CodecError("E_REF", detail="resolution")
    operational = isinstance(error, OSError) and error.errno not in (
        errno.ENOENT, errno.ENOTDIR, errno.ELOOP, getattr(errno, "ESTALE", None))
    return CodecError("E_AUTH", detail="operation" if operational else None)


def _need(condition, code="E_FORMAT"):
    if not condition:
        raise CodecError(code)


def _object(required, optional=None):
    return {"type": "object", "required": required, "optional": optional or {}}


def _array(items):
    return {"type": "array", "items": items}


def _enum(*values):
    return {"type": "string", "enum": values}


STRING, INTEGER, BOOLEAN, OPAQUE = ({"type": t} for t in ("string", "integer", "boolean", "json"))
STRINGS = _array(STRING)
VERDICT = _enum("ACCEPT", "REQUEST_CHANGES", "CANNOT_REVIEW")
FINDING_REQUIRED = {
    "id": STRING, "severity": _enum("P0", "P1", "P2", "P3"), "blocking": BOOLEAN,
    "category": _enum("CORRECTNESS", "SECURITY", "FAIL_OPEN", "CONCURRENCY", "PERFORMANCE",
                      "TEST_GAP", "CONTRACT", "DOCS", "OTHER"),
    "file": STRING, "line": INTEGER, "quote": STRING, "scenario": STRING, "fix": STRING,
    "evidence": _enum("VERIFIED", "PLAUSIBLE", "SPECULATIVE"), "related": STRINGS,
}
PRIOR = _array(_object({"id": STRING, "state": _enum("FIXED", "NOT_FIXED", "PARTIAL", "NOT_APPLICABLE"),
                         "note": STRING}))
REVIEW_REQUIRED = {"reasoning_summary": STRING, "findings": _array(_object(FINDING_REQUIRED)),
                   "checked": STRINGS, "coverage_gaps": STRING, "verdict": VERDICT}
KIND_SCHEMAS = {
    "text": _object({}),
    "record": _object({"value": OPAQUE}),
    "log": _object({"rows": _array(_object({"text": STRING},
                                         {"time": STRING, "level": STRING, "data": OPAQUE}))}),
    "blob": _object({}, {"media_type": STRING, "filename": STRING}),
    "review.v1": _object(dict(REVIEW_REQUIRED, prior_findings=PRIOR)),
    "prereview.v1": _object(dict(REVIEW_REQUIRED,
        lens=_enum("WHOLE_CHANGE", "CORRECTNESS", "SECURITY", "FAIL_OPEN", "OTHER"),
        findings=_array(_object(dict(FINDING_REQUIRED, sibling_of=STRING))))),
    "handoff.v1": _object({
        "reasoning_summary": STRING, "base_head": STRING,
        "files_changed": _array(_object({"path": STRING, "change": _enum("ADDED", "MODIFIED", "DELETED"),
                                          "summary": STRING})),
        "tests": _array(_object({"phase": _enum("RED", "GREEN", "OTHER"), "command": STRING,
                                  "passed": INTEGER, "failed": INTEGER})),
        "findings_addressed": PRIOR, "assumptions": STRINGS, "open_questions": STRINGS,
        "hold_kind": _enum("NONE", "PRODUCTION_SCOPE", "ASSERTION_CONFLICT", "HASH_PINNED",
                           "DEFECT_NOT_UNDERSTOOD", "BUDGET", "OTHER"),
        "hold_reason": STRING, "status": _enum("READY_FOR_FULL", "HOLD"),
    }),
    "leadreport.v1": _object({
        "reasoning_summary": STRING, "head": STRING,
        "reviews": _array(_object({"lens": _enum("CORRECTNESS", "SECURITY", "OTHER"),
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
    _need(type(value) is str)
    _need(len(value) <= MAX_BYTES, "E_LIMIT")
    _need(_SURROGATE.search(value) is None)


class _Budget:
    """Independent output, selection staging, visit-work and I/O accounting."""
    def __init__(self, limit, parent=None):
        _need(type(limit) is int and limit >= 0, "E_LIMIT")
        self.limit, self.used, self.visits = limit, 0, 0
        self.parent = parent

    def check(self, count):
        _need(self.used + count <= self.limit, "E_LIMIT")
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
        _need(self.visits <= MAX_SELECTION_VISITS, "E_LIMIT")


def _number(value):
    if type(value) is int:
        _need(-10 ** 63 < value < 10 ** 64, "E_LIMIT")
    if type(value) is float:
        _need(math.isfinite(value))
    token = json.dumps(value, allow_nan=False)
    _need(len(token) <= MAX_NUMBER_CHARS, "E_LIMIT")
    return token


def _estimated_text(value, budget):
    _need(type(value) is str)
    cost = len(value) + 2
    budget.check(cost)
    _text(value)
    for match in _QUOTED.finditer(value):
        char = match[0]
        cost += 1 if char in '"\\\b\f\n\r\t' else 5 if ord(char) <= 0xFFFF else 11
        budget.check(cost)
    budget.charge(cost)


def _tree(value):
    pending, nodes, budget = [(value, 1)], 0, _Budget(MAX_BYTES)
    while pending:
        current, depth = pending.pop()
        nodes += 1
        _need(depth <= MAX_DEPTH and nodes <= MAX_NODES, "E_LIMIT")
        if type(current) in (dict, list):
            children = current.values() if type(current) is dict else current
            _need(nodes + len(pending) + len(current) <= MAX_NODES, "E_LIMIT")
            budget.charge(2 + max(0, len(current) - 1))
            if type(current) is dict:
                for key in current:
                    _need(type(key) is str and 0 < len(key) <= 256)
                    _estimated_text(key, budget)
                    budget.charge(1)
            pending.extend((child, depth + 1) for child in children)
        elif type(current) is str:
            _estimated_text(current, budget)
        else:
            _need(current is None or type(current) in (int, float, bool))
            token = ("null" if current is None else "true" if current is True else
                     "false" if current is False else _number(current))
            budget.charge(len(token))


def _validate_type(value, schema):
    kind = schema["type"]
    if kind == "json":
        return
    if kind == "object":
        _need(type(value) is dict)
        required, optional = schema["required"], schema["optional"]
        _need(required.keys() <= value.keys() and value.keys() <= required.keys() | optional.keys())
        for key, child in value.items():
            _validate_type(child, required[key] if key in required else optional[key])
    elif kind == "array":
        _need(type(value) is list)
        for child in value:
            _validate_type(child, schema["items"])
    else:
        _need(type(value) is {"string": str, "integer": int, "boolean": bool}[kind])
        if "enum" in schema:
            _need(value in schema["enum"])


def _validate(value):
    _tree(value)
    _need(type(value) is dict and value.keys() == KEYS)
    _need(value["schema"] == SCHEMA and type(value["kind"]) is str)
    _need(value["kind"] in KIND_SCHEMAS)
    _validate_type(value["meta"], _object({k: STRING for k in ("from", "host", "session", "created_at")}))
    _validate_type(value["fields"], KIND_SCHEMAS[value["kind"]])
    _need(type(value["body"]) is str and type(value["spans"]) is list and type(value["refs"]) is dict)
    _need(len(value["refs"]) <= MAX_REFS, "E_LIMIT")
    for name, rid in value["refs"].items():
        _need(REF_NAME.fullmatch(name) is not None)
        _need(type(rid) is str and SHA.fullmatch(rid) is not None)
    for span in value["spans"]:
        _need(type(span) is list and len(span) == 3)
        start, end, title = span
        _need(type(start) is int and type(end) is int and type(title) is str)
        _need(0 <= start <= end <= len(value["body"]))


def _escape_char(char):
    # Cn stays escaped fail-closed even when Unicode database versions differ.
    if unicodedata.category(char) not in {"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"} and not _EXPLICIT.fullmatch(char):
        return char
    return "\\u%04x" % ord(char) if ord(char) <= 0xFFFF else json.dumps(char, ensure_ascii=True)[1:-1]


def _neutral(text, json_text=False):
    if json_text:
        text = _JSON_ESC.sub(lambda m: "\\u" + _JSON_SHORT[m[0][1]] if m[0][1:] in _JSON_SHORT else m[0], text)
    if text.isascii() and text.isprintable() or text.isprintable() and not _EXPLICIT.search(text):
        return text
    return _DISPLAY.sub(lambda m: _escape_char(m[0]), text)


def _strings(value, ascii=True, display=False):
    yield '"'
    for start in range(0, len(value), 128):
        text = json.dumps(value[start:start + 128], ensure_ascii=ascii, allow_nan=False)[1:-1]
        yield _neutral(text, json_text=True) if display else text
    yield '"'


def _put(text, position):
    position[0] += len(text)
    yield text


def _chunks(value, ascii=True, display=False, ranges=None, path=(), position=None):
    position = [0] if position is None else position
    start = position[0]
    if type(value) is dict:
        yield from _put("{", position)
        for index, key in enumerate(sorted(value) if ascii else value):
            if index:
                yield from _put(",", position)
            key_start = position[0]
            for chunk in _strings(key, ascii, display):
                yield from _put(chunk, position)
            if ranges is not None and path + (_KEY, key) in ranges:
                ranges[path + (_KEY, key)] = (key_start, position[0])
            yield from _put(":", position)
            yield from _chunks(value[key], ascii, display, ranges, path + (key,), position)
        yield from _put("}", position)
    elif type(value) is list:
        yield from _put("[", position)
        for index, child in enumerate(value):
            if index:
                yield from _put(",", position)
            yield from _chunks(child, ascii, display, ranges, path + (index,), position)
        yield from _put("]", position)
    else:
        pieces = _strings(value, ascii, display) if type(value) is str else (
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
    """Validate and encode exactly like the mailbox, in bounded scalar chunks."""
    _validate(value)
    return _collect(_chunks(value), _Budget(MAX_BYTES)).encode("utf-8")


def _tokens(text):
    index = 0
    while index < len(text):
        match = _TOKEN.match(text, index)
        _need(match is not None)
        kind, start, index = match.lastgroup, index, match.end()
        if kind == "space":
            continue
        token = match[0]
        if kind == "atom":
            _need(token in ("null", "true", "false") or NUMBER.fullmatch(token) is not None)
            _need(token[0] not in "-0123456789" or len(token) <= MAX_NUMBER_CHARS, "E_LIMIT")
        yield token if kind == "mark" else "string" if kind == "string" else "scalar", start, index


def _preflight(text):
    """Bound value starts/ref keys before json.loads builds any containers."""
    stack, nodes, seen = [], 0, False
    for token, start, stop in _tokens(text):
        frame = stack[-1] if stack else None
        state = frame["state"] if frame else None
        if token in ("}", "]"):
            _need(frame is not None and frame["op"] == ("{" if token == "}" else "["))
            _need(state in ("after", "first_key", "first_value"))
            stack.pop()
            continue
        if token == ",":
            _need(frame is not None and state == "after")
            frame["state"] = "key" if frame["op"] == "{" else "value"
            continue
        if token == ":":
            _need(frame is not None and state == "colon")
            frame["state"] = "value"
            continue
        if frame and state in ("key", "first_key"):
            _need(token == "string")
            frame["count"] += 1
            _need(not frame["refs"] or frame["count"] <= MAX_REFS, "E_LIMIT")
            key = json.decoder.scanstring(text, start + 1, True)[0]
            _text(key)
            frame["key"], frame["state"] = key, "colon"
            continue
        _need((frame is not None and state in ("value", "first_value")) or (frame is None and not seen))
        nodes += 1
        _need(nodes <= MAX_NODES and len(stack) + 1 <= MAX_DEPTH, "E_LIMIT")
        seen = True
        if frame:
            frame["state"] = "after"
        if token in ("{", "["):
            is_refs = len(stack) == 1 and frame["op"] == "{" and frame.get("key") == "refs"
            stack.append({"op": token, "state": "first_key" if token == "{" else "first_value",
                          "refs": is_refs, "count": 0})
    _need(seen and not stack)


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result)
        result[key] = value
    return result


def _nonfinite(_value):
    raise CodecError("E_FORMAT")


def parse(data):
    """Bytes only; byte/node/ref/depth/numeric bounds precede container decoding."""
    _need(type(data) is bytes)
    _need(len(data) <= MAX_BYTES, "E_LIMIT")
    try:
        text = data.decode("utf-8")
        _preflight(text)
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        _need(canonical(value) == data)
        return value
    except (UnicodeError, ValueError, OverflowError) as exc:
        if isinstance(exc, CodecError):
            raise
        raise CodecError("E_FORMAT") from None


def record_id(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _at(fd, *names):
    _need(type(fd) is int and fd >= 0, "E_AUTH")
    return {name: fd for name in names or ("dir_fd",)}


def _release(fd):
    with suppress(OSError):  # A failed close may already release the number; never retry.
        os.close(fd)


class Store:
    """Existing caller-bound root; all entry operations require anchored primitives."""
    def __init__(self, root):
        self.fd = None
        self._lock = Lock()
        try:
            capabilities = {function.__name__ for function in os.supports_dir_fd}
            _need({"open", "stat", "link", "unlink"} <= capabilities and
                  hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"), "E_AUTH")
            _need(type(root) in (str, Path) or isinstance(root, Path), "E_AUTH")
            given = Path(root)
            if not given.is_absolute() or ".." in given.parts:
                raise CodecError("E_AUTH", detail="path")
            before = given.lstat()
            _need(stat.S_ISDIR(before.st_mode), "E_AUTH")
            self.root = given.resolve(strict=True)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            self.fd = os.open(self.root.anchor, flags)
            for component in self.root.parts[1:]:
                child = os.open(component, flags, **_at(self.fd))
                parent, self.fd = self.fd, child
                os.close(parent)
            info = os.fstat(self.fd)
            self._identity = (info.st_dev, info.st_ino)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise CodecError("E_AUTH", detail="private")
            _need((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino), "E_AUTH")
            self._finalizer = weakref.finalize(self, _release, self.fd)
        except (OSError, ValueError, RuntimeError) as error:
            fd, self.fd = self.fd, None
            if fd is not None:
                _release(fd)
            if isinstance(error, CodecError):
                raise
            raise _store_error(error) from None

    def close(self):
        with self._lock:
            fd, self.fd = self.fd, None
            if fd is not None:
                self._finalizer.detach()
                _release(fd)

    @contextmanager
    def _directory(self):
        with self._lock:
            try:
                fd = self.fd
                _need(type(fd) is int, "E_AUTH")
                info = os.fstat(fd)
                _need(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == self._identity, "E_AUTH")
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise CodecError("E_AUTH", detail="private")
                yield fd
            except (OSError, ValueError, RuntimeError) as exc:
                if isinstance(exc, CodecError):
                    raise
                raise _store_error(exc, reference=True) from None

    def _open(self, name, flags, rootfd):
        flags |= os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(name, flags, 0o600, **_at(rootfd))
        try:
            _need(stat.S_ISREG(os.fstat(fd).st_mode), "E_AUTH")
            return fd
        except BaseException:
            _release(fd)
            raise

    def resolve(self, reference):
        with self._directory() as rootfd:
            return self._resolve(reference, rootfd)

    def _resolve(self, reference, rootfd):
        _need(type(reference) is str and HANDLE.fullmatch(reference) is not None, "E_REF")
        matches = [reference] if len(reference) == 64 else []
        if not matches:
            scan_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, **_at(rootfd))
            try:
                with os.scandir(scan_fd) as entries:
                    for entry in entries:
                        name = entry.name
                        if len(name) == 69 and name.endswith(".json") and SHA.fullmatch(name[:64]) and name[:64].startswith(reference):
                            matches.append(name[:64])
                            if len(matches) == 2:
                                break
            finally:
                os.close(scan_fd)
        if len(matches) != 1:
            raise CodecError("E_REF", detail="resolution")
        _need(stat.S_ISREG(os.stat(matches[0] + ".json", follow_symlinks=False, **_at(rootfd)).st_mode), "E_AUTH")
        return matches[0]

    def _read_bytes(self, rid, rootfd, budget=None, expected_size=None):
        fd = self._open(rid + ".json", os.O_RDONLY, rootfd)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if expected_size is not None:
                _need(before.st_size == expected_size, "E_HASH")
            _need(before.st_size <= MAX_BYTES, "E_LIMIT")
            if budget is not None:
                budget.check(before.st_size)
            chunks, size = [], 0
            while True:
                count = min(4096, MAX_BYTES + 1 - size)
                if budget is not None:
                    count = min(count, max(1, budget.limit - budget.used + 1))
                chunk = stream.read(count)
                if not chunk:
                    break
                size += len(chunk)
                _need(size <= MAX_BYTES, "E_LIMIT")
                if budget is not None:
                    budget.charge(len(chunk))
                chunks.append(chunk)
            after = os.fstat(stream.fileno())
            # Link-count/ctime changes during publication do not alter content.
            _need((before.st_dev, before.st_ino, before.st_size) ==
                  (after.st_dev, after.st_ino, after.st_size), "E_HASH")
        data = b"".join(chunks)
        _need(len(data) == before.st_size and hashlib.sha256(data).hexdigest() == rid, "E_HASH")
        return data, len(data)

    def _verified(self, reference, budget, describe=False):
        _need(budget is None or type(budget) is _Budget, "E_LIMIT")
        with self._directory() as rootfd:
            rid = self._resolve(reference, rootfd)
            data, size = self._read_bytes(rid, rootfd, budget)
            value = parse(data)
            if not describe:
                return value
            return {"ref": rid[:16], "kind": value["kind"], "chars": size}

    def read(self, reference, *, _budget=None):
        return self._verified(reference, _budget)

    def describe(self, reference, *, _budget=None):
        """Verify actual bytes, canonical encoding and schema on every call."""
        return self._verified(reference, _budget, describe=True)

    def write(self, value):
        data = canonical(value)
        rid = hashlib.sha256(data).hexdigest()
        with self._directory() as rootfd:
            try:
                _need(self._read_bytes(rid, rootfd, expected_size=len(data))[0] == data, "E_HASH")
                return rid
            except FileNotFoundError:
                pass
            name, temporary = rid + ".json", ".msg-" + uuid.uuid4().hex
            fd = self._open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, rootfd)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, name, follow_symlinks=False, **_at(rootfd, "src_dir_fd", "dst_dir_fd"))
                except FileExistsError:
                    pass  # Existing bytes receive exactly the same verification.
                _need(self._read_bytes(rid, rootfd, expected_size=len(data))[0] == data, "E_HASH")
                os.fsync(rootfd)
            finally:
                with suppress(OSError):  # Cleanup never replaces the original refusal.
                    os.unlink(temporary, **_at(rootfd))
                with suppress(OSError):
                    os.fsync(rootfd)
        return rid


def _selector(selector):
    _need(type(selector) is str and 0 < len(selector) <= 1024, "E_SELECTOR")
    parts = selector.split(".")
    _need(len(parts) <= 8 and all(parts), "E_SELECTOR")
    for index, part in enumerate(parts):
        if part.startswith("{") and part.endswith("}"):
            keys = part[1:-1].split(",")
            _need(index == len(parts) - 1 and index > 0 and parts[index - 1] == "*", "E_SELECTOR")
            _need(all(NAME.fullmatch(k) for k in keys) and len(set(keys)) == len(keys), "E_SELECTOR")
        else:
            _need(part == "*" or NAME.fullmatch(part) or REF_NAME.fullmatch(part) or INDEX.fullmatch(part), "E_SELECTOR")
    return parts


def _record_schema(kind):
    return _object({"schema": STRING, "kind": STRING, "body": STRING, "fields": KIND_SCHEMAS[kind],
                    "meta": _object({k: STRING for k in ("from", "host", "session", "created_at")}),
                    "spans": _array({"type": "tuple", "items": [INTEGER, INTEGER, STRING]}),
                    "refs": {"type": "mapping", "items": STRING, "keys": REF_NAME}})


def _children(schema):
    return dict(schema["required"], **schema["optional"])


def _schema_path(schema, parts):
    if not parts:
        return
    part, rest = parts[0], parts[1:]
    kind = schema["type"]
    if part.startswith("{"):
        _need(kind == "object", "E_SELECTOR")
        for key in part[1:-1].split(","):
            _schema_path(schema, [key])
    elif kind in ("object", "mapping"):
        children = _children(schema) if kind == "object" else None
        _need(children is not None or part == "*" or schema["keys"].fullmatch(part), "E_SELECTOR")
        if part == "*" and children is not None:
            _need(bool(children), "E_SELECTOR")
            for child in children.values():
                _schema_path(child, rest)
        else:
            _need(children is None or part in children, "E_SELECTOR")
            _schema_path(schema["items"] if children is None else children[part], rest)
    elif kind in ("array", "tuple"):
        _need(part == "*" or (INDEX.fullmatch(part) and len(part) <= 5), "E_SELECTOR")
        if kind == "array":
            _schema_path(schema["items"], rest)
        else:
            indices = range(len(schema["items"])) if part == "*" else [int(part)]
            for index in indices:
                _need(index < len(schema["items"]), "E_SELECTOR")
                _schema_path(schema["items"][index], rest)
    else:
        raise CodecError("E_SELECTOR")


class _Coverage:
    """Retain only budgeted selected paths; compute source offsets lazily."""
    def __init__(self, value, budget, page=None, transformed=False):
        self.value, self.budget, self.page = value, budget, page
        self.transformed, self.names, self.wildcards = transformed, set(), set()
        self.ranges, self.paths, self.spans, self.absent = {}, set(), [], set()

    def source(self, path):
        if self.page is not None and path[:2] == ("fields", "rows") and len(path) > 2:
            return path[:2] + (path[2] + self.page[0],) + path[3:]
        return path

    def add(self, path):
        if self.page is not None and path in ((), ("fields",), ("fields", "rows")):
            for index in range(self.page[1] - self.page[0]):
                self.add(("fields", "rows", index))
            return
        path = self.source(path)
        if self.transformed and path[:1] == ("refs",):
            if len(path) == 1:
                for name in self.names:
                    self._add(("refs", _KEY, name))
            return
        self._add(path)

    def _add(self, path):
        if path not in self.paths:
            self.budget.stage(2)
            self.paths.add(path)
            self.ranges[path] = None

    def span(self, start, end):
        self.budget.stage(2)
        self.spans.append((start, end))
        self.ranges.setdefault(("body",), None)

    def omitted(self, size):
        if self.spans:
            self.budget.charge(len(self.value["body"]))
        for _chunk in _chunks(self.value, ranges=self.ranges):
            pass
        intervals = [self.ranges[path] for path in self.paths]
        if self.spans:
            offsets, previous, position = {}, 0, self.ranges[("body",)][0] + 1
            for boundary in sorted({point for span in self.spans for point in span}):
                position += sum(len(c) for c in _strings(self.value["body"][previous:boundary])) - 2
                offsets[boundary], previous = position, boundary
            intervals.extend((offsets[start], offsets[end]) for start, end in set(self.spans))
        covered, end = 0, 0
        for start, stop in sorted(intervals):
            covered += max(0, stop - max(start, end))
            end = max(end, stop)
        return size - covered


_MISSING = object()


def _child(value, schema, key, rest, path, missing, coverage, budget):
    budget.visit()
    if (type(value) is list and key >= len(value)) or (type(value) is dict and key not in value):
        concrete = coverage.source(path + (key,) + tuple(rest))
        source = tuple("*" if type(p) is int and i in coverage.wildcards else p for i, p in enumerate(concrete))
        budget.stage(sum(len(str(p)) for p in source) + len(source) + 2)
        label = ".".join(str(p) for p in source)
        if (label, concrete) not in coverage.absent:
            budget.stage(2)
            coverage.absent.add((label, concrete))
            missing[label] = missing.get(label, 0) + 1
        return _MISSING
    kind = schema["type"]
    child_schema = (_children(schema)[key] if kind == "object" else
                    schema["items"][key] if kind == "tuple" else schema["items"])
    return _select(value[key], child_schema, rest, path + (key,), missing, coverage, budget)


def _select(value, schema, parts, path, missing, coverage, budget):
    budget.visit()
    if not parts:
        coverage.add(path)
        for chunk in _chunks(value, ascii=False, display=True):
            budget.stage(len(chunk))
        return value
    part, rest = parts[0], parts[1:]
    kind = schema["type"]
    if part.startswith("{"):
        budget.stage(2)
        result = {}
        for key in part[1:-1].split(","):
            child = _child(value, schema, key, rest, path, missing, coverage, budget)
            if child is not _MISSING:
                budget.stage(len(key) + 3)
                result[key] = child
        return result
    if part == "*":
        keys = (_children(schema) if kind == "object" else value.keys() if kind == "mapping"
                else range(len(value)))
        budget.stage(2)
        mapping = kind in ("object", "mapping")
        result = {} if mapping else []
        if kind == "mapping":
            coverage.add(path)
        for key in keys:  # Literal keys never re-enter selector interpretation.
            child = _child(value, schema, key, rest, path, missing, coverage, budget)
            if child is _MISSING and kind == "array" and rest:
                child = None  # Keep every row position; missing records absence.
                budget.stage(4)
            if child is not _MISSING:
                budget.stage(1)
                if mapping:
                    result[key] = child
                else:
                    result.append(child)
        return result
    return _child(value, schema, int(part) if type(value) is list else part,
                  rest, path, missing, coverage, budget)


def _outline(value):
    fields = {}
    for key, child in value["fields"].items():
        if type(child) in (list, dict):
            fields[key] = {"type": "array" if type(child) is list else "object", "items": len(child)}
        elif type(child) is str:
            fields[key] = {"type": "string", "chars": len(child)}
        else:
            fields[key] = {"type": "null" if child is None else "boolean" if type(child) is bool else "number"}
    return {"fields": fields, "body_chars": len(value["body"]),
            "spans": [{"n": i, "title": title if len(title) <= 64 else {"chars": len(title)}, "chars": end - start}
                      for i, (start, end, title) in enumerate(value["spans"][:64])],
            "more": max(0, len(value["spans"]) - 64),
            "selectors": sorted(KEYS) + ["fields." + key for key in value["fields"]]}


def _refs(value, store, expand, work, names, max_chars):
    _need(not value["refs"] or type(store) is Store, "E_REF")
    result, cache, io, rendered = {}, {}, _Budget(MAX_REF_BYTES), _Budget(max_chars)
    expanded_ids = {value["refs"][name] for name in expand}
    for name, rid in value["refs"].items():
        if name not in names:
            continue
        if rid not in cache:
            io.parent = work if rid in expanded_ids else None
            # ASCII canonical escapes use at most 12 bytes per display character.
            io.limit = min(MAX_REF_BYTES, io.used + 12 * (rendered.limit - rendered.used)) if io.parent else MAX_REF_BYTES
            before = io.used
            child = store.read(rid, _budget=io) if io.parent else store.describe(rid, _budget=io)
            descriptor = {"ref": rid[:16], "kind": child["kind"], "chars": io.used - before} if io.parent else child
            cache[rid] = (child, descriptor)
        child, descriptor = cache[rid]
        if name in expand:
            for chunk in _chunks(child, ascii=False, display=True):
                rendered.charge(len(chunk))
        result[name] = child if name in expand else descriptor
    return result


def _prefix(rows, n):
    digest = hashlib.sha256()
    for chunk in _chunks(rows[:n]):
        digest.update(chunk.encode("ascii"))
    return str(n) + ":" + digest.hexdigest()


def _page(value, cursor, row_limit):
    _need(value["kind"] == "log", "E_SELECTOR")
    rows = value["fields"]["rows"]
    offset = 0 if cursor == "0" else int(cursor.partition(":")[0])
    _need(offset <= len(rows) and (cursor == "0" or _prefix(rows, offset) == cursor), "E_SELECTOR")
    stop = min(len(rows), offset + row_limit) if row_limit is not None else len(rows)
    return dict(value, fields=dict(value["fields"], rows=rows[offset:stop])), (offset, stop), _prefix(rows, stop)


def _md(value, max_chars):
    payload = _collect(_chunks(value, ascii=False, display=True), _Budget(max_chars))
    width = max(3, 1 + max((m.end() - m.start() for m in re.finditer(r"`+", payload)), default=0))
    header = value["ref"] + " " + value["kind"] + " untrusted omitted_chars=" + str(value["omitted_chars"]) + "\n"
    _need(len(header) + len(payload) + 2 * width + len("json untrusted\n\n") <= max_chars, "E_LIMIT")
    for text, count in ((header, 1), ("`", width), ("json untrusted\n", 1), (payload, 1), ("\n", 1), ("`", width)):
        for start in range(0, len(text) * count, 128):
            yield text[start:start + 128] if count == 1 else text * min(128, count - start)


def _tsv(view):
    items = [(k, v) for k, v in view.items() if k != "data"] + [(None, None)] + list(view["data"].items())
    for key, value in items:
        if key is None:
            yield "#data\n"
            continue
        table = type(value) is list and bool(value) and all(type(row) is dict for row in value)
        yield "#table\t" if table else "@key\t"
        yield from _chunks(key, ascii=False, display=True)
        if table:
            yield "\trows=" + str(len(value)) + "\n@columns"
            columns = sorted({column for row in value for column in row})
            for column in columns:
                yield "\t"
                yield from _chunks(column, ascii=False, display=True)
            for row in value:
                yield "\n@row"
                for column in columns:
                    yield "\t"
                    if column in row:
                        yield from _chunks(row[column], ascii=False, display=True)
            yield "\n#endtable\n"
        else:
            yield "\t"
            yield from _chunks(value, ascii=False, display=True)
            yield "\n"


def _render(view, format, budget):
    chunks = _chunks(view, ascii=False, display=True) if format == "json" else _tsv(view) if format == "tsv" else _md(view, budget.limit)
    return _collect(chunks, budget)


def _options(value, selectors, spans, expand, since, row_limit, outline, format, max_chars, store, unknown):
    """Validate all caller values before content hashing, sets or I/O."""
    _need(type(expand) in (list, tuple) and len(expand) <= MAX_REFS, "E_REF")
    _need(all(type(n) is str and REF_NAME.fullmatch(n) for n in expand), "E_REF")
    _need(store is None or type(store) is Store, "E_REF")
    _need(type(selectors) in (list, tuple) and len(selectors) <= 16, "E_SELECTOR")
    _need(type(spans) in (list, tuple) and len(spans) <= MAX_SPANS, "E_SPAN")
    _need(all(type(n) is int and 0 <= n < MAX_NODES for n in spans), "E_SPAN")
    _need(since is None or (type(since) is str and len(since) <= 70 and
                           (since == "0" or _CURSOR.fullmatch(since))), "E_SELECTOR")
    _need(row_limit is None or (type(row_limit) is int and 1 <= row_limit <= MAX_NODES), "E_LIMIT")
    _need((since is not None or row_limit is None) and type(outline) is bool and not unknown, "E_SELECTOR")
    if type(format) is not str or format not in ("json", "md", "tsv"):
        raise CodecError("E_FORMAT", detail="format")
    _need(type(max_chars) is int and 0 <= max_chars <= MAX_OUTPUT_CHARS, "E_LIMIT")
    planned = {}
    for selector in selectors:
        parts = _selector(selector)
        parts = parts if parts[0] in KEYS else ["fields"] + parts
        if type(value) is dict and type(value.get("kind")) is str and value["kind"] in KIND_SCHEMAS:
            _schema_path(_record_schema(value["kind"]), parts)
        _need(tuple(parts) not in planned, "E_SELECTOR")
        planned[tuple(parts)] = selector
    _need(not expand or (type(value) is dict and type(value.get("refs")) is dict and
                         all(name in value["refs"] for name in expand)), "E_REF")
    return planned


def read_view(value, *, selectors=(), spans=(), outline=False, since=None, row_limit=None,
              expand=(), store=None, format="json", max_chars=60000, **unknown):
    """Total for data inputs, including unknown options; wrong arity is programmer error."""
    planned = _options(value, selectors, spans, expand, since, row_limit, outline, format, max_chars, store, unknown)
    output, budget = _Budget(max_chars), _Budget(MAX_WORK_BYTES)
    raw = canonical(value)
    _need(all(index < len(value["spans"]) for index in spans), "E_SPAN")
    rid = hashlib.sha256(raw).hexdigest()
    page, cursor, original = None, None, value
    if since is not None:
        value, page, cursor = _page(value, since, row_limit)
    coverage, schema = _Coverage(original, budget, page, bool(value["refs"])), _record_schema(value["kind"])
    data, missing = {}, {}
    default = not (selectors or spans or since is not None)
    include_refs = default or bool(expand) or any(parts[0] == "refs" for parts in planned)
    if include_refs:
        paths = [parts for parts in planned if parts[0] == "refs"]
        names = (set(value["refs"]) if default or any(len(p) == 1 or p[1] == "*" for p in paths)
                 else {p[1] for p in paths} | set(expand))
        coverage.names = names & value["refs"].keys()
        value = dict(value, refs=_refs(value, store, expand, budget, names, max_chars))
    for parts, selector in planned.items():
        coverage.wildcards = {i for i, part in enumerate(parts) if part == "*"}
        selected = _select(value, schema, parts, (), missing, coverage, budget)
        if selected is not _MISSING:
            data[selector] = selected
    for index in dict.fromkeys(spans):
        start, end, _title = value["spans"][index]
        budget.stage(end - start)
        data["span:" + str(index)] = value["body"][start:end]
        coverage.span(start, end)
    whole = not (selectors or spans or since is not None or outline) and len(raw) <= 4000
    if whole:
        data = dict(value)
        coverage.add(()) if not value["refs"] or store is None else None
    elif since is not None and not selectors and not spans:
        data = {"rows": value["fields"]["rows"]}
        coverage.add(("fields", "rows"))
    elif not selectors and not spans:
        data = {key: value[key] for key in ("schema", "kind")}
        data["fields"] = {key: item for key, item in value["fields"].items() if type(item) not in (dict, list)}
        outline = True
    if not selectors and since is None and not spans:
        for key in data:
            if key == "fields":
                for field in data[key]:
                    coverage.add(("fields", field))
            elif key != "refs":
                coverage.add((key,))
    if include_refs and (default or expand):
        data["refs"] = value["refs"]
        coverage.add(("refs",))
    view = {"ref": rid[:16], "kind": value["kind"], "from": value["meta"]["from"],
            "untrusted": True, "omitted_chars": coverage.omitted(len(raw)), "data": data}
    if cursor is not None:
        view["cursor"] = cursor
    if missing:
        view["missing"] = [{"path": path, "count": count} for path, count in missing.items()]
    if outline:
        view["outline"] = _outline(original)
    return _render(view, format, output)
