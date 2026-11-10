"""Stdlib-only view plans and preflighted renderers for aegis.msg/1 (ADR A2).

Plans hold source references, never materialized span strings or projected rows.
Every formatter measures its complete output before emission. String fragments
reserve their escaped size before slicing/json.dumps; joins follow that reservation.
The codec supplies its fixed-error and closed-character escape functions explicitly.
"""
import hashlib
import json
import re


__all__ = ["Text", "Join", "Object", "Array", "Rows", "Renderer", "outline", "page"]
_SPECIAL = re.compile(r'["\\\x00-\x1f\x7f-\U0010ffff]')
_RUN = re.compile(r"`+")
_MISSING = object()


class Text:
    def __init__(self, source, start=0, stop=None):
        self.source, self.start = source, start
        self.stop = len(source) if stop is None else stop

    def pieces(self):
        yield self.source, self.start, self.stop


class Join:
    def __init__(self, parts, separator="."):
        self.parts, self.separator = parts, separator

    def pieces(self):
        for index, part in enumerate(self.parts):
            if index:
                yield self.separator, 0, len(self.separator)
            text = part if type(part) is str else str(part)
            yield text, 0, len(text)


class Object:
    def __init__(self, factory):
        self.factory = factory

    def items(self):
        return self.factory()

    def get(self, wanted, default=None):
        for key, value in self.items():
            if key == wanted:
                return value
        return default


class Array:
    def __init__(self, factory, length):
        self.factory, self.length = factory, length

    def __len__(self):
        return self.length

    def __iter__(self):
        return iter(self.factory())


class Rows:
    def __init__(self, source, start, stop):
        self.source, self.start, self.stop = source, start, stop

    def __len__(self):
        return self.stop - self.start

    def __getitem__(self, index):
        return self.source[self.start + index]

    def __iter__(self):
        for index in range(self.start, self.stop):
            yield self.source[index]


def _object(value):
    return type(value) is dict or isinstance(value, Object)


def _array(value):
    return type(value) is list or isinstance(value, (Array, Rows))


def _pieces(value):
    if type(value) is str:
        yield value, 0, len(value)
    else:
        yield from value.pieces()


class Renderer:
    def __init__(self, need, escape, neutral, limit):
        self.need, self.escape, self.neutral = need, escape, neutral
        self.limit = limit

    def text_size(self, value, start=0, stop=None, ascii=False):
        stop = len(value) if stop is None else stop
        size = stop - start + 2
        for match in _SPECIAL.finditer(value, start, stop):
            char = match[0]
            if char in '"\\\b\f\n\r\t':
                cost = 2
            elif ascii:
                cost = 2 if char in '\b\f\n\r\t' else 6 if ord(char) <= 0xFFFF else 12
            else:
                cost = 6 if ord(char) < 32 else len(self.escape(char))
            size += cost - 1
        run = max((m.end() - m.start() for m in _RUN.finditer(value, start, stop)), default=0)
        return size, run

    def _json(self, value):
        if type(value) is str or isinstance(value, (Text, Join)):
            yield "string", value
        elif _object(value):
            yield "raw", "{"
            for index, (key, child) in enumerate(value.items()):
                if index:
                    yield "raw", ","
                yield "string", key
                yield "raw", ":"
                yield from self._json(child)
            yield "raw", "}"
        elif _array(value):
            yield "raw", "["
            for index, child in enumerate(value):
                if index:
                    yield "raw", ","
                yield from self._json(child)
            yield "raw", "]"
        else:
            self.need(value is None or type(value) in (int, float, bool))
            token = "null" if value is None else "true" if value is True else "false" if value is False else repr(value)
            yield "raw", token

    def _size(self, token):
        kind, value = token
        if kind == "string":
            size, run = 2, 0
            for source, start, stop in _pieces(value):
                count, inner = self.text_size(source, start, stop)
                size += count - 2
                run = max(run, inner)
            return size, run
        if kind == "repeat":
            return value, value
        if kind == "range":
            return value.stop - value.start, 0
        return len(value), 0

    def _measure(self, tokens, limit):
        size, run = 0, 0
        self.remaining = limit
        for token in tokens:
            count, inner = self._size(token)
            self.need(size + count <= limit, "E_LIMIT")
            size, run = size + count, max(run, inner)
            self.remaining = limit - size
        return size, run

    def json_size(self, value, limit=None):
        return self._measure(self._json(value), self.limit if limit is None else limit)[0]

    def _columns(self, value, remaining):
        columns, cost = set(), 0
        for row in value:
            for key, _child in row.items():
                if key not in columns:
                    size = self._size(("string", key))[0] + 1
                    self.need(cost + size <= remaining, "E_LIMIT")
                    cost += size
                    columns.add(key)
        return sorted(columns)

    def _tsv(self, view):
        for key, value in view.items():
            if key != "data":
                yield "raw", "@key\t"
                yield "string", key
                yield "raw", "\t"
                yield from self._json(value)
                yield "raw", "\n"
        if "data" not in view:
            return
        yield "raw", "#data\n"
        for key, value in view["data"].items():
            table = _array(value) and len(value) > 0 and all(_object(row) for row in value)
            yield "raw", "#table\t" if table else "@key\t"
            yield "string", key
            if table:
                yield "raw", "\trows=" + str(len(value)) + "\n@columns"
                columns = self._columns(value, self.remaining)
                for column in columns:
                    yield "raw", "\t"
                    yield "string", column
                for row in value:
                    yield "raw", "\n@row"
                    for column in columns:
                        yield "raw", "\t"
                        entry = row.get(column, _MISSING)
                        if entry is not _MISSING:
                            yield from self._json(entry)
                yield "raw", "\n#endtable\n"
            else:
                yield "raw", "\t"
                yield from self._json(value)
                yield "raw", "\n"

    def _md(self, view):
        size, run = self._measure(self._json(view), self.limit)
        width = max(3, run + 1)
        header = (("range", view["ref"]), ("raw", " " + view["kind"] + " untrusted omitted_chars="),
                  ("raw", str(view["omitted_chars"]) + "\n"))
        count = sum(self._size(token)[0] for token in header) + 2 * width + len("json untrusted\n\n") + size
        self.need(count <= self.limit, "E_LIMIT")
        yield from header
        yield "repeat", width
        yield "raw", "json untrusted\n"
        yield from self._json(view)
        yield "raw", "\n"
        yield "repeat", width

    def measure(self, view, format):
        tokens = self._json(view) if format == "json" else self._md(view) if format == "md" else self._tsv(view)
        return self._measure(tokens, self.limit)[0]

    def _emit_string(self, value, reserve):
        reserve(1)
        yield '"'
        for source, begin, end in _pieces(value):
            for start in range(begin, end, 128):
                stop = min(end, start + 128)
                reserve(self.text_size(source, start, stop)[0] - 2)
                encoded = json.dumps(source[start:stop], ensure_ascii=False, allow_nan=False)[1:-1]
                yield self.neutral(encoded)
        reserve(1)
        yield '"'

    def render(self, view, format):
        expected = self.measure(view, format)
        tokens = self._json(view) if format == "json" else self._md(view) if format == "md" else self._tsv(view)
        parts, used = [], 0
        self.remaining = self.limit
        def reserve(count):
            nonlocal used
            self.need(used + count <= self.limit, "E_LIMIT")
            used += count
            self.remaining = self.limit - used
        for kind, value in tokens:
            if kind == "string":
                parts.extend(self._emit_string(value, reserve))
            elif kind == "repeat":
                for start in range(0, value, 128):
                    count = min(128, value - start)
                    reserve(count)
                    parts.append("`" * count)
            else:
                source, begin, end = (value.source, value.start, value.stop) if kind == "range" else (value, 0, len(value))
                for start in range(begin, end, 128):
                    stop = min(end, start + 128)
                    reserve(stop - start)
                    parts.append(source[start:stop])
        self.need(used == expected and used <= self.limit, "E_LIMIT")
        return "".join(parts)


def outline(value, keys):
    fields = {}
    for key, child in value["fields"].items():
        if type(child) in (list, dict):
            fields[key] = {"type": "array" if type(child) is list else "object", "items": len(child)}
        elif type(child) is str:
            fields[key] = {"type": "string", "chars": len(child)}
        else:
            fields[key] = {"type": "null" if child is None else "boolean" if type(child) is bool else "number"}
    def spans():
        for index in range(min(64, len(value["spans"]))):
            start, end, title = value["spans"][index]
            yield {"n": index, "title": title if len(title) <= 64 else {"chars": len(title)}, "chars": end - start}
    def selectors():
        yield from sorted(keys)
        for key in value["fields"]:
            yield Join(("fields", key))
    return {"fields": fields, "body_chars": len(value["body"]),
            "spans": Array(spans, min(64, len(value["spans"]))),
            "more": max(0, len(value["spans"]) - 64),
            "selectors": Array(selectors, len(keys) + len(value["fields"]))}


def _prefix(rows, start, stop, chunks, digest):
    """Extend an open canonical array; close only a copy at this boundary."""
    for index in range(start, stop):
        if index:
            digest.update(b",")
        for chunk in chunks(rows[index]):
            digest.update(chunk.encode("ascii"))
    closed = digest.copy()
    closed.update(b"]")
    return closed.hexdigest()


def page(value, cursor, row_limit, chunks, need):
    need(value["kind"] == "log", "E_SELECTOR")
    rows = value["fields"]["rows"]
    offset = 0 if cursor == "0" else int(cursor.partition(":")[0])
    need(offset <= len(rows), "E_SELECTOR")
    stop = min(len(rows), offset + row_limit) if row_limit is not None else len(rows)
    digest = hashlib.sha256(b"[")
    previous = _prefix(rows, 0, offset, chunks, digest)
    need(cursor == "0" or previous == cursor.partition(":")[2], "E_SELECTOR")
    current = previous if stop == offset else _prefix(rows, offset, stop, chunks, digest)
    return dict(value, fields=dict(value["fields"], rows=Rows(rows, offset, stop))), (offset, stop), Join((stop, current), ":")
