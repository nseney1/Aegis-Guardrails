"""Stdlib-only aegis.msg/1; CodecError.as_dict is the fixed data-error shape.
Code supplies meta and [start,end,title] body-character spans; schemas follow S4/A1.
Opaque JSON keys are arbitrary strings; schema names remain closed.
Selection/expansion work is 2*MAX_BYTES; descriptor I/O admits 64 maximal records.
Every store read/description verifies bytes. Missing array leaves use positional
null plus {path,count}; projections retain presence. Coverage unions intervals.
since is '<n>:<sha256(canonical rows[:n])>'; '0' starts; row_limit pages first.
Unsafe/closed/unsupported stores refuse E_AUTH; Windows support is deferred.
JSON is default; MD fences that JSON; TSV marks data and uses JSON cells.
JSON short escapes are preserved; outline alone emits only envelope and outline.
"""
import hashlib
from typing import NamedTuple

from . import message_codec_views as _views
from .message_codec_format import (
    CodecError, KIND_SCHEMAS, MAX_BYTES, MAX_NODES, MAX_SELECTORS, MAX_REFS,
    MAX_SPANS, MAX_WORK_BYTES, MAX_REF_BYTES, MAX_OUTPUT_CHARS, REF_NAME, NAME,
    INDEX, KEYS, STRING, INTEGER, Budget, require, object_schema, array_schema, KEY_MARKER, CURSOR_PATTERN,
    json_chunks, escape_char, neutral_text, canonical, parse, compose, record_id,
)
from .message_codec_store import Store


__all__ = ["CodecError", "Store", "canonical", "parse", "compose", "record_id", "read_view",
           "KIND_SCHEMAS", "MAX_BYTES"]


def _selector(selector):
    require(type(selector) is str and 0 < len(selector) <= 1024, "E_SELECTOR")
    parts = selector.split(".")
    require(len(parts) <= 8 and all(parts), "E_SELECTOR")
    for index, part in enumerate(parts):
        if part.startswith("{") and part.endswith("}"):
            keys = part[1:-1].split(",")
            require(index == len(parts) - 1 and index > 0 and parts[index - 1] == "*", "E_SELECTOR")
            require(all(NAME.fullmatch(k) for k in keys) and len(set(keys)) == len(keys), "E_SELECTOR")
        else:
            require(part == "*" or NAME.fullmatch(part) or REF_NAME.fullmatch(part) or INDEX.fullmatch(part), "E_SELECTOR")
    return parts


def _record_schema(kind):
    return object_schema({"schema": STRING, "kind": STRING, "body": STRING, "fields": KIND_SCHEMAS[kind],
                    "meta": object_schema({k: STRING for k in ("from", "host", "session", "created_at")}),
                    "spans": array_schema({"type": "tuple", "items": [INTEGER, INTEGER, STRING]}),
                    "refs": {"type": "mapping", "items": STRING, "keys": REF_NAME}})


def _children(schema):
    return dict(schema["required"], **schema["optional"])


def _schema_path(schema, parts):
    if not parts:
        return
    part, rest = parts[0], parts[1:]
    kind = schema["type"]
    if part.startswith("{"):
        require(kind == "object", "E_SELECTOR")
        for key in part[1:-1].split(","):
            _schema_path(schema, [key])
    elif kind in ("object", "mapping"):
        children = _children(schema) if kind == "object" else None
        require(children is not None or part == "*" or schema["keys"].fullmatch(part), "E_SELECTOR")
        if part == "*" and children is not None:
            require(bool(children), "E_SELECTOR")
            for child in children.values():
                _schema_path(child, rest)
        else:
            require(children is None or part in children, "E_SELECTOR")
            _schema_path(schema["items"] if children is None else children[part], rest)
    elif kind in ("array", "tuple"):
        require(part == "*" or (INDEX.fullmatch(part) and len(part) <= 5), "E_SELECTOR")
        if kind == "array":
            _schema_path(schema["items"], rest)
        else:
            indices = range(len(schema["items"])) if part == "*" else [int(part)]
            for index in indices:
                require(index < len(schema["items"]), "E_SELECTOR")
                _schema_path(schema["items"][index], rest)
    else:
        raise CodecError("E_SELECTOR")


class _Coverage:
    """Retain only budgeted selected paths; compute source offsets lazily."""
    def __init__(self, value, budget, renderer, page=None, transformed=False):
        self.value, self.budget, self.page = value, budget, page
        self.transformed, self.names, self.wildcards = transformed, set(), set()
        self.ranges, self.paths, self.spans, self.absent = {}, set(), [], set()
        self.renderer, self.active = renderer, True

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
                    self._add(("refs", KEY_MARKER, name))
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
        for _chunk in json_chunks(self.value, ranges=self.ranges):
            pass
        intervals = [self.ranges[path] for path in self.paths]
        if self.spans:
            offsets, previous, position = {}, 0, self.ranges[("body",)][0] + 1
            for boundary in sorted({point for span in self.spans for point in span}):
                position += self.renderer.text_size(self.value["body"], previous, boundary, ascii=True)[0] - 2
                offsets[boundary], previous = position, boundary
            intervals.extend((offsets[start], offsets[end]) for start, end in set(self.spans))
        covered, end = 0, 0
        for start, stop in sorted(intervals):
            covered += max(0, stop - max(start, end))
            end = max(end, stop)
        return size - covered


_MISSING = object()


def _child(value, schema, key, rest, path, missing, coverage, budget):
    if ((type(value) is list or isinstance(value, _views.Rows)) and key >= len(value)) or (type(value) is dict and key not in value):
        if coverage.active:
            concrete = coverage.source(path + (key,) + tuple(rest))
            source = tuple("*" if type(p) is int and i in coverage.wildcards else p for i, p in enumerate(concrete))
            budget.stage(sum(len(str(p)) for p in source) + len(source) + 2)
            if (source, concrete) not in coverage.absent:
                budget.stage(2)
                coverage.absent.add((source, concrete))
                missing[source] = missing.get(source, 0) + 1
        return _MISSING
    kind = schema["type"]
    child_schema = (_children(schema)[key] if kind == "object" else
                    schema["items"][key] if kind == "tuple" else schema["items"])
    return _select(value[key], child_schema, rest, path + (key,), missing, coverage, budget)


def _select(value, schema, parts, path, missing, coverage, budget):
    if coverage.active:
        budget.visit()
    if not parts:
        if coverage.active:
            coverage.add(path)
            budget.stage(coverage.renderer.json_size(value, budget.limit - budget.used))
        return value
    part, rest = parts[0], parts[1:]
    kind = schema["type"]
    if part.startswith("{"):
        if coverage.active:
            budget.stage(2)
        def projected():
            for key in part[1:-1].split(","):
                child = _child(value, schema, key, rest, path, missing, coverage, budget)
                if child is not _MISSING:
                    if coverage.active:
                        budget.stage(len(key) + 3)
                    yield key, child
        return _views.Object(projected)
    if part == "*":
        keys = (_children(schema) if kind == "object" else value.keys() if kind == "mapping"
                else range(len(value)))
        if coverage.active:
            budget.stage(2)
        mapping = kind in ("object", "mapping")
        if kind == "mapping" and coverage.active:
            coverage.add(path)
        def children():
            for key in keys:  # Literal keys never re-enter selector interpretation.
                child = _child(value, schema, key, rest, path, missing, coverage, budget)
                if child is _MISSING and kind == "array" and rest:
                    child = None
                    if coverage.active:
                        budget.stage(4)
                if child is not _MISSING:
                    if coverage.active:
                        budget.stage(1)
                    yield (key, child) if mapping else child
        return _views.Object(children) if mapping else _views.Array(children, len(value))
    return _child(value, schema, int(part) if type(value) is list or isinstance(value, _views.Rows) else part,
                  rest, path, missing, coverage, budget)


def _refs(value, store, expand, work, names, renderer):
    require(not value["refs"] or type(store) is Store, "E_REF")
    result, cache, io, rendered = {}, {}, Budget(MAX_REF_BYTES), Budget(renderer.limit)
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
            descriptor = {"ref": _views.Text(rid, 0, 16), "kind": child["kind"], "chars": io.used - before} if io.parent else child
            cache[rid] = (child, descriptor)
        child, descriptor = cache[rid]
        if name in expand:
            rendered.charge(renderer.json_size(child, rendered.limit - rendered.used))
        result[name] = child if name in expand else descriptor
    return result



def _renderer(limit):
    return _views.Renderer(require, escape_char, neutral_text, limit)


class _ReadOptions(NamedTuple):
    options: dict
    planned: dict


def _read_selectors(groups, cli):
    """Bound both representations before slicing CLI groups into selector entries."""
    require(type(groups) in (list, tuple) and len(groups) <= MAX_SELECTORS, "E_SELECTOR")
    if not cli:
        require(all(type(n) is str and 0 < len(n) <= 1024 for n in groups), "E_SELECTOR")
        return groups
    parts = []
    for expression in groups:
        require(isinstance(expression, str) and len(expression) <= MAX_SELECTORS * 1025 - 1, "E_SELECTOR")
        depth, start = 0, 0
        for index, char in enumerate(expression):
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == "," and depth == 0:
                require(len(parts) < MAX_SELECTORS and 0 < index - start <= 1024, "E_SELECTOR")
                parts.append((expression, start, index))
                start = index + 1
        require(len(parts) < MAX_SELECTORS and 0 < len(expression) - start <= 1024, "E_SELECTOR")
        parts.append((expression, start, len(expression)))
    return [expression[start:stop] for expression, start, stop in parts]


def _read_integer(value, limit, code, cli):
    if cli:
        require(type(value) is str and 0 < len(value) <= len(str(limit)) and INDEX.fullmatch(value), code)
        value = int(value)
    require(type(value) is int and 0 <= value <= limit, code)
    return value


def preflight_read(cli=False, /, *, selectors=(), spans=(), expand=(), since=None, row_limit=None,
                   outline=False, format="json", max_chars=60000, store=None, **unknown):
    """Normalize in one refusal order; cli=True positionally selects raw argparse values.

    Return normalized read_view options and their selector plan. The representation
    switch is positional-only so a read_view unknown keyword cannot enable parsing.
    Record-specific schema and reference checks follow record verification.
    """
    require(type(cli) is bool, "E_SELECTOR")
    require(type(expand) in (list, tuple) and len(expand) <= MAX_REFS, "E_REF")
    require(all(type(n) is str and REF_NAME.fullmatch(n) for n in expand), "E_REF")
    require(store is None or type(store) is Store, "E_REF")
    selectors = _read_selectors(selectors, cli)
    require(type(spans) in (list, tuple) and len(spans) <= MAX_SPANS, "E_SPAN")
    spans = [_read_integer(n, MAX_NODES - 1, "E_SPAN", cli) for n in spans]
    require(since is None or (type(since) is str and len(since) <= 70 and
                           (since == "0" or CURSOR_PATTERN.fullmatch(since))), "E_SELECTOR")
    require(row_limit is None or (type(row_limit) is int and 1 <= row_limit <= MAX_NODES), "E_LIMIT")
    require(not unknown, "E_SELECTOR", detail="option")
    require((since is not None or row_limit is None) and type(outline) is bool, "E_SELECTOR")
    if type(format) is not str or format not in ("json", "md", "tsv"):
        raise CodecError("E_FORMAT", detail="format")
    max_chars = _read_integer(max_chars, MAX_OUTPUT_CHARS, "E_LIMIT", cli)
    planned = {}
    for selector in selectors:
        parts = _selector(selector)
        parts = parts if parts[0] in KEYS else ["fields"] + parts
        require(tuple(parts) not in planned, "E_SELECTOR")
        planned[tuple(parts)] = selector
    return _ReadOptions(dict(selectors=selectors, spans=spans, expand=expand, since=since, row_limit=row_limit,
                             outline=outline, format=format, max_chars=max_chars), planned)


def _options(value, selectors, spans, expand, since, row_limit, outline, format, max_chars, store, unknown):
    planned = preflight_read(selectors=selectors, spans=spans, expand=expand, since=since, row_limit=row_limit,
                             outline=outline, format=format, max_chars=max_chars, store=store, **unknown).planned
    if type(value) is dict and type(value.get("kind")) is str and value["kind"] in KIND_SCHEMAS:
        for parts in planned:
            _schema_path(_record_schema(value["kind"]), parts)
    require(not expand or (type(value) is dict and type(value.get("refs")) is dict and
                         all(name in value["refs"] for name in expand)), "E_REF")
    return planned


def read_view(value, *, selectors=(), spans=(), outline=False, since=None, row_limit=None,
              expand=(), store=None, format="json", max_chars=60000, **unknown):
    """Total for data inputs, including unknown options; wrong arity is programmer error."""
    planned = _options(value, selectors, spans, expand, since, row_limit, outline, format, max_chars, store, unknown)
    renderer, budget = _renderer(max_chars), Budget(MAX_WORK_BYTES)
    raw = canonical(value)
    require(all(index < len(value["spans"]) for index in spans), "E_SPAN")
    rid = hashlib.sha256(raw).hexdigest()
    handle = _views.Text(rid, 0, 16)
    outline_only = outline and not (selectors or spans or since is not None or expand)
    view = {"ref": handle, "kind": value["kind"], "from": value["meta"]["from"],
            "untrusted": True, "omitted_chars": 0}
    if not outline_only:
        view["data"] = {}
    renderer.measure(view, format)  # Minimum envelope; no output can be smaller.
    page, cursor, original = None, None, value
    if since is not None:
        value, page, cursor = _views.page(value, since, row_limit, json_chunks, require)
    coverage, schema = _Coverage(original, budget, renderer, page, bool(value["refs"])), _record_schema(value["kind"])
    data, missing = {}, {}
    default = not (selectors or spans or since is not None or outline_only)
    include_refs = default or bool(expand) or any(parts[0] == "refs" for parts in planned)
    if include_refs:
        paths = [parts for parts in planned if parts[0] == "refs"]
        names = (set(value["refs"]) if default or any(len(p) == 1 or p[1] == "*" for p in paths)
                 else {p[1] for p in paths} | set(expand))
        coverage.names = names & value["refs"].keys()
        value = dict(value, refs=_refs(value, store, expand, budget, names, renderer))
    extra_refs = include_refs and (default or bool(expand))
    def selected_items():
        for parts, selector in planned.items():
            coverage.wildcards = {i for i, part in enumerate(parts) if part == "*"}
            selected = _select(value, schema, parts, (), missing, coverage, budget)
            if selected is not _MISSING:
                yield selector, selected
        for index in dict.fromkeys(spans):
            start, end, _title = value["spans"][index]
            if coverage.active:
                budget.stage(end - start)
                coverage.span(start, end)
            yield "span:" + str(index), _views.Text(value["body"], start, end)
        if extra_refs and "refs" not in planned.values():
            yield "refs", value["refs"]
    if selectors or spans:
        data = _views.Object(selected_items)
    whole = not (selectors or spans or since is not None or outline) and len(raw) <= 4000
    if whole:
        data = dict(value)
        coverage.add(()) if not value["refs"] or store is None else None
    elif since is not None and not selectors and not spans:
        data = {"rows": value["fields"]["rows"]}
        coverage.add(("fields", "rows"))
    elif not selectors and not spans and not outline_only:
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
    if extra_refs:
        if type(data) is dict:
            data["refs"] = value["refs"]
        coverage.add(("refs",))
    renderer.json_size(data, MAX_OUTPUT_CHARS if format == "tsv" else max_chars)
    coverage.active = False  # Replay plans without recharging selection analysis.
    view["omitted_chars"] = coverage.omitted(len(raw))
    if not outline_only:
        view["data"] = data
    if cursor is not None:
        view["cursor"] = cursor
    if missing:
        view["missing"] = _views.Array(lambda: ({"path": _views.Join(path), "count": count}
                                               for path, count in missing.items()), len(missing))
    if outline:
        view["outline"] = _views.outline(original, KEYS)
    return renderer.render(view, format)
