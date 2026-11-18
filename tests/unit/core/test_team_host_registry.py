"""Host-registry parity and bounded, fixed refusals (TA-4a round 1b)."""
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_host_registry as core
from tools import hierarchy_hosts as legacy


SESSION = "4f1c2b9e-8d7a-4c3b-9a1e-2f6d5c4b3a21"
OTHER = "00000000-0000-0000-0000-000000000001"


def make_store(tmp_path):
    if not core.descriptor_supported():
        pytest.skip("descriptor-relative no-follow discovery required")
    return tmp_path


def assert_refusal(caught, reason):
    error = caught.value
    assert error.as_dict() == {"status": "refused", "reason": reason,
                               "next_action": error.next_action, "code": 1}
    assert error.next_action
    assert "untrusted-marker" not in str(error)


@pytest.mark.parametrize("name,args,kwargs", [
    ("entry", (), {}), ("entry", ("codex-cli", "extra"), {}),
    ("entry", ("codex-cli",), {"kind": "codex-cli"}),
    ("entry", (), {"untrusted_marker": "value"}),
    ("describe", ("extra",), {}), ("session_verdict", ("codex-cli",), {}),
])
def test_call_shape_refuses_with_fixed_envelope_and_retry(name, args, kwargs):
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            getattr(core, name)(*args, **kwargs)
        assert_refusal(caught, "invalid_record")
    assert core.entry(kind=core.CODEX) == legacy.entry(core.CODEX)


@pytest.mark.parametrize("value", [None, 17, True, 1.5])
def test_non_iterable_stream_refuses_with_fixed_envelope_and_retry(value):
    for reader in (core.claude_events, core.claude_init, core.claude_usage, core.claude_turn_items):
        for _ in range(2):
            with pytest.raises(core.HostRefusal) as caught:
                result = reader(value)
                if reader is core.claude_events:
                    list(result)
            assert_refusal(caught, "invalid_record")
    assert list(core.claude_events("{}")) == [{}]


def test_sequence_only_stream_protocol_keeps_legacy_values():
    class SequenceLines:
        def __getitem__(self, index):
            return ('{}', '{"type":"result"}')[index]
    assert list(core.claude_events(SequenceLines())) == list(legacy.claude_events(SequenceLines()))


def test_disabled_iteration_refuses_without_reading_sequence():
    reads = []
    class DisabledLines:
        __iter__ = None
        def __getitem__(self, index):
            reads.append(index)
            return "{}"
    with pytest.raises(core.HostRefusal) as caught:
        list(core.claude_events(DisabledLines()))
    assert_refusal(caught, "invalid_record")
    assert reads == []


@pytest.mark.parametrize("returned", [None, 17, []])
def test_invalid_iterator_return_refuses_before_read_and_retry(returned):
    class InputLines:
        def __iter__(self):
            return returned
    with pytest.raises(core.HostRefusal) as caught:
        list(core.claude_events(InputLines()))
    assert_refusal(caught, "invalid_record")
    assert list(core.claude_events("{}")) == [{}]


@pytest.mark.parametrize("shape", ["none", "not_callable", "not_iterable", "bad_item", "bytes_key"])
def test_environment_shape_refuses_with_fixed_envelope_and_retry(shape):
    class InputEnvironment:
        def items(self):
            return {"not_iterable": None, "bad_item": [None], "bytes_key": [(b"KEY", "value")]}[shape]
    value = None if shape == "none" else SimpleNamespace(items=17) if shape == "not_callable" else InputEnvironment()
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            core.child_environment(value, "no-host")
        assert_refusal(caught, "invalid_record")
    assert core.child_environment({"KEEP": "value"}, "no-host") == {"KEEP": "value"}


def test_duck_environment_items_keep_legacy_values():
    class InputEnvironment:
        def items(self):
            return iter([iter(("KEEP", "value")), iter(("CODEX_THREAD_ID", SESSION))])
    assert core.child_environment(InputEnvironment(), "no-host") == legacy.child_environment(
        InputEnvironment(), "no-host")


@pytest.mark.parametrize("value", [None, 17, True, b"OPENAI_API_KEY", bytearray(b"OPENAI_API_KEY")])
def test_billing_shape_refuses_with_fixed_envelope_and_retry(value):
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            core.billing_set(core.CODEX, value)
        assert_refusal(caught, "invalid_record")
    assert core.billing_set(core.CODEX, {"OPENAI_API_KEY": ""}) == ["OPENAI_API_KEY"]


@pytest.mark.parametrize("shape", ["dict", "list", "set", "text", "iterator", "memoryview"])
def test_billing_container_protocol_keeps_legacy_values(shape):
    def supplied():
        if shape == "dict":
            return {"OPENAI_API_KEY": ""}
        if shape == "list":
            return ["OPENAI_API_KEY"]
        if shape == "set":
            return {"OPENAI_API_KEY"}
        if shape == "text":
            return "OPENAI_API_KEY"
        if shape == "memoryview":
            return memoryview(b"OPENAI_API_KEY")
        return iter(["OPENAI_API_KEY"])
    assert core.billing_set(core.CODEX, supplied()) == legacy.billing_set(core.CODEX, supplied())


@pytest.mark.parametrize("value", [None, 17, [], {"path": "untrusted-marker"}])
def test_auth_home_shape_refuses_with_fixed_envelope_and_retry(tmp_path, value):
    status = dict(loggedIn=True, authMethod="claude.ai", apiProvider="firstParty",
                  configDirectory=str(tmp_path))
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            core.claude_auth_check(0, status, value)
        assert_refusal(caught, "invalid_record")
    assert core.claude_auth_check(0, status, tmp_path) == legacy.claude_auth_check(0, status, tmp_path)


def test_auth_path_protocol_validates_return_shape_and_keeps_legacy_values(tmp_path):
    status = dict(loggedIn=True, authMethod="claude.ai", apiProvider="firstParty",
                  configDirectory=str(tmp_path))
    class GoodPath:
        def __fspath__(self):
            return str(tmp_path)
    class BadPath:
        def __fspath__(self):
            return 17
    with pytest.raises(core.HostRefusal) as caught:
        core.claude_auth_check(0, status, BadPath())
    assert_refusal(caught, "invalid_record")
    assert core.claude_auth_check(0, status, GoodPath()) == legacy.claude_auth_check(0, status, GoodPath())



@pytest.mark.parametrize("name", ["entry", "family", "entrypoints"])
@pytest.mark.parametrize("kind", ["untrusted-marker", None, {}, []])
def test_unknown_host_fixed_refusal_and_valid_retry(name, kind):
    with pytest.raises(ValueError):
        getattr(legacy, name)(kind)
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            getattr(core, name)(kind)
        assert_refusal(caught, "unknown_host")
    assert getattr(core, name)(core.CODEX) == getattr(legacy, name)(legacy.CODEX)


def test_declarative_values_and_copies_match_legacy():
    assert core.describe() == legacy.describe()
    assert core.HOST_ENVIRONMENT == legacy.HOST_ENVIRONMENT
    row = core.entry(core.CODEX)
    row["entrypoints"]["program_basenames"].clear()
    assert core.entrypoints(core.CODEX) == legacy.entrypoints(legacy.CODEX)
    for kind in core.HOST_KINDS:
        assert core.family(kind) == legacy.family(kind)
        assert core.billing_set(kind, {"OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": ""}) == legacy.billing_set(
            kind, {"OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": ""})
    for kind in core.TEAM_HOSTS:
        for writer in (False, True):
            assert core.qualify(kind, writer) == legacy.qualify(kind, writer)


def test_option_catalog_values_and_serialized_bytes_match_legacy():
    assert core.CODEX_STOP_OPTIONS == legacy.CODEX_STOP_OPTIONS
    assert core.CLAUDE_STOP_FLAGS == legacy.CLAUDE_STOP_FLAGS
    assert core.CLAUDE_STOP_VALUES == legacy.CLAUDE_STOP_VALUES
    assert json.dumps(core.describe(), separators=(",", ":")).encode("utf-8") == json.dumps(
        legacy.describe(), separators=(",", ":")).encode("utf-8")


@pytest.mark.parametrize("kind,argv,expected", [
    ("codex-cli", ["codex", "-c", "key=value", "-m", "model", "exec", "resume", SESSION], "OWNED"),
    ("codex-cli", ["codex", "exec", "resume", "-c", "key=value", "-m", "model", SESSION], "OWNED"),
    ("claude-code", ["claude", "--session-id", SESSION, "--fork-session", "-c"], "OWNED"),
    ("claude-code", ["claude", "-c"], "HOLD"),
])
def test_short_option_catalogs_keep_legacy_acceptance_and_refusal(kind, argv, expected):
    assert core.session_verdict(kind, argv, SESSION) == legacy.session_verdict(kind, argv, SESSION) == expected


@pytest.mark.parametrize("purpose", ["host-cli", "no-host"])
def test_child_environment_parity(purpose):
    env = {"KEEP": "value", "CODEX_THREAD_ID": SESSION, "CLAUDE_CODE_SESSION_ID": SESSION,
           "OPENAI_API_KEY": "", "ANTHROPIC_API_KEY": "", "CLAUDE_CODE_CUSTOM": "value"}
    assert core.child_environment(env, purpose) == legacy.child_environment(env, purpose)
    assert env["KEEP"] == "value"


@pytest.mark.parametrize("kind,argv", [
    ("codex-cli", ["codex", "exec", "resume", SESSION]),
    ("codex-cli", ["codex", "exec", "resume", OTHER]),
    ("codex-cli", ["codex", "exec", "resume", SESSION, "resume", OTHER]),
    ("codex-cli", ["node", "--require", "setup.js", "codex.js", "exec", "resume", SESSION]),
    ("codex-cli", ["env", "K=V", "codex", "resume", SESSION]),
    ("codex-cli", ["codex", "--unlisted", "resume", SESSION]),
    ("claude-code", ["claude", "--resume", SESSION]),
    ("claude-code", ["claude", "--resume", OTHER]),
    ("claude-code", ["claude", "--resume", SESSION, "--session-id", OTHER]),
    ("claude-code", ["claude", "--session-id", SESSION, "--fork-session", "--continue"]),
    ("claude-code", ["claude", "--resume", SESSION, "--model", "a prompt " + OTHER]),
    ("claude-code", ["python", "worker.py"]),
])
def test_process_grammar_parity(kind, argv):
    for boundaries in ("proven", "unproven"):
        assert core.session_verdict(kind, argv, SESSION, boundaries) == legacy.session_verdict(
            kind, argv, SESSION, boundaries)
        assert core.matches_session(kind, argv, SESSION, boundaries) == legacy.matches_session(
            kind, argv, SESSION, boundaries)
    assert core.matches_entrypoint(kind, argv) == legacy.matches_entrypoint(kind, argv)
    assert core.names_session(argv, SESSION) == legacy.names_session(argv, SESSION)
    assert core.descendant_verdict(argv, SESSION) == legacy.descendant_verdict(argv, SESSION)
    assert core.selects_other_session(argv, SESSION) == legacy.selects_other_session(argv, SESSION)


def test_events_usage_and_turn_values_match_legacy(tmp_path):
    events = [
        {"type": "system", "subtype": "init", "session_id": SESSION, "model": "model"},
        {"type": "assistant", "message": {"content": [
            {"type": "text", "text": "hello"},
            {"type": "tool_use", "name": "mcp__mail__inbox", "input": {"count": 1}}]}},
        {"type": "result", "usage": dict(input_tokens=3, cache_creation_input_tokens=2,
            cache_read_input_tokens=1, output_tokens=4), "session_id": SESSION},
    ]
    lines = "\n".join(json.dumps(row) for row in events) + "\n{\n[]\n"
    assert list(core.claude_events(lines)) == list(legacy.claude_events(lines))
    assert core.claude_init(lines) == legacy.claude_init(lines)
    assert core.claude_usage(lines) == legacy.claude_usage(lines)
    assert core.claude_turn_items(lines) == legacy.claude_turn_items(lines)
    totals = {"input_tokens": 9, "cached_input_tokens": 3, "output_tokens": 2}
    assert core.codex_usage(totals) == legacy.codex_usage(totals)
    status = dict(loggedIn=True, authMethod="claude.ai", apiProvider="firstParty",
                  configDirectory=str(tmp_path), ignored="untrusted-marker")
    assert core.claude_auth_check(0, status, tmp_path) == legacy.claude_auth_check(0, status, tmp_path)


def test_oversized_event_refuses_before_parsing_and_valid_retry(monkeypatch):
    calls = []
    original = core.json.loads
    def parsed(value):
        calls.append(len(value))
        return original(value)
    monkeypatch.setattr(core, "json", SimpleNamespace(loads=parsed))
    with pytest.raises(core.HostRefusal) as caught:
        list(core.claude_events(" " * (core.MAX_BYTES + 1)))
    assert_refusal(caught, "too_large")
    assert calls == []
    assert list(core.claude_events("{}")) == [{}]


def test_auth_diagnostics_never_echo_untrusted_fields(tmp_path):
    _, problems = core.claude_auth_check("untrusted-marker", {
        "authMethod": "untrusted-marker", "apiProvider": "untrusted-marker"}, tmp_path)
    assert problems
    assert "untrusted-marker" not in json.dumps(problems)


def test_stream_count_limit_precedes_parsing(monkeypatch):
    monkeypatch.setattr(core, "MAX_EVENTS_PER_STREAM", 2)
    calls = []
    def unexpected_parse(value):
        calls.append(value)
        raise AssertionError("oversized stream reached parser")
    monkeypatch.setattr(core, "json", SimpleNamespace(loads=unexpected_parse))
    with pytest.raises(core.HostRefusal) as caught:
        list(core.claude_events("{}\n{}\n{}"))
    assert_refusal(caught, "too_large")
    assert calls == []


def test_transcripts_match_legacy_and_skip_links(tmp_path):
    root = make_store(tmp_path)
    path = root / "projects" / "example" / (SESSION + ".jsonl")
    path.parent.mkdir(parents=True)
    path.write_text("{}")
    assert core.transcripts(core.CLAUDE, root, SESSION) == legacy.transcripts(legacy.CLAUDE, root, SESSION)
    outside = root / "outside"
    outside.mkdir()
    (outside / (SESSION + ".jsonl")).write_text("{}")
    symlink_or_skip(outside, root / "projects" / "linked", target_is_directory=True)
    assert core.transcripts(core.CLAUDE, root, SESSION) == [path]


def test_unsupported_discovery_is_typed_before_io(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "descriptor_supported", lambda: False)
    with pytest.raises(core.HostRefusal) as caught:
        core.transcripts(core.CLAUDE, tmp_path, SESSION)
    assert_refusal(caught, "unsupported_platform")
    assert list(tmp_path.iterdir()) == []


def test_discovery_descriptors_close_on_directory_open_failure(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    (root / "projects").mkdir()
    opened, closed = [], []
    def opened_fd(path, flags, **options):
        if path == "projects":
            raise PermissionError("untrusted-marker")
        fd = os.open(path, flags, **options)
        opened.append(fd)
        return fd
    def closed_fd(fd):
        closed.append(fd)
        return os.close(fd)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": opened_fd, "close": closed_fd}))
    with pytest.raises(core.HostRefusal) as caught:
        core.transcripts(core.CLAUDE, root, SESSION)
    assert_refusal(caught, "io")
    assert sorted(opened) == sorted(closed)


STREAM_KINDS = ("str", "bytes", "bytearray", "text_file", "binary_file", "iterator")
STREAM_SHAPES = ("event_at", "event_over", "big_int", "duplicate", "nan", "infinity",
                 "depth_33", "depth_near_limit", "depth_over_limit", "many_keys", "two_results",
                 "terminated_at", "terminated_over", "blank_at", "blank_over", "invalid_utf8")


@contextmanager
def event_input(raw, kind, tmp_path):
    if kind in ("text_file", "binary_file"):
        path = tmp_path / "events.jsonl"
        path.write_bytes(raw)
        options = {"encoding": "utf-8", "errors": "replace", "newline": "\n"} if kind == "text_file" else {}
        with path.open("r" if kind == "text_file" else "rb", **options) as source:
            yield source
    elif kind == "str":
        yield raw.decode("utf-8", "replace")
    elif kind == "bytes":
        yield raw
    elif kind == "bytearray":
        yield [bytearray(line) for line in io.BytesIO(raw)]
    else:
        yield (line for line in io.BytesIO(raw))


def event_shape(shape):
    result = b'{"type":"result","usage":{"input_tokens":1,"cache_creation_input_tokens":2,'
    result += b'"cache_read_input_tokens":3,"output_tokens":4}'
    prefix = result + b',"padding":'
    if shape in ("event_at", "event_over"):
        return prefix + b'"' + b"x" * (262144 - len(prefix) - 3) + b'"}' + (b" " if shape == "event_over" else b"")
    if shape in ("terminated_at", "terminated_over", "blank_at", "blank_over"):
        count = 10001 if shape.endswith("over") else 10000
        return (b"{}\n" if shape.startswith("terminated") else b"\n") * count
    if shape == "two_results":
        return prefix + b"18446744073709551616}\n" + result + b"}\n"
    if shape.startswith("depth_"):
        depth = 33 if shape == "depth_33" else min(sys.getrecursionlimit() - 100, 20000)
        if shape == "depth_over_limit":
            depth = sys.getrecursionlimit() + 100
        value = b"[" * depth + b"0" + b"]" * depth
    else:
        value = {"big_int": b"18446744073709551616", "duplicate": b'{"key":0,"key":1}',
                 "nan": b"NaN", "infinity": b"Infinity", "invalid_utf8": b'"' + bytes([255]) + b'"',
                 "many_keys": json.dumps({str(i): 0 for i in range(10001)}).encode()}[shape]
    return prefix + value + b"}\n"


@pytest.mark.parametrize("kind", ("bytes", "binary_file", "iterator", "bytearray"))
@pytest.mark.parametrize("shape", ("reported", "quoted", "ambiguous"))
def test_raw_byte_inflation_matches_each_legacy_input_kind_and_retry(tmp_path, kind, shape):
    result = event_shape("two_results").split(b"\n")[1]
    raw = b'{"type":"result"}\n' + b"\xff" * 87382
    assert len(raw) == 87400
    if shape != "reported":
        raw = result[:-1] + b',"padding":"' + b"\xff" * 87382 + b'"}\n'
        if shape == "ambiguous":
            raw += result + b"\n"
    assert len(raw) <= core.MAX_STREAM_BYTES
    readers = ((core.claude_events, legacy.claude_events), (core.claude_init, legacy.claude_init),
               (core.claude_usage, legacy.claude_usage), (core.claude_turn_items, legacy.claude_turn_items))
    for reader, legacy_reader in readers:
        with event_input(raw, kind, tmp_path) as source:
            expected = legacy_reader(source)
            if legacy_reader is legacy.claude_events:
                expected = list(expected)
        for _ in range(2):
            with event_input(raw, kind, tmp_path) as source:
                found = reader(source)
                if reader is core.claude_events:
                    found = list(found)
                assert found == expected
        with event_input(b"{}\n", kind, tmp_path) as source:
            assert list(core.claude_events(source)) == [{}]


@pytest.mark.parametrize("kind", ("bytes", "binary_file", "iterator", "bytearray"))
def test_raw_line_byte_limit_precedes_decode_and_parser_then_retry(tmp_path, monkeypatch, kind):
    limit = core.MAX_EVENT_BYTES
    # Isolate the per-line limit for complete bytes as well as streaming sources.
    monkeypatch.setattr(core, "MAX_STREAM_BYTES", limit + 1)
    prefix, suffix = b'{"padding":"', b'"}'
    raw = prefix + b"\xff" * (limit - len(prefix) - len(suffix)) + suffix
    assert len(raw) == limit
    with event_input(raw, kind, tmp_path) as source:
        expected = list(legacy.claude_events(source))
    with event_input(raw, kind, tmp_path) as source:
        assert list(core.claude_events(source)) == expected
    original, calls = core.json, []
    def unexpected_parse(value):
        calls.append(True)
        raise AssertionError("raw line overflow reached parser")
    monkeypatch.setattr(core, "json", SimpleNamespace(loads=unexpected_parse))
    for _ in range(2):
        with event_input(raw + b" ", kind, tmp_path) as source:
            with pytest.raises(core.HostRefusal) as caught:
                list(core.claude_events(source))
            assert_refusal(caught, "too_large")
    assert calls == []
    monkeypatch.setattr(core, "json", original)
    with event_input(raw, kind, tmp_path) as source:
        assert list(core.claude_events(source)) == expected


@pytest.mark.parametrize("kind", ("bytes", "binary_file", "iterator", "bytearray"))
def test_raw_whole_byte_limit_and_streaming_input_scope(tmp_path, kind):
    first = b'{"type":"result"}\n'
    raw = first + b"\xff" * (core.MAX_STREAM_BYTES - len(first))
    assert len(raw) == core.MAX_STREAM_BYTES
    for value in (raw, raw + b" ", raw):
        with event_input(value, kind, tmp_path) as source:
            expected = list(legacy.claude_events(source))
        assert expected == [{"type": "result"}]
        with event_input(value, kind, tmp_path) as source:
            if kind == "bytes" and len(value) > core.MAX_STREAM_BYTES:
                with pytest.raises(core.HostRefusal) as caught:
                    list(core.claude_events(source))
                assert_refusal(caught, "too_large")
            else:
                assert list(core.claude_events(source)) == expected


@pytest.mark.parametrize("kind", ("whole", "readline", "iterator"))
@pytest.mark.parametrize("token", ("\ud800", "\udc00", "\ud800\udc00", "e\u0301", "\ufffd"))
def test_received_text_limits_use_utf8_surrogatepass_without_transforming(monkeypatch, kind, token):
    monkeypatch.setattr(core, "MAX_EVENT_BYTES", 64)
    monkeypatch.setattr(core, "MAX_STREAM_BYTES", 64)
    prefix, suffix = '{"padding":"', '"}'
    budget = 64 - len(prefix + suffix)
    width = len(token.encode("utf-8", "surrogatepass"))
    raw = prefix + token * (budget // width) + "x" * (budget % width) + suffix
    assert len(raw.encode("utf-8", "surrogatepass")) == 64
    expected = list(legacy.claude_events(raw))
    for value in (raw, raw + " ", raw):
        with io.StringIO(value) as stream:
            source = value if kind == "whole" else stream if kind == "readline" else iter([value])
            if len(value.encode("utf-8", "surrogatepass")) > 64:
                with pytest.raises(core.HostRefusal) as caught:
                    list(core.claude_events(source))
                assert_refusal(caught, "too_large")
            else:
                assert list(core.claude_events(source)) == expected
            assert not stream.closed


@pytest.mark.parametrize("kind", STREAM_KINDS)
@pytest.mark.parametrize("shape", STREAM_SHAPES)
def test_event_stream_input_shape_matrix_matches_legacy_or_refuses(tmp_path, kind, shape):
    raw = event_shape(shape)
    overflow = shape in ("event_over", "terminated_over", "blank_over")
    readers = ((core.claude_events, legacy.claude_events), (core.claude_init, legacy.claude_init),
               (core.claude_usage, legacy.claude_usage), (core.claude_turn_items, legacy.claude_turn_items))
    for reader, legacy_reader in readers:
        def read(selected):
            with event_input(raw, kind, tmp_path) as source:
                value = selected(source)
                return list(value) if selected in (core.claude_events, legacy.claude_events) else value
        expected = read(legacy_reader)
        if overflow:
            for _ in range(2):
                with pytest.raises(core.HostRefusal) as caught:
                    read(reader)
                assert_refusal(caught, "too_large")
        else:
            assert json.dumps(read(reader), sort_keys=True) == json.dumps(expected, sort_keys=True)
        with event_input(b'{"type":"result"}\n', kind, tmp_path) as source:
            assert list(core.claude_events(source)) == [{"type": "result"}]


@pytest.mark.parametrize("kind", STREAM_KINDS)
@pytest.mark.parametrize("shape", ("big_int", "duplicate", "nan", "infinity", "depth_33", "many_keys"))
def test_tool_input_values_are_preserved_inside_event_bounds(tmp_path, kind, shape):
    result = event_shape(shape)
    padding = result.split(b',"padding":', 1)[1].rstrip(b"\n")[:-1]
    raw = b'{"type":"assistant","message":{"content":[{"type":"tool_use",'
    raw += b'"name":"mcp__mail__inbox","input":' + padding + b"}]}}\n"
    with event_input(raw, kind, tmp_path) as source:
        expected = legacy.claude_turn_items(source)
    with event_input(raw, kind, tmp_path) as source:
        found = core.claude_turn_items(source)
    assert json.dumps(found, sort_keys=True) == json.dumps(expected, sort_keys=True)
    assert len(found) == 1


@pytest.mark.parametrize("binary", (False, True))
@pytest.mark.parametrize("overflow", (False, True))
def test_file_lines_are_read_with_a_bound_before_allocation(binary, overflow):
    limit = core.MAX_EVENT_BYTES
    raw = '{"payload":"' + "x" * (limit - len('{"payload":""}')) + '"}'
    source = io.BytesIO(raw.encode() + (b" " if overflow else b"")) if binary else io.StringIO(raw + (" " if overflow else ""))
    calls = []
    class BoundedReader:
        def __iter__(self):
            return self
        def __next__(self):
            raise AssertionError("file iteration would allocate an unbounded physical line")
        def readline(self, size=-1):
            assert 0 < size <= limit + 1
            calls.append(size)
            return source.readline(size)
    if overflow:
        with pytest.raises(core.HostRefusal) as caught:
            list(core.claude_events(BoundedReader()))
        assert_refusal(caught, "too_large")
        assert source.tell() <= limit + 1
    else:
        assert list(core.claude_events(BoundedReader())) == [{"payload": "x" * (limit - len('{"payload":""}'))}]
    assert calls
    assert not source.closed
    source.close()


@pytest.mark.parametrize("reader", ("claude_events", "claude_init", "claude_usage", "claude_turn_items"))
def test_whole_stream_overflow_never_becomes_a_partial_authoritative_result(reader):
    first = '{"type":"system","subtype":"init","session_id":"session"}\n'
    first += '{"type":"result","usage":{"input_tokens":1,"cache_creation_input_tokens":2,"cache_read_input_tokens":3,"output_tokens":4}}\n'
    with pytest.raises(core.HostRefusal) as caught:
        value = getattr(core, reader)(iter([first.split("\n")[0], first.split("\n")[1], "x" * 262145]))
        if reader == "claude_events":
            list(value)
    assert_refusal(caught, "too_large")
    assert core.claude_init(first)["session_id"] == "session"


def test_stream_growing_between_bounded_reads_refuses_and_leaves_caller_file_open(tmp_path):
    path = tmp_path / "growing.jsonl"
    first = b'{"type":"system","subtype":"init"}\n'
    path.write_bytes(first)
    with path.open("rb") as source:
        class GrowingReader:
            def __iter__(self):
                return self
            def __next__(self):
                raise AssertionError("use bounded readline")
            def readline(self, size=-1):
                if source.tell() == 0:
                    with path.open("ab") as writer:
                        writer.write(b"x" * 262145)
                return source.readline(size)
        with pytest.raises(core.HostRefusal) as caught:
            core.claude_init(GrowingReader())
        assert_refusal(caught, "too_large")
        assert not source.closed
    path.write_bytes(first)
    with path.open("rb") as source:
        assert core.claude_init(source)["session_id"] is None


def test_bounded_read_failure_is_fixed_and_retry_is_valid():
    class FailedReader:
        def __iter__(self):
            return iter(())
        def readline(self, size):
            raise OSError("untrusted-marker")
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            list(core.claude_events(FailedReader()))
        assert_refusal(caught, "io")
    assert list(core.claude_events(io.StringIO("{}\n"))) == [{}]


def test_legacy_bytearray_event_and_top_level_bytearray_remain_distinct():
    raw = bytearray(b'{"type":"result"}')
    assert list(core.claude_events([raw])) == list(legacy.claude_events([raw])) == [{"type": "result"}]
    assert list(core.claude_events(raw)) == list(legacy.claude_events(raw)) == []


@contextmanager
def newline_input(raw, kind, newline, tmp_path):
    if kind == "string_io":
        with io.StringIO(raw, newline=newline) as source:
            yield source
    else:
        path = tmp_path / "newline-events.jsonl"
        path.write_bytes(raw.encode("utf-8"))
        with path.open(encoding="utf-8", newline=newline) as source:
            yield source


@pytest.mark.parametrize("kind", ("string_io", "text_file"))
@pytest.mark.parametrize("newline", ("", "\r", None, "\r\n"))
@pytest.mark.parametrize("shape", ("result", "init", "assistant"))
def test_text_reader_newline_modes_preserve_legacy_events(tmp_path, kind, newline, shape):
    event = {"result": event_shape("two_results").decode().split("\n")[1],
             "init": '{"type":"system","subtype":"init","session_id":"session"}',
             "assistant": '{"type":"assistant","message":{"content":[{"type":"text","text":"hello"}]}}'}[shape]
    raw = event + "\r{}\n" + event + "\n"
    readers = ((core.claude_events, legacy.claude_events), (core.claude_init, legacy.claude_init),
               (core.claude_usage, legacy.claude_usage), (core.claude_turn_items, legacy.claude_turn_items))
    for reader, legacy_reader in readers:
        with newline_input(raw, kind, newline, tmp_path) as source:
            expected = legacy_reader(source)
            if legacy_reader is legacy.claude_events:
                expected = list(expected)
        for _ in range(2):
            with newline_input(raw, kind, newline, tmp_path) as source:
                found = reader(source)
                if reader is core.claude_events:
                    found = list(found)
                assert found == expected
                assert not source.closed
    with newline_input("{}\n", kind, None, tmp_path) as source:
        assert list(core.claude_events(source)) == [{}]


@pytest.mark.parametrize("newline", ("\r", "\r\n"))
def test_text_reader_does_not_split_internal_lf_at_read_size(tmp_path, monkeypatch, newline):
    monkeypatch.setattr(core, "MAX_EVENT_BYTES", 64)
    # A bounded fragment ending in LF is not a line boundary in these modes.
    raw = " " * 13 + "{}\n{}" + newline
    with newline_input(raw, "text_file", newline, tmp_path) as source:
        expected = list(legacy.claude_events(source))
    assert expected == []
    with newline_input(raw, "text_file", newline, tmp_path) as source:
        assert list(core.claude_events(source)) == expected


@pytest.mark.parametrize("newline", ("", "\r", None, "\r\n"))
def test_text_reader_counts_source_lines_and_refuses_then_retries(tmp_path, monkeypatch, newline):
    monkeypatch.setattr(core, "MAX_EVENTS_PER_STREAM", 2)
    delimiter = "\r\n" if newline == "\r\n" else "\r"
    for count in (2, 3, 2):
        raw = ("{}" + delimiter) * count
        with newline_input(raw, "text_file", newline, tmp_path) as source:
            if count == 3:
                with pytest.raises(core.HostRefusal) as caught:
                    list(core.claude_events(source))
                assert_refusal(caught, "too_large")
            else:
                assert list(core.claude_events(source)) == [{}, {}]
            assert not source.closed


@pytest.mark.parametrize("newline", ("", "\r", None, "\r\n"))
@pytest.mark.parametrize("token", ("x", "é", "€", "😀"))
def test_text_reader_byte_bound_precedes_parser_and_valid_retry(tmp_path, monkeypatch, newline, token):
    monkeypatch.setattr(core, "MAX_EVENT_BYTES", 64)
    ending = "\r\n" if newline == "\r\n" else "\r"
    width = len(token.encode("utf-8"))
    budget = 64 - len('{"x":""}' + ending)
    raw = '{"x":"' + token * (budget // width) + "x" * (budget % width) + '"}' + ending
    assert len(raw.encode("utf-8")) == 64
    # Universal translation replaces CRLF only; these accepted values stay at N.
    with newline_input(raw, "text_file", newline, tmp_path) as source:
        expected = list(legacy.claude_events(source))
    with newline_input(raw, "text_file", newline, tmp_path) as source:
        assert list(core.claude_events(source)) == expected
    calls = []
    def unexpected_parse(value):
        calls.append(value)
        raise AssertionError("oversized text line reached JSON parser")
    original = core.json
    monkeypatch.setattr(core, "json", SimpleNamespace(loads=unexpected_parse))
    for _ in range(2):
        with newline_input(raw[:-len(ending)] + " " + ending, "text_file", newline, tmp_path) as source:
            with pytest.raises(core.HostRefusal) as caught:
                list(core.claude_events(source))
            assert_refusal(caught, "too_large")
            assert not source.closed
    assert calls == []
    monkeypatch.setattr(core, "json", original)
    with newline_input(raw, "text_file", newline, tmp_path) as source:
        assert list(core.claude_events(source)) == expected


@pytest.mark.parametrize("kind", ("list", "iterator"))
def test_materialized_items_are_checked_before_parsing_and_retry(monkeypatch, kind):
    monkeypatch.setattr(core, "MAX_EVENT_BYTES", 16)
    seen = []
    def parse(line):
        seen.append(line)
        return json.loads(line)
    monkeypatch.setattr(core, "json", SimpleNamespace(loads=parse))
    for _ in range(2):
        values = [" " * 17, "{}"]
        with pytest.raises(core.HostRefusal) as caught:
            list(core.claude_events(values if kind == "list" else iter(values)))
        assert_refusal(caught, "too_large")
        assert seen == []
    assert list(core.claude_events(["{}"] if kind == "list" else iter(["{}"]))) == [{}]
    assert seen == ["{}"]



def test_documented_safety_constants_are_pinned():
    assert core.MAX_ARGV_ATOMS == 128
    assert core.MAX_ARGV_ATOM_CHARS == 32768
    assert core.MAX_ARGV_CHARS == 131072
    assert core.MAX_EVENT_BYTES == 262144
    assert core.MAX_STREAM_BYTES == 262144
    assert core.MAX_EVENTS_PER_STREAM == 10000
    assert core.MAX_TRANSCRIPT_ENTRIES == 10000
    assert core.MAX_TRANSCRIPT_DEPTH == 128
    assert core.MAX_ROOT_CHARS == 32768


def test_stream_read_failure_is_typed_and_valid_retry_succeeds():
    class FailedRead:
        def __iter__(self):
            return self

        def __next__(self):
            raise OSError("untrusted-marker")
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            list(core.claude_events(FailedRead()))
        assert_refusal(caught, "io")
    assert list(core.claude_events("{}")) == list(legacy.claude_events("{}")) == [{}]


def test_argv_atom_count_exact_boundary_and_retry():
    argv = ["codex"] + ["-c", "a=b"] * 62 + ["exec", "resume", SESSION]
    assert len(argv) == 128
    assert core.session_verdict(core.CODEX, argv, SESSION) == legacy.session_verdict(
        core.CODEX, argv, SESSION) == "OWNED"
    over = argv + ["prompt"]
    assert len(over) == 129
    assert legacy.session_verdict(core.CODEX, over, SESSION) == "OWNED"
    assert core.session_verdict(core.CODEX, over, SESSION) == "HOLD"
    assert core.session_verdict(core.CODEX, argv, SESSION) == "OWNED"


def test_argv_single_atom_exact_boundary_and_retry():
    argv = ["codex", "exec", "resume", SESSION, "p" * 32768]
    assert core.session_verdict(core.CODEX, argv, SESSION) == legacy.session_verdict(
        core.CODEX, argv, SESSION) == "OWNED"
    over = argv[:-1] + [argv[-1] + "p"]
    assert legacy.session_verdict(core.CODEX, over, SESSION) == "OWNED"
    assert core.session_verdict(core.CODEX, over, SESSION) == "HOLD"
    assert core.session_verdict(core.CODEX, argv, SESSION) == "OWNED"


def test_argv_total_characters_exact_boundary_and_retry():
    argv = ["codex"] + ["-c", "k=" + "x" * 32766] * 3 + ["exec", "resume", SESSION]
    argv.append("p" * (131072 - sum(map(len, argv))))
    assert sum(map(len, argv)) == 131072
    assert max(map(len, argv)) == 32768
    assert core.session_verdict(core.CODEX, argv, SESSION) == legacy.session_verdict(
        core.CODEX, argv, SESSION) == "OWNED"
    over = argv[:-1] + [argv[-1] + "p"]
    assert sum(map(len, over)) == 131073
    assert legacy.session_verdict(core.CODEX, over, SESSION) == "OWNED"
    assert core.session_verdict(core.CODEX, over, SESSION) == "HOLD"
    assert core.session_verdict(core.CODEX, argv, SESSION) == "OWNED"


@pytest.mark.parametrize("shape", ["text", "bytes", "list", "iterator"])
def test_single_event_exact_byte_boundary_and_retry(shape):
    prefix, suffix = b'{"payload":"', b'"}'
    raw = prefix + b"x" * (262144 - len(prefix) - len(suffix)) + suffix
    assert len(raw) == 262144
    def supplied(value):
        if shape == "text":
            return value.decode("ascii")
        if shape == "bytes":
            return value
        if shape == "list":
            return [value]
        return iter([value])
    expected = list(legacy.claude_events(supplied(raw)))
    assert list(core.claude_events(supplied(raw))) == expected
    for _ in range(2):
        with pytest.raises(core.HostRefusal) as caught:
            list(core.claude_events(supplied(raw + b" ")))
        assert_refusal(caught, "too_large")
    assert list(core.claude_events(supplied(raw))) == expected


@pytest.mark.parametrize("token", [pytest.param("é", id="two_byte"),
    pytest.param("€", id="three_byte"), pytest.param("😀", id="four_byte")])
def test_unicode_event_boundary_is_utf8_bytes_not_character_count(token):
    prefix, suffix = '{"payload":"', '"}'
    payload_bytes = 262144 - len(prefix) - len(suffix)
    width = len(token.encode("utf-8"))
    raw = prefix + token * (payload_bytes // width) + "x" * (payload_bytes % width) + suffix
    assert len(raw.encode("utf-8")) == 262144
    expected = list(legacy.claude_events(raw))
    assert list(core.claude_events(raw)) == expected
    with pytest.raises(core.HostRefusal) as caught:
        list(core.claude_events(raw + " "))
    assert_refusal(caught, "too_large")
    assert list(core.claude_events(raw)) == expected


@pytest.mark.parametrize("shape", ["text", "list", "iterator"])
def test_unicode_overflow_refuses_before_parser_at_each_input_boundary(monkeypatch, shape):
    prefix, suffix = '{"payload":"', '"}'
    payload_bytes = 262144 - len(prefix) - len(suffix)
    raw = prefix + "é" * (payload_bytes // 2) + "x" * (payload_bytes % 2) + suffix + " "
    assert len(raw.encode("utf-8")) == 262145
    calls = []
    def unexpected_parse(value):
        calls.append(True)
        raise AssertionError("byte overflow reached parser")
    monkeypatch.setattr(core, "json", SimpleNamespace(loads=unexpected_parse))
    supplied = raw if shape == "text" else [raw] if shape == "list" else iter([raw])
    with pytest.raises(core.HostRefusal) as caught:
        list(core.claude_events(supplied))
    assert_refusal(caught, "too_large")
    assert calls == []


@pytest.mark.parametrize("shape", ["text", "list", "iterator"])
def test_event_count_exact_boundary_and_retry(shape):
    def supplied(count):
        if shape == "text":
            return "\n".join(["{}"] * count)
        if shape == "list":
            return ["{}"] * count
        return ("{}" for _ in range(count))
    expected = list(legacy.claude_events(supplied(10000)))
    assert len(expected) == 10000
    assert list(core.claude_events(supplied(10000))) == expected
    assert len(list(legacy.claude_events(supplied(10001)))) == 10001
    with pytest.raises(core.HostRefusal) as caught:
        list(core.claude_events(supplied(10001)))
    assert_refusal(caught, "too_large")
    assert list(core.claude_events(supplied(10000))) == expected


def test_transcript_entry_budget_exact_boundary_and_retry(tmp_path):
    root = make_store(tmp_path)
    for number in range(10000):
        (root / str(number)).touch()
    assert core.transcripts(core.CODEX, root, SESSION) == legacy.transcripts(core.CODEX, root, SESSION) == []
    extra = root / "extra"
    extra.touch()
    with pytest.raises(core.HostRefusal) as caught:
        core.transcripts(core.CODEX, root, SESSION)
    assert_refusal(caught, "too_large")
    extra.unlink()
    assert core.transcripts(core.CODEX, root, SESSION) == []


def test_transcript_depth_exact_boundary_and_retry(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    parent = root / "sessions"
    for _ in range(127):
        parent /= "d"
    parent.mkdir(parents=True)
    path = parent / ("rollout-" + SESSION + ".jsonl")
    path.touch()
    assert len(path.relative_to(root).parts) - 1 == 128
    assert core.transcripts(core.CODEX, root, SESSION) == legacy.transcripts(core.CODEX, root, SESSION) == [path]
    deeper = parent / "d"
    deeper.mkdir()
    path.rename(deeper / path.name)
    deepest = parent.stat()
    def bounded_open(name, flags, **options):
        if name == "d" and "dir_fd" in options:
            info = os.fstat(options["dir_fd"])
            if (info.st_dev, info.st_ino) == (deepest.st_dev, deepest.st_ino):
                raise AssertionError("directory opened beyond depth budget")
        return os.open(name, flags, **options)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": bounded_open}))
    with pytest.raises(core.HostRefusal) as caught:
        core.transcripts(core.CODEX, root, SESSION)
    assert_refusal(caught, "too_large")
    monkeypatch.setattr(core, "os", os)
    (deeper / path.name).rename(path)
    deeper.rmdir()
    assert core.transcripts(core.CODEX, root, SESSION) == [path]



@pytest.mark.parametrize("name,args,reason", [
    ("qualify", ("codex-cli", None), "invalid_record"),
    ("qualify", ("codex", True), "unqualified_host"),
    ("entrypoints", ("codex",), "invalid_record"),
    ("child_environment", ({}, "untrusted-marker"), "invalid_purpose"),
])
def test_other_legacy_refusals_are_typed(name, args, reason):
    with pytest.raises(ValueError):
        getattr(legacy, name)(*args)
    with pytest.raises(core.HostRefusal) as caught:
        getattr(core, name)(*args)
    assert_refusal(caught, reason)


def test_large_argv_cannot_enter_ownership_grammar():
    argv = ["codex"] + ["-c", "a=b"] * 65 + ["exec", "resume", SESSION]
    assert legacy.session_verdict(core.CODEX, argv, SESSION) == "OWNED"
    assert core.session_verdict(core.CODEX, argv, SESSION) == "HOLD"
    assert not core.matches_session(core.CODEX, argv, SESSION)
    assert core.descendant_verdict(argv, SESSION) == "HOLD"


def test_transcript_pattern_does_not_allow_overlapping_prefix_and_session(tmp_path):
    root = make_store(tmp_path)
    path = root / "sessions" / "rollout-.jsonl"
    path.parent.mkdir()
    path.write_text("{}")
    assert legacy.transcripts(core.CODEX, root, "rollout-") == []
    assert core.transcripts(core.CODEX, root, "rollout-") == []


def test_discovery_held_ancestor_survives_rename(tmp_path, monkeypatch):
    root = make_store(tmp_path) / "base"
    root.mkdir()
    actual = root / "projects" / "account" / (SESSION + ".jsonl")
    actual.parent.mkdir(parents=True)
    actual.write_text("{}")
    moved = tmp_path / "moved"
    outside = tmp_path / "outside"
    outside.mkdir()
    real_scan = os.scandir
    swapped = []
    def scanned(fd):
        if not swapped:
            root.rename(moved)
            root.mkdir()
            swapped.append(True)
        return real_scan(fd)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "scandir": scanned}))
    # Keep the real capability probe independent of the owned OS test boundary.
    monkeypatch.setattr(core, "descriptor_supported", lambda: True)
    assert core.transcripts(core.CLAUDE, root, SESSION) == [actual]
    assert list(root.iterdir()) == []
    assert (moved / "projects" / "account" / actual.name).read_text() == "{}"


def test_discovery_racing_directory_symlink_refuses_and_closes(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    projects = root / "projects"
    projects.mkdir()
    outside = root / "outside"
    outside.mkdir()
    # Probe link capability before entering a modelled directory open.
    probe = root / "probe"
    symlink_or_skip(outside, probe, target_is_directory=True)
    probe.unlink()
    real_open = os.open
    opened, closed = [], []
    def opened_fd(path, flags, **options):
        if path == "projects":
            projects.rename(root / "held")
            projects.symlink_to(outside, target_is_directory=True)
        fd = real_open(path, flags, **options)
        opened.append(fd)
        return fd
    def closed_fd(fd):
        closed.append(fd)
        os.close(fd)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": opened_fd, "close": closed_fd}))
    with pytest.raises(core.HostRefusal) as caught:
        core.transcripts(core.CLAUDE, root, SESSION)
    assert_refusal(caught, "unsafe_path")
    assert sorted(opened) == sorted(closed)


