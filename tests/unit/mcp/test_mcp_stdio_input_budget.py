"""Byte framing through the public stdio entry point, in both dispatch modes."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aegis_core.config import ENV_MANAGER_CONFIG, ENV_MANAGER_CONFIG_SHA256
from aegis_core import message_codec as codec, storage
from aegis_mcp import manager, server
from tests.unit.core.test_message_codec import make_store


MANAGER_LIMIT = 262144
REPOSITORY_LIMIT = 6 * codec.MAX_BYTES + 65536
DISCARD_LIMIT = 1048576
PING = b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n'
REPLY = {"jsonrpc": "2.0", "id": 7, "result": {}}
PARSE_ERROR = {"jsonrpc": "2.0", "id": None,
               "error": {"code": -32700, "message": "Parse error"}}


class BoundedInput(io.BytesIO):
    """An OS-stream boundary that refuses any unbounded read."""

    def __init__(self, data, max_bytes):
        super().__init__(data)
        self.max_bytes = max_bytes
        self.read_sizes = []

    def readline(self, size=-1):
        assert 0 < size <= self.max_bytes + 1, "transport must bound reads before allocation"
        self.read_sizes.append(size)
        return super().readline(size)


@pytest.fixture(params=["repository", "manager"])
def mode(request, tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    monkeypatch.delenv(ENV_MANAGER_CONFIG, raising=False)
    monkeypatch.delenv(ENV_MANAGER_CONFIG_SHA256, raising=False)
    monkeypatch.chdir(tmp_path)
    if request.param == "manager":
        monkeypatch.setenv(ENV_MANAGER_CONFIG, str(tmp_path / "manager.json"))
        monkeypatch.setenv(ENV_MANAGER_CONFIG_SHA256, "0" * 64)
    return request.param


@pytest.fixture
def frame_limit(mode):
    return MANAGER_LIMIT if mode == "manager" else REPOSITORY_LIMIT


def serve(monkeypatch, capsys, data, *, text=False, stream=None):
    if stream is None:
        limit = MANAGER_LIMIT if ENV_MANAGER_CONFIG in os.environ else REPOSITORY_LIMIT
        stream = io.StringIO(data.decode("utf-8")) if text else BoundedInput(data, limit)
    stdin = stream if text else io.TextIOWrapper(stream, encoding="utf-8")
    # Own the module reference; do not replace shared sys or OS functions.
    monkeypatch.setattr(server, "sys", SimpleNamespace(**{**vars(sys), "stdin": stdin}))
    monkeypatch.setattr(server, "harden_process", lambda: False)
    assert server.run_stdio_server() == 0
    captured = capsys.readouterr()
    assert "HOSTILE_MARKER" not in captured.out + captured.err
    return [json.loads(line) for line in captured.out.splitlines()], stream


def padded_ping(size, *, ending=b"\n", unit=b"x"):
    prefix = b'{"jsonrpc":"2.0","id":7,"method":"ping","params":{"padding":"'
    suffix = b'"}}' + ending
    count, remainder = divmod(size - len(prefix) - len(suffix), len(unit))
    return prefix + unit * count + b"x" * remainder + suffix


@pytest.mark.parametrize("ending", [b"\n", b"\r\n", b""], ids=["lf", "crlf", "eof"])
@pytest.mark.parametrize("unit", [b"x", "\U0001f600".encode("utf-8")], ids=["ascii", "utf8"])
@pytest.mark.parametrize("text", [False, True], ids=["binary", "embedded-text"])
def test_exact_byte_limit_is_accepted(mode, frame_limit, monkeypatch, capsys, ending, unit, text):
    data = padded_ping(frame_limit, ending=ending, unit=unit)
    assert len(data) == frame_limit
    replies, _ = serve(monkeypatch, capsys, data, text=text)
    assert replies == [REPLY]


@pytest.mark.parametrize("unit", [b"x", "\U0001f600".encode("utf-8")], ids=["ascii", "utf8"])
@pytest.mark.parametrize("text", [False, True], ids=["binary", "embedded-text"])
def test_one_byte_over_limit_is_refused_then_next_frame_is_served(mode, frame_limit, monkeypatch, capsys, unit, text):
    replies, _ = serve(monkeypatch, capsys, padded_ping(frame_limit + 1, unit=unit) + PING, text=text)
    assert replies == [PARSE_ERROR, REPLY]


def test_oversized_frame_suffix_is_never_a_request(mode, frame_limit, monkeypatch, capsys):
    # The ping after the first read belongs to the oversized frame, up to its LF.
    data = b"HOSTILE_MARKER" + b" " * frame_limit + PING + PING
    replies, stream = serve(monkeypatch, capsys, data)
    assert replies == [PARSE_ERROR, REPLY]
    assert stream.read_sizes and max(stream.read_sizes) <= frame_limit + 1


def test_discard_has_a_byte_budget_and_closes_without_reading_the_tail(mode, frame_limit, monkeypatch, capsys):
    data = b"x" * (frame_limit + DISCARD_LIMIT + 2) + b"\n" + PING
    replies, stream = serve(monkeypatch, capsys, data)
    assert replies == [PARSE_ERROR]
    assert stream.tell() <= frame_limit + 1 + DISCARD_LIMIT


def test_plain_iterator_stdin_is_refused_without_consuming_it(mode, monkeypatch, capsys):
    line = PING.decode("utf-8")
    stdin = iter([line])
    monkeypatch.setattr(server, "sys", SimpleNamespace(**{**vars(sys), "stdin": stdin}))
    monkeypatch.setattr(server, "harden_process", lambda: False)

    assert server.run_stdio_server() == 0

    captured = capsys.readouterr()
    assert [json.loads(frame) for frame in captured.out.splitlines()] == [PARSE_ERROR]
    assert captured.err == ""
    assert list(stdin) == [line]


@pytest.mark.parametrize("extra", [1, 4096])
def test_oversized_unterminated_frame_at_eof_is_refused_once(mode, frame_limit, monkeypatch, capsys, extra):
    replies, _ = serve(monkeypatch, capsys, b"x" * (frame_limit + extra))
    assert replies == [PARSE_ERROR]


@pytest.mark.parametrize("fail_at", [1, 2], ids=["read", "discard"])
@pytest.mark.parametrize("error_type", [OSError, ValueError], ids=["io-error", "closed-stream"])
def test_input_io_failure_closes_with_a_fixed_refusal(mode, frame_limit, monkeypatch, capsys, fail_at, error_type):
    class BrokenInput(BoundedInput):
        def readline(self, size=-1):
            if len(self.read_sizes) + 1 == fail_at:
                raise error_type("HOSTILE_MARKER")
            return super().readline(size)

    stream = BrokenInput(b"x" * (frame_limit + 1) + PING, frame_limit)
    replies, _ = serve(monkeypatch, capsys, b"", stream=stream)
    assert replies == [PARSE_ERROR]


@pytest.mark.parametrize("data", [b"", b" \t\r\n", b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'])
def test_eof_blank_lines_and_notifications_are_silent(mode, monkeypatch, capsys, data):
    replies, _ = serve(monkeypatch, capsys, data)
    assert replies == []


@pytest.mark.parametrize("data", [b'\xffHOSTILE_MARKER\n', b'{HOSTILE_MARKER\n', b'{"method":'])
def test_bad_encoding_json_and_partial_eof_are_parse_errors(mode, monkeypatch, capsys, data):
    replies, _ = serve(monkeypatch, capsys, data)
    assert replies == [PARSE_ERROR]


def test_invalid_utf8_recovers_at_next_lf(mode, monkeypatch, capsys):
    replies, _ = serve(monkeypatch, capsys, b'\xf0\x9f\n' + PING)
    assert replies == [PARSE_ERROR, REPLY]


def test_oversized_notification_and_whitespace_are_not_exempt(mode, frame_limit, monkeypatch, capsys):
    notification = b'{"jsonrpc":"2.0","method":"notifications/initialized","params":"'
    notification += b"x" * frame_limit + b'"}\n'
    replies, _ = serve(monkeypatch, capsys, notification + b" " * frame_limit + b"\n" + PING)
    assert replies == [PARSE_ERROR, PARSE_ERROR, REPLY]


def test_manager_keeps_strict_json_decoding(mode, monkeypatch, capsys):
    data = b'{"jsonrpc":"2.0","id":7,"method":"ping","params":{"a":1,"a":2}}\n'
    replies, _ = serve(monkeypatch, capsys, data)
    assert replies == ([PARSE_ERROR] if mode == "manager" else [REPLY])


@pytest.mark.parametrize("line", ["x" * (MANAGER_LIMIT + 1), "\U0001f600" * (MANAGER_LIMIT // 4 + 1)], ids=["ascii", "utf8"])
def test_direct_manager_decoder_retains_its_byte_limit(line):
    with pytest.raises(ValueError, match="^manager frame exceeds 262144 bytes$"):
        manager.decode_frame(line)


def test_packaged_entry_point_uses_utf8_bytes_independent_of_locale(mode, frame_limit):
    env = dict(os.environ, PYTHONIOENCODING="ascii", PYTHONPATH=str(Path(server.__file__).resolve().parents[1]))
    data = padded_ping(frame_limit + 1, unit="\U0001f600".encode("utf-8")) + PING
    done = subprocess.run([sys.executable, "-m", "aegis_mcp"], input=data,
                          capture_output=True, timeout=30, env=env)
    assert done.returncode == 0, done.stderr
    assert [json.loads(line) for line in done.stdout.splitlines()] == [PARSE_ERROR, REPLY]


@pytest.fixture
def message_workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    (root / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.delenv(ENV_MANAGER_CONFIG, raising=False)
    monkeypatch.delenv(ENV_MANAGER_CONFIG_SHA256, raising=False)
    monkeypatch.setenv("AEGIS_WORKSPACE", str(root))
    return root


def escaped_content(unit, size):
    empty_size = len(json.dumps({"fields": {}, "body": "", "refs": {}}, separators=(",", ":")))
    width = len(json.dumps(unit)[1:-1])
    count, remainder = divmod(size - empty_size, width)
    body = unit * count + "x" * remainder
    content = json.dumps({"fields": {}, "body": body, "refs": {}}, separators=(",", ":"))
    assert len(content.encode("utf-8")) == size
    return content, body


def message_frames(content, *, full_escape=False):
    initialize = {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                  "params": {"clientInfo": {"name": "stdio-budget-test"}}}
    write = {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
             "params": {"name": "aegis_msg_write", "arguments": {"kind": "text", "content": content}}}
    wire = json.dumps(write)
    if full_escape:
        assert content.isascii() and len(content) <= codec.MAX_BYTES
        # JSON also permits every ASCII content byte to use a six-byte escape,
        # even where the ordinary serializer would keep it literal or shorter.
        escaped = '"' + "".join("\\u%04x" % ord(char) for char in content) + '"'
        assert len(escaped) - 2 == 6 * len(content)
        wire = wire.replace(json.dumps(content), escaped, 1)
    return (json.dumps(initialize) + "\n" + wire + "\n").encode("utf-8")


@pytest.mark.parametrize("unit", ['"', "\\", "\x00"], ids=["quotes", "backslashes", "controls"])
@pytest.mark.parametrize("full_escape", [False, True], ids=["ordinary-json", "sixfold-json"])
def test_msg_write_at_compact_content_limit_reaches_the_handler(message_workspace, monkeypatch, capsys, unit, full_escape):
    content, _ = escaped_content(unit, codec.MAX_BYTES)
    data = message_frames(content, full_escape=full_escape)
    assert MANAGER_LIMIT < len(data) < REPOSITORY_LIMIT

    replies, _ = serve(monkeypatch, capsys, data)

    assert [reply["id"] for reply in replies] == [0, 11]
    # Content is admitted; code-authored record metadata then exceeds the separate
    # canonical-record budget. This is a tool refusal, not a transport parse error.
    assert replies[1]["result"]["isError"] is True
    assert json.loads(replies[1]["result"]["content"][0]["text"])["error"]["code"] == "E_LIMIT"


@pytest.mark.parametrize("unit", ['"', "\\", "\x00"], ids=["quotes", "backslashes", "controls"])
@pytest.mark.parametrize("full_escape", [False, True], ids=["ordinary-json", "sixfold-json"])
def test_valid_escaped_msg_write_at_content_limit_is_stored(message_workspace, monkeypatch, capsys, unit, full_escape):
    directory = message_workspace / ".aegis" / "state" / "messages"
    directory.mkdir(parents=True, mode=0o700)
    store = make_store(directory)
    try:
        # Leave room in the canonical record for server-authored metadata. Legal
        # trailing JSON whitespace brings the tool's content to its exact limit.
        content, body = escaped_content(unit, codec.MAX_BYTES - 1024)
        content += " " * (codec.MAX_BYTES - len(content.encode("utf-8")))
        assert len(content.encode("utf-8")) == codec.MAX_BYTES
        data = message_frames(content, full_escape=full_escape)
        assert MANAGER_LIMIT < len(data) < REPOSITORY_LIMIT

        replies, _ = serve(monkeypatch, capsys, data)

        assert [reply["id"] for reply in replies] == [0, 11]
        assert replies[1]["result"]["isError"] is False
        result = json.loads(replies[1]["result"]["content"][0]["text"])
        assert store.read(result["id"])["body"] == body
    finally:
        store.close()


def test_escaped_msg_write_refuses_unsupported_store_with_fixed_code(message_workspace, monkeypatch, capsys):
    # Patch this module's OS reference, not the shared os capability sets used by
    # pytest teardown. This refusal test also runs on unsupported platforms.
    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "supports_dir_fd": set()}))
    content, _ = escaped_content("\x00", codec.MAX_BYTES - 1024)
    content += " " * (codec.MAX_BYTES - len(content.encode("utf-8")))

    replies, _ = serve(monkeypatch, capsys, message_frames(content, full_escape=True))

    assert [reply["id"] for reply in replies] == [0, 11]
    assert replies[1]["result"]["isError"] is True
    assert json.loads(replies[1]["result"]["content"][0]["text"])["error"] == codec.CodecError("E_AUTH").as_dict()["error"]
