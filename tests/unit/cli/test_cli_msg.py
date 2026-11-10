"""Public message CLI contracts; codec output is passed through verbatim."""
import copy
from datetime import datetime, timezone
import io
from itertools import combinations
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest
from conftest import symlink_or_skip

from aegis_cli.cli import main
from aegis_core import message_codec as codec
from tests.unit.core.test_message_codec import make_store


GOLDENS = json.loads((Path(__file__).parents[1] / "core" / "message_codec_goldens.json").read_text(encoding="utf-8"))
SELECTOR_MESSAGE = (
    "invalid selector or cursor; fields (--fields): at most 16 selectors of 1-1024 characters, depth 8; "
    "dotted names and zero-based indices, one-level *; final row projection "
    "findings.*.{id,severity,file,line}; one selector per MCP array entry; "
    "CLI entries may be comma-separated or repeated; no regex or recursive wildcard; "
    "paths start in fields unless prefixed by schema,kind,meta,fields,body,spans,refs; "
    "spans (--spans): at most 64 zero-based indices, each below 10000 and present in the body outline; "
    "expand (--expand): at most 64 named refs, one level within max_chars (--max-chars); "
    "since (--since): 0 starts log rows, otherwise n:sha256(canonical rows[:n]); re-read without since if stale"
)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    (root / ".aegis").mkdir(parents=True)
    monkeypatch.chdir(root)
    monkeypatch.delenv("AEGIS_WORKSPACE", raising=False)
    return root


@pytest.fixture
def store(tmp_path):
    directory = tmp_path / "records"
    directory.mkdir(mode=0o700)
    instance = make_store(directory)
    yield instance
    instance.close()


def invoke(store, *argv):
    return main(["msg", "--store", str(store.root), *argv])


def assert_error(output, code, detail=None):
    assert not output.err
    messages = {
        "arguments": "invalid arguments; see aegis msg ACTION --help",
        "workspace": "workspace is not initialized; run aegis init",
        "binding": "workspace binding refused; check --workspace / AEGIS_WORKSPACE",
        "root": "workspace root refused; choose a project directory",
        "attachment": "workspace attachment unavailable; check permissions",
        "input": "input file unreadable",
        "write_ref": "write reference must be a full 64-hex id present in the target store",
    }
    details = detail if isinstance(detail, tuple) else (detail,)
    expected = []
    for fixed_detail in details:
        error = codec.CodecError(code, detail=fixed_detail).as_dict()
        if code == "E_SELECTOR":
            error["error"]["message"] = SELECTOR_MESSAGE
        if fixed_detail in messages:
            error["error"]["message"] = messages[fixed_detail]
        expected.append(json.dumps(error, separators=(",", ":")) + "\n")
    assert output.out in expected


def content(record):
    return {key: record[key] for key in ("fields", "body", "refs")}


@pytest.mark.parametrize("action,flags", [
    ("write", ["--kind", "--in", "--store"]),
    ("read", ["--fields", "--spans", "--outline", "--since", "--expand",
              "--format", "--max-chars", "--store"]),
    ("verify", ["REF"]),
])
def test_msg_help(action, flags, capsys):
    with pytest.raises(SystemExit) as caught:
        main(["msg", action, "--help"])
    assert caught.value.code == 0
    output = capsys.readouterr()
    assert not output.err
    for flag in flags:
        assert flag in output.out


@pytest.mark.parametrize("argv", [
    ["msg"],
    ["msg", "HOSTILE_MARKER"],
    ["msg", "read"],
    ["msg", "read", "a" * 64, "--HOSTILE_MARKER"],
    ["msg", "read", "a" * 64, "--spans"],
    ["msg", "read", "a" * 64, "--format"],
    ["msg", "write", "--kind", "text"],
    ["msg", "verify"],
])
def test_msg_usage_errors_are_fixed_json(argv, capsys):
    assert main(argv) == 2
    output = capsys.readouterr()
    assert not output.err
    assert json.loads(output.out) == {
        "error": {"code": "E_FORMAT", "message": "invalid arguments; see aegis msg ACTION --help"}
    }
    assert "HOSTILE_MARKER" not in output.out


@pytest.mark.parametrize("argv,secret", [
    (["--store", "/private/customer-X", "msg", "verify", "REF"], "/private/customer-X"),
    (["--bogus", "SECRETVAL", "msg", "read", "REF"], "SECRETVAL"),
    (["--workspace", "/private/customer-Y", "msg", "write", "--kind", "record"], "/private/customer-Y"),
    (["msg", "--bogus", "SECRETVAL", "read", "REF"], "SECRETVAL"),
    (["scan", "--bogus", "SECRETVAL", "msg"], "SECRETVAL"),
    (["--workspace", "msg", "scan", "--bogus", "SECRETVAL"], "SECRETVAL"),
    (["--json=sk-private-HOSTILE_MARKER", "--", "msg", "verify", "a" * 64], "sk-private-HOSTILE_MARKER"),
    (["--store", "/private/HOSTILE_MARKER", "msg", "verify", "a" * 64], "/private/HOSTILE_MARKER"),
    (["--bogus", "SECRETVAL", "--", "msg"], "SECRETVAL"),
])
def test_round6_msg_argv_errors_never_echo_values(argv, secret, capsys):
    assert main(argv) == 2
    output = capsys.readouterr()
    assert_error(output, "E_FORMAT", "arguments")
    assert secret not in output.out and secret not in output.err


def test_round7_abbreviated_workspace_after_separator_is_fixed_json(workspace, capsys):
    assert not (workspace / "verify").exists()
    assert main(["--work", "verify", "--", "msg", "read", "a" * 64]) == 2
    output = capsys.readouterr()
    code = json.loads(output.out)["error"]["code"]
    details = {"E_FORMAT": ("arguments",), "E_AUTH": (None, "root", "binding", "workspace", "attachment"),
               "E_REF": (None, "resolution")}
    assert code in {"E_FORMAT", "E_AUTH", "E_REF"}
    assert_error(output, code, details[code])
    assert "verify" not in output.out and "verify" not in output.err


@pytest.mark.parametrize("argv,echoed", [
    (["scan", "--bogus", "x"], "unrecognized arguments: --bogus\n"),
    (["--bogus", "SECRETVAL", "--", "ordinary"], "SECRETVAL"),
])
def test_round6_non_msg_errors_keep_argparse(argv, echoed, capsys):
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "usage: aegis" in output.err and echoed in output.err


def test_round6_successful_non_msg_parse_with_msg_value_is_unchanged(capsys):
    for argv in (["scan", "--help"], ["--workspace", "msg", "scan", "--help"]):
        with pytest.raises(SystemExit) as caught:
            main(argv)
        assert caught.value.code == 0
        output = capsys.readouterr()
        assert not output.err
        if len(argv) == 2:
            expected = output.out
        else:
            assert output.out == expected


def test_round6_missing_anchored_capabilities_refuse_fixed_json(tmp_path, workspace, monkeypatch, capsys):
    directory = tmp_path / "unsupported-store"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(os, "supports_dir_fd", set())
    assert main(["msg", "--store", str(directory), "verify", "a" * 64]) == 2
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out == json.dumps({"error": {"code": "E_AUTH", "message":
        "store access refused: unsafe directory or platform lacks anchored file operations; use a supported real directory"}},
        separators=(",", ":")) + "\n"


@pytest.mark.parametrize("token", [
    b"0.30000000000000000001", b"1e2", b"12345678901234567890.5", b"1.0e0", b"-0",
])
def test_round6_write_refuses_changed_numbers(token, store, workspace, monkeypatch, capsys):
    payload = b'{"fields":{"value":' + token + b'},"body":"","refs":{}}'
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "record", "--in", "-") == 2
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {"error": {"code": "E_FORMAT", "message":
        "number cannot be preserved verbatim; use canonical numeric text"}}
    assert token.decode() not in output.out
    assert list(store.root.iterdir()) == []


@pytest.mark.parametrize("token", [b"0", b"9007199254740993", b"12345678901234567890", b"0.5", b"-1.25"] + [
    json.dumps(value).encode("ascii") for value in (0.1, 0.3, 1e+20, 1e-7, 1.2345678901234567)
])
def test_round6_write_stores_numeric_bytes_verbatim(token, store, workspace, monkeypatch, capsys):
    payload = b'{"fields":{"value":' + token + b'},"body":"","refs":{}}'
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "record", "--in", "-") == 0
    output = capsys.readouterr()
    assert not output.err
    rid = json.loads(output.out)["id"]
    stored = (store.root / (rid + ".json")).read_bytes()
    expected = store.read(rid)
    expected["fields"]["value"] = None
    assert stored == codec.canonical(expected).replace(b'"value":null', b'"value":' + token)


@pytest.mark.parametrize("action", ["read", "verify", "write"])
@pytest.mark.parametrize("directory", ["", ".", "nested"])
@pytest.mark.usefixtures("store")
def test_round6b_store_preserves_relative_root_refusals(action, directory, workspace, monkeypatch, capsys):
    (workspace / "nested").mkdir(mode=0o700)
    payload = json.dumps({"fields": {}, "body": "", "refs": {}}).encode()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    def snapshot():
        return {str(p.relative_to(workspace)): None if p.is_dir() else p.read_bytes()
                for p in workspace.rglob("*")}
    before = snapshot()
    argv = (["write", "--kind", "text", "--in", "-"] if action == "write"
            else [action, "a" * 64])
    assert main(["msg", "--store", directory, *argv]) == 2
    assert_error(capsys.readouterr(), "E_AUTH", "path")
    assert snapshot() == before


@pytest.mark.parametrize("record_state", ["valid", "corrupt", "missing"])
def test_round6b_selector_count_precedes_allocation_and_record_read(record_state, store, workspace, capsys):
    rid = store.write(GOLDENS[0]["record"])
    if record_state == "corrupt":
        (store.root / (rid + ".json")).write_bytes(b"HOSTILE_MARKER")
    elif record_state == "missing":
        rid = "a" * 64
    slices = [0]
    class CountedExpression(str):
        def __getitem__(self, key):
            if isinstance(key, slice):
                slices[0] += 1
            return super().__getitem__(key)
    expression = CountedExpression("," * 4096)
    assert invoke(store, "read", rid, "--fields", expression) == 2
    assert_error(capsys.readouterr(), "E_SELECTOR")
    assert slices[0] <= 17


@pytest.mark.parametrize("groups", ["single", "repeated"])
def test_round6b_sixteen_selectors_equal_core(groups, store, workspace, capsys):
    value = copy.deepcopy(next(g["record"] for g in GOLDENS if g["record"]["kind"] == "review.v1"))
    rid = store.write(value)
    value = store.read(rid)
    selectors = ["schema", "kind", "body", "meta", "meta.from", "meta.host", "meta.session", "meta.created_at",
                 "fields", "verdict", "reasoning_summary", "coverage_gaps", "checked", "findings",
                 "prior_findings", "findings.*.id"]
    assert len(selectors) == 16
    flags = (["--fields", ",".join(selectors)] if groups == "single"
             else ["--fields", ",".join(selectors[:8]), "--fields", ",".join(selectors[8:])])
    assert invoke(store, "read", rid, *flags) == 0
    output = capsys.readouterr()
    assert not output.err
    assert output.out == codec.read_view(value, selectors=selectors, store=store)


def test_abbreviated_global_workspace_keeps_json_usage_errors(workspace, capsys):
    assert main(["--work", str(workspace), "msg", "read", "a" * 64, "--HOSTILE_MARKER"]) == 2
    assert_error(capsys.readouterr(), "E_FORMAT", "arguments")


@pytest.mark.parametrize("golden", GOLDENS, ids=lambda g: g["record"]["kind"])
@pytest.mark.parametrize("format", ["json", "md", "tsv"])
def test_read_goldens_equal_core_bytes(golden, format, store, workspace, capsys):
    rid = store.write(golden["record"])
    assert rid == golden["id"]
    value = store.read(rid)
    for reference in (rid, rid[:16]):
        assert invoke(store, "read", reference, "--format", format) == 0
        output = capsys.readouterr()
        assert not output.err
        assert output.out == codec.read_view(value, store=store, format=format)


@pytest.mark.parametrize("flags,options", [
    (["--fields", "verdict", "--fields", "findings.*.{id,severity,file,line}"],
     {"selectors": ["verdict", "findings.*.{id,severity,file,line}"]}),
    (["--fields", "verdict,findings.*.{id,severity,file,line}"],
     {"selectors": ["verdict", "findings.*.{id,severity,file,line}"]}),
    (["--fields", "verdict", "--fields", "findings.*.{id,severity}"],
     {"selectors": ["verdict", "findings.*.{id,severity}"]}),
    (["--outline"], {"outline": True}),
    (["--fields", "verdict", "--outline"], {"selectors": ["verdict"], "outline": True}),
])
def test_read_selection_equal_core(flags, options, store, workspace, capsys):
    value = next(g["record"] for g in GOLDENS if g["record"]["kind"] == "review.v1")
    rid = store.write(value)
    value = store.read(rid)
    assert invoke(store, "read", rid, *flags) == 0
    output = capsys.readouterr()
    assert not output.err
    assert output.out == codec.read_view(value, store=store, **options)


def test_read_spans_refs_cursor_and_missing(store, workspace, capsys):
    child = GOLDENS[0]["record"]
    child_id = store.write(child)
    value = copy.deepcopy(next(g["record"] for g in GOLDENS if g["record"]["kind"] == "log"))
    value.update(body="αβ\nsecond", spans=[[0, 2, "first"], [3, 9, "second"]], refs={"child": child_id})
    rid = store.write(value)
    value = store.read(rid)
    cases = [
        (["--spans", "0", "--spans", "1"], {"spans": [0, 1]}),
        (["--expand", "child"], {"expand": ["child"]}),
        (["--fields", "refs"], {"selectors": ["refs"]}),
        (["--since", "0"], {"since": "0"}),
        (["--fields", "rows.*.time"], {"selectors": ["rows.*.time"]}),
    ]
    for flags, options in cases:
        assert invoke(store, "read", rid, *flags) == 0
        output = capsys.readouterr()
        assert not output.err
        assert output.out == codec.read_view(value, store=store, **options)
    cursor = json.loads(codec.read_view(value, since="0", store=store))["cursor"]
    assert invoke(store, "read", rid, "--since", cursor) == 0
    assert capsys.readouterr().out == codec.read_view(value, since=cursor, store=store)


@pytest.mark.parametrize("golden", GOLDENS, ids=lambda g: g["record"]["kind"])
@pytest.mark.parametrize("source", ["file", "stdin"])
def test_write_code_authors_record(golden, source, store, workspace, tmp_path, monkeypatch, capsys):
    payload = json.dumps(content(golden["record"]), ensure_ascii=False).encode()
    if source == "stdin":
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
        filename = "-"
    else:
        path = tmp_path / "content.json"
        path.write_bytes(payload)
        filename = str(path)
    before = datetime.now(timezone.utc).replace(microsecond=0)
    assert invoke(store, "write", "--kind", golden["record"]["kind"], "--in", filename) == 0
    after = datetime.now(timezone.utc).replace(microsecond=0)
    output = capsys.readouterr()
    assert not output.err
    result = json.loads(output.out)
    assert set(result) == {"id", "ref"}
    assert re.fullmatch("[0-9a-f]{64}", result["id"])
    assert result["ref"] == result["id"][:16]
    record = store.read(result["id"])
    assert content(record) == content(golden["record"])
    assert record["schema"] == "aegis.msg/1"
    assert record["kind"] == golden["record"]["kind"]
    assert record["spans"] == []
    assert {k: record["meta"][k] for k in ("from", "host", "session")} == {
        "from": "cli", "host": "cli", "session": ""}
    stamp = record["meta"]["created_at"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp)
    assert before <= datetime.fromisoformat(stamp.replace("Z", "+00:00")) <= after


def test_write_derives_character_spans(store, workspace, monkeypatch, capsys):
    body = "preamble α\n# One\nαβ\n## Two ##\r\nbody\n####### no\n#nospace\n###### Three\nend"
    payload = {"fields": {}, "body": body, "refs": {}}
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode())))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 0
    rid = json.loads(capsys.readouterr().out)["id"]
    record = store.read(rid)
    starts = [body.index("# One"), body.index("## Two"), body.index("###### Three")]
    assert record["spans"] == [[starts[0], starts[1], "One"],
                               [starts[1], starts[2], "Two"], [starts[2], len(body), "Three"]]
    assert invoke(store, "read", rid, "--spans", "0", "--spans", "2") == 0
    assert capsys.readouterr().out == codec.read_view(record, spans=[0, 2], store=store)


@pytest.mark.parametrize("payload,code", [
    (b"HOSTILE_MARKER", "E_FORMAT"),
    (b"\xff", "E_FORMAT"),
    (b"[]", "E_FORMAT"),
    (b"{}", "E_FORMAT"),
    (b'{"fields":{},"body":"","body":"HOSTILE_MARKER","refs":{}}', "E_FORMAT"),
    (b'{"fields":{},"body":"\\ud800","refs":{}}', "E_FORMAT"),
    (b'{"fields":{},"body":NaN,"refs":{}}', "E_FORMAT"),
    (b'{"fields":{},"body":42,"refs":{}}', "E_FORMAT"),
    (b"[" * 40 + b"0" + b"]" * 40, "E_LIMIT"),
    (b"x" * (codec.MAX_BYTES + 1), "E_LIMIT"),
], ids=["not-json", "not-utf8", "array", "missing-content", "duplicate-key",
        "surrogate", "nan", "body-type", "depth", "bytes"])
def test_write_rejects_bad_content(payload, code, store, workspace, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 2
    assert_error(capsys.readouterr(), code, "record" if code == "E_LIMIT" else None)
    assert list(store.root.iterdir()) == []


@pytest.mark.parametrize("key", ["meta", "spans", "schema", "kind", "HOSTILE_MARKER"])
def test_write_refuses_caller_owned_envelope(key, store, workspace, monkeypatch, capsys):
    payload = dict(content(GOLDENS[0]["record"]), **{key: "HOSTILE_MARKER"})
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode())))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 2
    assert_error(capsys.readouterr(), "E_FORMAT")
    assert list(store.root.iterdir()) == []


def test_stdin_read_is_bounded(store, workspace, monkeypatch, capsys):
    class BoundedInput:
        def read(self, size):
            assert 0 < size <= codec.MAX_BYTES + 1
            return b"x" * size
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BoundedInput()))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 2
    assert_error(capsys.readouterr(), "E_LIMIT", "record")


@pytest.mark.parametrize("case", ["depth", "nodes", "refs", "encoded-bytes"])
def test_write_core_limits_are_fixed_errors(case, store, workspace, monkeypatch, capsys):
    value = content(GOLDENS[1]["record"])
    if case == "depth":
        nested = []
        for _ in range(33):
            nested = [nested]
        value["fields"] = {"value": {"nested": nested}}
    elif case == "nodes":
        value["fields"] = {"value": {"nodes": [0] * 10000}}
    elif case == "refs":
        value["refs"] = {"ref" + str(n): "a" * 64 for n in range(65)}
    else:
        value["body"] = "é" * (codec.MAX_BYTES // 3)
    payload = json.dumps(value, ensure_ascii=False).encode()
    assert len(payload) <= codec.MAX_BYTES
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "record", "--in", "-") == 2
    assert_error(capsys.readouterr(), "E_LIMIT", "record")
    assert list(store.root.iterdir()) == []


@pytest.mark.parametrize("case", ["input-bytes", "span-count"])
def test_write_at_input_limits(case, store, workspace, monkeypatch, capsys):
    value = {"fields": {}, "body": "# h\n" * 65 if case == "span-count" else "", "refs": {}}
    payload = json.dumps(value).encode()
    if case == "input-bytes":
        payload += b" " * (codec.MAX_BYTES - len(payload))
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 0
    rid = json.loads(capsys.readouterr().out)["id"]
    assert len(store.read(rid)["spans"]) == (65 if case == "span-count" else 0)


def test_missing_input_file_is_fixed_error(store, workspace, capsys):
    assert invoke(store, "write", "--kind", "text", "--in", "HOSTILE_MARKER.json") == 2
    assert_error(capsys.readouterr(), "E_AUTH", "input")


@pytest.mark.parametrize("flags,code,detail", [
    (["--fields", "HOSTILE_MARKER"], "E_SELECTOR", None),
    (["--fields", ",".join(["body"] * 17)], "E_SELECTOR", None),
    (["--spans", "0"], "E_SPAN", None),
    (["--spans", "-1"], "E_SPAN", None),
    (["--since", "HOSTILE_MARKER"], "E_SELECTOR", None),
    (["--expand", "HOSTILE_MARKER"], "E_REF", None),
    (["--max-chars", "1"], "E_LIMIT", None),
    (["--max-chars", "-1"], "E_LIMIT", None),
    (["--max-chars", "HOSTILE_MARKER"], "E_LIMIT", None),
    (["--spans", "HOSTILE_MARKER"], "E_SPAN", None),
    (["--format", "HOSTILE_MARKER"], "E_FORMAT", "format"),
])
def test_read_refusals_are_total(flags, code, detail, store, workspace, capsys):
    rid = store.write(GOLDENS[0]["record"])
    assert invoke(store, "read", rid, *flags) == 2
    assert_error(capsys.readouterr(), code, detail)


@pytest.mark.parametrize("action", ["read", "verify"])
@pytest.mark.parametrize("reference,detail", [("HOSTILE_MARKER", "handle"), ("a" * 64, "resolution")])
def test_invalid_or_missing_ref(action, reference, detail, store, workspace, capsys):
    assert invoke(store, action, reference) == 2
    assert_error(capsys.readouterr(), "E_REF", detail)


def test_verify_checks_bytes_and_reports_full_id(store, workspace, capsys):
    rid = store.write(GOLDENS[0]["record"])
    assert invoke(store, "verify", rid[:16]) == 0
    assert json.loads(capsys.readouterr().out) == {"id": rid, "ref": rid[:16], "verified": True}
    (store.root / (rid + ".json")).write_bytes(b"HOSTILE_MARKER")
    for action in ("verify", "read"):
        assert invoke(store, action, rid) == 2
        assert_error(capsys.readouterr(), "E_HASH")


@pytest.mark.parametrize("position", ["global", "group", "action"])
@pytest.mark.usefixtures("store")
def test_default_store_uses_target_workspace(position, workspace, tmp_path, monkeypatch, capsys):
    target = tmp_path / "target"
    (target / ".aegis").mkdir(parents=True)
    options = ["--workspace", str(target), "--json", "--plain"]
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(content(GOLDENS[0]["record"])).encode())))
    argv = ["msg", "write", "--kind", "text", "--in", "-"]
    index = {"global": 0, "group": 1, "action": 2}[position]
    argv[index:index] = options
    assert main(argv) == 0
    rid = json.loads(capsys.readouterr().out)["id"]
    directory = target / ".aegis" / "state" / "messages"
    assert (directory / (rid + ".json")).is_file()
    assert directory.stat().st_mode & 0o077 == 0
    assert (directory.parent / ".gitignore").read_text().endswith("*\n")
    assert not (workspace / ".aegis" / "state").exists()
    for action in ("read", "verify"):
        assert main(["msg", action, rid[:16], "--workspace", str(target)]) == 0
        capsys.readouterr()


@pytest.mark.parametrize("case", ["missing", "symlink", pytest.param("public", marks=
    pytest.mark.skipif(os.name == "nt", reason="POSIX permission modes"))])
@pytest.mark.usefixtures("store")
def test_override_store_refuses_unsafe_root(case, workspace, tmp_path, capsys):
    path = tmp_path / "override"
    if case == "symlink":
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        symlink_or_skip(real, path, target_is_directory=True)
    elif case == "public":
        path.mkdir(mode=0o777)
        path.chmod(0o777)
    assert main(["msg", "verify", "a" * 64, "--store", str(path)]) == 2
    assert_error(capsys.readouterr(), "E_AUTH", "private" if case == "public" else None)
    assert not (workspace / ".aegis" / "state").exists()
    if case == "missing":
        assert not path.exists()


def test_default_store_refuses_linked_state(workspace, tmp_path, capsys):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    symlink_or_skip(elsewhere, workspace / ".aegis" / "state", target_is_directory=True)
    assert main(["msg", "verify", "a" * 64]) == 2
    assert_error(capsys.readouterr(), "E_AUTH")
    assert list(elsewhere.iterdir()) == []


def test_workspace_pin_conflict_is_fixed_json(workspace, tmp_path, monkeypatch, capsys):
    other = tmp_path / "other"
    (other / ".aegis").mkdir(parents=True)
    monkeypatch.setenv("AEGIS_WORKSPACE", str(other))
    assert main(["msg", "--workspace", str(workspace), "verify", "a" * 64]) == 2
    assert_error(capsys.readouterr(), "E_AUTH", "binding")


@pytest.mark.parametrize("target", ["home", "root"])
def test_msg_denied_workspace_has_distinct_fixed_error(target, workspace, tmp_path, monkeypatch, capsys):
    home = tmp_path / "private-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    path = home if target == "home" else Path(workspace.anchor)
    assert main(["--workspace", str(path), "msg", "verify", "a" * 64]) == 2
    assert_error(capsys.readouterr(), "E_AUTH", "root")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission modes")
def test_msg_unreadable_discovery_directory_is_fixed_json(workspace, capsys):
    from aegis_core.workspace.layout import WorkspaceLayout

    legacy = WorkspaceLayout(workspace).legacy_rule_dirs[0].parent
    legacy.mkdir(mode=0o700)
    legacy.chmod(0)
    try:
        assert main(["msg", "verify", "a" * 64]) == 2
        assert_error(capsys.readouterr(), "E_AUTH", "attachment")
    finally:
        legacy.chmod(0o700)


@pytest.mark.parametrize("reference", ["typo", "other-store", "prefix", "malformed"])
def test_write_refuses_unresolvable_refs(reference, store, workspace, tmp_path, monkeypatch, capsys):
    directory = tmp_path / "other-records"
    directory.mkdir(mode=0o700)
    with_other = make_store(directory)
    try:
        child = with_other.write(GOLDENS[0]["record"])
    finally:
        with_other.close()
    if reference == "typo":
        child = "a" * 64
    elif reference == "prefix":
        child = store.write(GOLDENS[0]["record"])[:16]
    elif reference == "malformed":
        child = "HOSTILE_MARKER"
    before = {p.name: p.read_bytes() for p in store.root.iterdir()}
    payload = json.dumps({"fields": {}, "body": "parent", "refs": {"child": child}}).encode()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 2
    assert_error(capsys.readouterr(), "E_REF", "write_ref")
    assert {p.name: p.read_bytes() for p in store.root.iterdir()} == before


def test_write_resolves_refs_in_target_store(store, workspace, monkeypatch, capsys):
    child = store.write(GOLDENS[0]["record"])
    payload = json.dumps({"fields": {}, "body": "parent", "refs": {"child": child}}).encode()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 0
    rid = json.loads(capsys.readouterr().out)["id"]
    assert invoke(store, "read", rid) == 0
    assert capsys.readouterr().out == codec.read_view(store.read(rid), store=store)


@pytest.mark.parametrize("flag,token,code", [
    ("--spans", "00", "E_SPAN"), ("--spans", "+0", "E_SPAN"),
    ("--spans", "10000", "E_SPAN"), ("--spans", "9" * 5000, "E_SPAN"),
    ("--max-chars", "060000", "E_LIMIT"), ("--max-chars", "16777217", "E_LIMIT"),
    ("--max-chars", "9" * 5000, "E_LIMIT"),
])
def test_msg_numeric_strings_are_bounded(flag, token, code, store, workspace, capsys):
    rid = store.write(GOLDENS[0]["record"])
    assert invoke(store, "read", rid, flag, token) == 2
    assert_error(capsys.readouterr(), code)


@pytest.mark.parametrize("encoding", ["utf-8", "ascii"])
@pytest.mark.usefixtures("store")
def test_installed_entrypoint_write_read_verify(workspace, encoding):
    source = Path(__file__).resolve().parents[3]
    env = dict(os.environ, PYTHONPATH=str(source), PYTHONIOENCODING=encoding)
    prefix = [sys.executable, "-m", "aegis_cli.cli", "--workspace", str(workspace), "msg"]
    payload = json.dumps(content(GOLDENS[0]["record"])).encode()
    written = subprocess.run([*prefix, "write", "--kind", "text", "--in", "-"], input=payload,
                             capture_output=True, env=env, timeout=15)
    assert written.returncode == 0, written.stderr
    rid = json.loads(written.stdout)["id"]
    for action in ("read", "verify"):
        result = subprocess.run([*prefix, action, rid], capture_output=True, env=env, timeout=15)
        assert result.returncode == 0, result.stderr
        assert not result.stderr
        assert json.loads(result.stdout)["ref"] == rid[:16]
        if action == "read":
            assert json.loads(result.stdout)["data"]["body"] == GOLDENS[0]["record"]["body"]


@pytest.mark.parametrize("flags", [
    ["--json=sk-private-HOSTILE_MARKER"],
    ["--plain=sk-private-HOSTILE_MARKER"],
    ["--work", "target", "--json=sk-private-HOSTILE_MARKER"],
])
def test_malformed_global_options_do_not_echo_values(flags, capsys):
    assert main([*flags, "msg", "verify", "a" * 64]) == 2
    assert_error(capsys.readouterr(), "E_FORMAT", "arguments")


@pytest.mark.parametrize("argv", [
    ["msg", "write", "--kin", "text", "--in", "-"],
    ["msg", "write", "--kind", "text", "--i", "-"],
    ["msg", "--stor", "HOSTILE_MARKER", "verify", "a" * 64],
])
def test_message_option_abbreviations_are_refused(argv, capsys):
    assert main(argv) == 2
    assert_error(capsys.readouterr(), "E_FORMAT", "arguments")


@pytest.mark.parametrize("flags,options", [
    (["--fields", "body"], {"selectors": ["body"]}),
    (["--spans", "0"], {"spans": [0]}),
])
def test_selection_options_before_reference_preserve_it(flags, options, store, workspace, capsys):
    value = copy.deepcopy(GOLDENS[0]["record"])
    value["spans"] = [[0, 4, "start"]]
    rid = store.write(value)
    assert invoke(store, "read", *flags, rid) == 0
    assert capsys.readouterr().out == codec.read_view(store.read(rid), store=store, **options)


@pytest.mark.parametrize("action", ["read", "verify"])
@pytest.mark.parametrize("existing_state", [False, True])
def test_missing_default_store_read_never_creates_state(action, existing_state, workspace, capsys):
    if existing_state:
        state = workspace / ".aegis" / "state"
        state.mkdir()
        (state / "sentinel").write_bytes(b"unchanged")
    def snapshot():
        return {str(p.relative_to(workspace)): None if p.is_dir() else p.read_bytes()
                for p in workspace.rglob("*")}
    before = snapshot()
    assert main(["msg", action, "a" * 64]) == 2
    assert_error(capsys.readouterr(), "E_REF", "resolution")
    assert snapshot() == before


def test_cli_kinds_equal_core_schemas():
    from aegis_cli.msg import KINDS
    assert KINDS == tuple(codec.KIND_SCHEMAS)


def test_registry_and_help_do_not_load_message_codec():
    source = str(Path(__file__).resolve().parents[3])
    script = ("import sys; import aegis_cli.registry; "
              "assert not any(n.startswith('aegis_core.message_codec') for n in sys.modules); "
              "from aegis_cli.cli import _build_parser; _build_parser(); "
              "assert not any(n.startswith('aegis_core.message_codec') for n in sys.modules)")
    result = subprocess.run([sys.executable, "-c", script], env=dict(os.environ, PYTHONPATH=source),
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_cli_write_uses_shared_composition(store, workspace, monkeypatch, capsys):
    calls, original = [], codec.compose
    def observed(kind, payload, meta):
        calls.append((kind, payload, meta))
        return original(kind, payload, meta)
    monkeypatch.setattr(codec, "compose", observed)
    payload = json.dumps({"fields": {}, "body": "# real\n```\n# fake\n```\n", "refs": {}}).encode()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 0
    rid = json.loads(capsys.readouterr().out)["id"]
    assert len(calls) == 1
    kind, supplied, meta = calls[0]
    assert (kind, supplied) == ("text", payload)
    assert store.read(rid) == codec.parse(codec.canonical(original(kind, supplied, meta)))
    assert store.read(rid)["spans"] == [[0, len(json.loads(payload)["body"]), "real"]]


@pytest.mark.parametrize("action", ["read", "verify", "write"])
@pytest.mark.parametrize("override_store", [False, True])
@pytest.mark.parametrize("explicit_workspace", [False, True])
def test_argon_uninitialized_repository_is_unchanged(action, override_store, explicit_workspace,
                                                    store, workspace, monkeypatch, capsys):
    inner = workspace / "inner"
    (inner / ".git").mkdir(parents=True)
    (inner / "sentinel").write_bytes(b"unchanged")
    monkeypatch.chdir(inner)
    monkeypatch.setattr(sys, "stdin", None)  # Refuse before even reading write input.
    def snapshot():
        return {str(p.relative_to(inner)): None if p.is_dir() else p.read_bytes()
                for p in inner.rglob("*")}
    before = snapshot()
    argv = ["msg"]
    if override_store:
        argv += ["--store", str(store.root)]
    argv += (["write", "--kind", "text", "--in", "-"] if action == "write"
             else [action, "a" * 64])
    if explicit_workspace:
        argv = ["--workspace", str(inner), *argv]
    assert main(argv) == 2
    assert_error(capsys.readouterr(), "E_AUTH", "workspace")
    assert snapshot() == before
    assert list(store.root.iterdir()) == []


@pytest.mark.parametrize("case", ["none", "closed", "text-only", "closed-text"])
def test_argon_unavailable_stdin_is_fixed_json(case, store, workspace, monkeypatch, capsys):
    if case == "none":
        source = None
    elif case == "text-only":
        source = io.StringIO("HOSTILE_MARKER")
    elif case == "closed-text":
        source = io.TextIOWrapper(io.BytesIO(b"HOSTILE_MARKER"))
        source.close()
    else:
        buffer = io.BytesIO(b"HOSTILE_MARKER")
        buffer.close()
        source = SimpleNamespace(buffer=buffer)
    monkeypatch.setattr(sys, "stdin", source)
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 2
    assert_error(capsys.readouterr(), "E_FORMAT", "arguments")
    assert list(store.root.iterdir()) == []


@pytest.mark.parametrize("malformed_global", [False, True])
def test_argon_removed_name_as_workspace_is_not_a_command(malformed_global, workspace, capsys):
    (workspace / "verify" / ".aegis").mkdir(parents=True)
    flags = ["--json=sk-private-HOSTILE_MARKER"] if malformed_global else []
    assert main(["--work", "verify", *flags, "msg", "read", "a" * 64]) == 2
    assert_error(capsys.readouterr(), "E_FORMAT" if malformed_global else "E_REF",
                 "arguments" if malformed_global else "resolution")
    assert not (workspace / "verify" / ".aegis" / "state").exists()


def test_argon_removed_name_as_workspace_can_read(store, workspace, capsys):
    (workspace / "verify" / ".aegis").mkdir(parents=True)
    rid = store.write(GOLDENS[0]["record"])
    assert main(["--work", "verify", "msg", "--store", str(store.root), "read", rid]) == 0
    output = capsys.readouterr()
    assert not output.err
    assert output.out == codec.read_view(store.read(rid), store=store)


def test_argon_span_reproducer_round_trip(store, workspace, monkeypatch, capsys):
    body = "# x" + " " * 8000 + "#" * 8000 + "!"
    payload = json.dumps({"fields": {}, "body": body, "refs": {}}).encode()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    assert invoke(store, "write", "--kind", "text", "--in", "-") == 0
    rid = json.loads(capsys.readouterr().out)["id"]
    assert store.read(rid)["spans"] == [[0, len(body), body[2:]]]


INVALID_READ_OPTIONS = [
    ({"format": "xml"}, "E_FORMAT"),
    ({"spans": [10000]}, "E_SPAN"),
    ({"spans": [0] * 65}, "E_SPAN"),
    ({"max_chars": -1}, "E_LIMIT"),
    ({"max_chars": 16777217}, "E_LIMIT"),
    ({"fields": ["body."]}, "E_SELECTOR"),
    ({"fields": ["body", "body"]}, "E_SELECTOR"),
    ({"fields": ["rows", "fields.rows"]}, "E_SELECTOR"),
    ({"fields": ["body"] * 17}, "E_SELECTOR"),
    ({"fields": ["x" * 1025]}, "E_SELECTOR"),
    ({"since": "HOSTILE_MARKER"}, "E_SELECTOR"),
    ({"since": "1:" + "a" * 63}, "E_SELECTOR"),
    ({"since": "1:" + "a" * 69}, "E_SELECTOR"),
    ({"expand": ["HOSTILE_MARKER"]}, "E_REF"),
    ({"expand": ["x" * 65]}, "E_REF"),
    ({"expand": ["child"] * 65}, "E_REF"),
]
INVALID_READ_IDS = ["format", "span-range", "span-count", "negative-limit", "excess-limit", "selector-grammar",
        "duplicate-selectors", "duplicate-aliases", "selector-count", "selector-length", "bad-cursor",
        "cursor-hash", "cursor-length", "expand-grammar", "expand-length", "expand-count"]


def invalid_read_cases():
    rows = list(zip(INVALID_READ_IDS, INVALID_READ_OPTIONS))
    cases = [pytest.param(state, options, {code}, id=label + "-" + state)
             for label, (options, code) in rows
             for state in ("absent-ref", "no-store", "corrupt-record")]
    for (left_id, (left, left_code)), (right_id, (right, right_code)) in combinations(rows, 2):
        options = dict(left)
        for name, value in right.items():
            options[name] = options[name] + value if name in options and type(value) is list else value
        cases.append(pytest.param("absent-ref", options, {left_code, right_code}, id=left_id + "+" + right_id))
    return cases


@pytest.mark.parametrize("record_state,options,codes", invalid_read_cases())
@pytest.mark.parametrize("field_form", ["entries", "commas"])
def test_invalid_read_options_have_identical_frontend_refusals_before_io(
        options, codes, record_state, field_form, workspace, monkeypatch, capsys):
    from aegis_core import storage
    from aegis_core.workspace.base import Workspace
    from aegis_mcp import server

    rid = "a" * 64
    directory = workspace / ".aegis" / "state" / "messages"
    if record_state != "no-store":
        directory.mkdir(parents=True, mode=0o700)
        probe = make_store(directory)
        try:
            if record_state == "corrupt-record":
                rid = probe.write(GOLDENS[0]["record"])
                (directory / (rid + ".json")).write_bytes(b"HOSTILE_MARKER")
        finally:
            probe.close()
    for name, value in server.fresh_state().items():
        monkeypatch.setattr(server, name, value)
    monkeypatch.setattr(server, "_canonical_workspace", Workspace(workspace))
    server.handle_request({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    opened, original = [], storage.message_store

    def observed(*args, **kwargs):
        opened.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(storage, "message_store", observed)
    flags = []
    for name, value in options.items():
        if name == "fields" and field_form == "commas":
            value = [",".join(value)]
        for item in value if type(value) is list else [value]:
            flags.extend(["--" + name.replace("_", "-"), str(item)])
    cli_status = main(["msg", "read", rid, *flags])
    output = capsys.readouterr()
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                      "params": {"name": "aegis_msg_read", "arguments": dict(options, ref=rid)}})
    assert cli_status == 2 and not output.err
    result = response["result"]
    assert result["isError"]
    cli_error = json.loads(output.out)
    mcp_error = json.loads(result["content"][0]["text"])
    assert cli_error["error"]["code"] == mcp_error["error"]["code"]
    assert cli_error["error"]["code"] in codes
    assert cli_error == mcp_error
    assert result["content"][0]["text"] + "\n" == output.out
    assert "HOSTILE_MARKER" not in output.out + result["content"][0]["text"]
    assert not opened
    if record_state == "no-store":
        assert not directory.parent.exists()
