"""Opt-in record tools through the caller-bound mailbox MCP surface."""
import gc
import hashlib
import errno
import inspect
import json
import os
from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys
import tracemalloc
from types import SimpleNamespace
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
import shutil
from io import BytesIO

import pytest
from conftest import symlink_or_skip
from tests.integration.test_hierarchy_mailbox import HELPER, invoke, message, pilot  # noqa: F401

sys.path.insert(0, str(HELPER.parent))
import hierarchy_mailbox_mcp as mcp
import hierarchy_mailbox_records as records
import hierarchy_mailbox as mailbox_module
from aegis_core import message_codec as codec
from aegis_core import message_codec_store as codec_store
from aegis_core import message_codec_views as codec_views


def make_store(root):
    capabilities = {function.__name__ for function in os.supports_dir_fd}
    if not ({"open", "mkdir", "stat", "link", "unlink", "rename", "rmdir"} <= capabilities and
            hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and hasattr(os, "geteuid")):
        pytest.skip("anchored record operations unavailable")
    return codec.Store(root)


def connection(root, endpoint="a/orchestrator"):
    return mcp.Connection(root, endpoint, "host-one", endpoint, 1, records=True)


def call(conn, name, arguments):
    return mcp.handle(conn, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": name, "arguments": arguments}})


def data(result):
    return json.loads(result["content"][0]["text"])


def request(identifier="record-1", **extra):
    return {"message_id": identifier, "to": "a/lane/review", "type": "info", "kind": "text",
            "content": json.dumps({"fields": {}, "body": "# Evidence\nHOSTILE_MARKER", "refs": {}}), **extra}


@pytest.fixture
def bound(pilot):  # noqa: F811
    root, _ = pilot
    make_store(root.parent).close()
    return root, connection(root), connection(root, "a/lane/review")


def test_publish_retry_legacy_stub_read_and_digest(bound):
    root, writer, reader = bound
    first = data(call(writer, "mailbox_publish_record", request()))
    assert data(call(writer, "mailbox_publish_record", request())) == first
    inbox = invoke(root, "inbox", endpoint="a/lane/review")
    stub = inbox["messages"][0]["message"]["body"]
    assert stub == "aegis-record/1 sha256=" + first["id"] + " kind=text"
    assert (root.parent / "mailbox-records" / (first["id"] + ".json")).is_file()
    assert not (root / "mailbox-records").exists()
    view = data(call(reader, "mailbox_read_record", {"message_id": "record-1", "fields": ["body"]}))
    assert view["untrusted"] is True and view["data"]["body"] == "# Evidence\nHOSTILE_MARKER"
    assert view["mailbox_from"] == view["from"] == "a/orchestrator"
    digest = data(call(reader, "mailbox_digest", {"fields": ["body"]}))
    assert digest["messages"][0]["message_id"] == "record-1"
    assert digest["messages"][0]["record"] == view
    assert data(call(reader, "mailbox_digest", {"after_message_id": "record-1"}))["messages"] == []
    assert data(call(writer, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"


@pytest.mark.parametrize("change,code", [("tamper", "E_HASH"), ("stub", "E_FORMAT"),
                                        ("sender", "E_AUTH"), ("host", "E_AUTH"), ("session", "E_AUTH")])
def test_integrity_and_attribution_refusals_are_total(bound, change, code):
    root, writer, reader = bound
    published = data(call(writer, "mailbox_publish_record", request()))
    path = root.parent / "mailbox-records" / (published["id"] + ".json")
    if change == "tamper":
        path.write_bytes(b"HOSTILE_MARKER")
    else:
        mailbox = reader.checked_mailbox()
        stored = mailbox.messages()["record-1"]
        payload = stored["message"]
        if change == "stub":
            payload["body"] = payload["body"].replace("kind=text", "kind=blob")
        else:
            value = json.loads(path.read_bytes())
            value["meta"]["from" if change == "sender" else change] = "HOSTILE_MARKER"
            raw = codec.canonical(value)
            rid = hashlib.sha256(raw).hexdigest()
            (path.parent / (rid + ".json")).write_bytes(raw)
            payload["body"] = payload["body"].replace(published["id"], rid)
        header = {k: v for k, v in payload.items() if k != "body"}
        from hierarchy_mailbox import encoded
        Path(stored["path"]).write_bytes(b"---\n" + encoded(header) + b"\n---\n\n" + payload["body"].encode())
    for name, args in [("mailbox_read_record", {"message_id": "record-1"}), ("mailbox_digest", {})]:
        result = call(reader, name, args)
        assert result["isError"] is True
        assert data(result) == (auth_error("reference") if code == "E_AUTH" else codec.CodecError(code).as_dict())
        assert "HOSTILE_MARKER" not in result["content"][0]["text"]


def test_retry_conflict_and_concurrent_publish(bound):
    root, writer, _ = bound
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: call(connection(root), "mailbox_publish_record", request()), range(2)))
    assert all("isError" not in result for result in results)
    assert data(results[0]) == data(results[1])
    assert len(writer.checked_mailbox().messages()) == 1
    conflict = request(content=json.dumps({"fields": {}, "body": "changed", "refs": {}}))
    assert data(call(writer, "mailbox_publish_record", conflict)) == codec.CodecError("E_FORMAT").as_dict()


@pytest.mark.parametrize("args,code", [({"content": "x" * 262145}, "E_LIMIT"),
                                      ({"kind": []}, "E_FORMAT"), ({"from": "HOSTILE_MARKER"}, "E_FORMAT"),
                                      ({"content": "\ud800"}, "E_FORMAT")])
def test_invalid_publish_has_fixed_errors_before_store_creation(bound, args, code):
    root, writer, _ = bound
    error = codec.CodecError(code, detail="record" if code == "E_LIMIT" else None)
    assert data(call(writer, "mailbox_publish_record", request(**args))) == error.as_dict()
    assert not (root.parent / "mailbox-records").exists()


def test_unsupported_platform_refuses_without_creating_store(pilot, monkeypatch):  # noqa: F811
    root, _ = pilot
    monkeypatch.setattr(records, "supported", lambda: False)
    assert data(call(connection(root), "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    assert not (root.parent / "mailbox-records").exists()


def test_symlink_store_refused_and_failure_retry(bound):
    root, writer, _ = bound
    outside = root.parent / "outside"
    outside.mkdir()
    link = root.parent / "mailbox-records"
    symlink_or_skip(outside, link, target_is_directory=True)
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    assert not list(outside.iterdir())
    link.unlink()
    assert "id" in data(call(writer, "mailbox_publish_record", request()))


def test_opt_in_stdio_and_pinned_hash(bound):
    root, _, _ = bound
    # A source snapshot needs no git history to check the pin.
    assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == "472c96ab7959f5fbcfdee2e3d3a11a78864b0eb7a708029a1e419f410825a905"
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "mailbox_publish_record", "arguments": request()}}]
    run = subprocess.run([sys.executable, "-I", "-B", str(HELPER.with_name("hierarchy_mailbox_mcp.py")),
                          "--root", str(root), "serve", "--records", "--endpoint", "a/orchestrator",
                          "--host", "host-one", "--session", "a/orchestrator", "--generation", "1"],
                         input="".join(json.dumps(f) + "\n" for f in frames), capture_output=True, text=True, timeout=15)
    assert run.returncode == 0 and not run.stderr, run.stdout + run.stderr
    replies = [json.loads(line) for line in run.stdout.splitlines()]
    assert {"mailbox_publish_record", "mailbox_read_record", "mailbox_digest"} <= {
        tool["name"] for tool in replies[0]["result"]["tools"]}
    assert "id" in data(replies[1]["result"])


def test_selectors_output_limits_and_legacy_digest(bound):
    root, writer, reader = bound
    call(writer, "mailbox_publish_record", request())
    invoke(root, "publish", message(recipient="a/lane/review", identifier="legacy", body="ordinary\u202etext"))
    for name, args in [("mailbox_read_record", {"message_id": "record-1"}), ("mailbox_digest", {})]:
        assert data(call(reader, name, dict(args, fields=["not_a_field"]))) == codec.CodecError("E_SELECTOR").as_dict()
        assert data(call(reader, name, dict(args, max_chars=10))) == codec.CodecError("E_LIMIT").as_dict()
    result = call(reader, "mailbox_digest", {"fields": ["body"]})
    rows = data(result)["messages"]
    assert len(rows) == 2 and next(r for r in rows if r["message_id"] == "legacy")["body"] == "ordinary\u202etext"
    assert "\u202e" not in result["content"][0]["text"]


@pytest.mark.parametrize("name,args,maximum", [
    ("mailbox_read_record", {"message_id": "record-1"}, 400), ("mailbox_digest", {}, 600)])
def test_public_record_text_keeps_codec_character_budget(bound, name, args, maximum):
    _, writer, reader = bound
    content = json.dumps({"fields": {}, "body": "é" * 100, "refs": {}})
    assert "id" in data(call(writer, "mailbox_publish_record", request(content=content)))
    for _ in range(2):
        result = call(reader, name, dict(args, fields=["body"], max_chars=maximum))
        assert not result.get("isError"), result
        assert len(result["content"][0]["text"]) <= maximum


def test_record_failure_does_not_publish_and_can_retry(bound, monkeypatch):
    root, writer, _ = bound
    real_open = os.open
    descriptors = []

    def fail_leaf(path, flags, *args, **kwargs):
        if path == "mailbox-records":
            raise PermissionError("HOSTILE_MARKER")
        fd = real_open(path, flags, *args, **kwargs)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": fail_leaf}))
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    monkeypatch.setattr(records, "os", os)
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert not writer.checked_mailbox().messages()
    assert "id" in data(call(writer, "mailbox_publish_record", request()))


def test_ancestor_symlink_swap_cannot_redirect_record_write(bound, monkeypatch):
    root, writer, _ = bound
    outside = root.parent / "outside"
    outside.mkdir()
    probe = root.parent / "probe"
    symlink_or_skip(outside, probe, target_is_directory=True)
    probe.unlink()
    # Swap the store after its descriptor is admitted, before the core binds its path.
    store = root.parent / "mailbox-records"
    saved = root.parent / "saved"
    real_open = os.open

    def swapped(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == "mailbox-records":
            store.rename(saved)
            symlink_or_skip(outside, store, target_is_directory=True)
        return fd

    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": swapped}))
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    monkeypatch.setattr(records, "os", os)
    assert not list(outside.iterdir()) and not list(saved.iterdir())
    store.unlink()
    saved.rename(store)
    assert "id" in data(call(writer, "mailbox_publish_record", request()))


def test_failed_mailbox_publish_leaves_no_dangling_stub_and_retries(bound, monkeypatch):
    root, writer, _ = bound
    publish = mcp.Mailbox.publish
    # Patch this lane's Mailbox class reference method, not process-wide OS functions.
    def unavailable(self, request):
        raise OSError("HOSTILE_MARKER")

    monkeypatch.setattr(mcp.Mailbox, "publish", unavailable)
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    monkeypatch.setattr(mcp.Mailbox, "publish", publish)
    assert not writer.checked_mailbox().messages()
    assert not list((root.parent / "mailbox-records").glob("*.json"))
    assert "id" in data(call(writer, "mailbox_publish_record", request()))


def test_review_stub_has_code_rendered_verdict_and_refuses_multiline(bound):
    _, writer, reader = bound
    fields = {"reasoning_summary": "ok", "findings": [], "checked": [], "coverage_gaps": "",
              "verdict": "ACCEPT", "prior_findings": []}
    content = {"fields": fields, "body": "review", "refs": {}}
    args = request(kind="review.v1", content=json.dumps(content))
    assert "id" in data(call(writer, "mailbox_publish_record", args))
    stored = reader.checked_mailbox().messages()["record-1"]["message"]
    assert stored["body"].endswith("\nverdict: ACCEPT")
    fields["verdict"] = "ACCEPT\nHOSTILE_MARKER"
    result = call(writer, "mailbox_publish_record", request("record-2", kind="review.v1", content=json.dumps(content)))
    assert data(result) == codec.CodecError("E_FORMAT").as_dict()


def test_codec_loader_refuses_foreign_cached_package_and_attributes(tmp_path):
    program = '''
import sys, types
sys.path.insert(0, sys.argv[1])
import hierarchy_mailbox_records as records
codec = records.codec_tools()
import aegis_core
original = aegis_core.message_codec
aegis_core.message_codec = types.SimpleNamespace(__file__=original.__file__)
try:
    records.codec_tools()
except ValueError as error:
    assert str(error) == 'record codec unavailable from this checkout'
else:
    raise AssertionError('foreign package attribute admitted')
aegis_core.message_codec = original
sys.modules['aegis_core']. __file__ = sys.argv[2]
try:
    records.codec_tools()
except ValueError as error:
    assert str(error) == 'record codec unavailable from this checkout'
else:
    raise AssertionError('foreign package origin admitted')
'''
    run = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(HELPER.parent), str(tmp_path / "foreign.py")],
                         capture_output=True, text=True, timeout=15)
    assert run.returncode == 0 and not run.stdout and not run.stderr, run.stdout + run.stderr


@pytest.mark.parametrize("refusal", ["completion", "reply"])
def test_r2_refused_publications_never_commit_records(bound, refusal):
    root, writer, _ = bound
    for number in range(3):
        args = request("refused-" + str(number), type="result" if refusal == "completion" else "info",
                       content=json.dumps({"fields": {}, "body": str(number), "refs": {}}))
        if refusal == "reply":
            args["in_reply_to"] = "missing"
        code = "E_REF" if refusal == "reply" else "E_FORMAT"
        assert data(call(writer, "mailbox_publish_record", args)) == codec.CodecError(code).as_dict()
        assert not list((root.parent / "mailbox-records").glob("*.json"))
        assert not writer.checked_mailbox().messages()
    assert "id" in data(call(writer, "mailbox_publish_record", request("accepted")))


def test_r2_concurrent_refusals_and_retry_keep_only_committed_records(bound):
    root, writer, _ = bound
    requests = [request("refused", type="result"), request(), request()]
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda args: data(call(connection(root), "mailbox_publish_record", args)), requests))
    assert results[0] == codec.CodecError("E_FORMAT").as_dict()
    assert results[1] == results[2]
    assert len(list((root.parent / "mailbox-records").glob("*.json"))) == 1
    assert list(writer.checked_mailbox().messages()) == ["record-1"]


@pytest.mark.parametrize("failure", ["link", "fdopen"])
def test_r2_commit_failure_reclaims_new_record_and_all_owned_fds(bound, monkeypatch, failure):
    root, writer, _ = bound
    opened, closed = [], []
    real_open, real_close, real_link, real_fdopen = os.open, os.close, os.link, os.fdopen

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def tracked_close(fd):
        closed.append(fd)
        return real_close(fd)

    def broken_link(source, destination, *args, **kwargs):
        if failure == "link" and str(destination).endswith(".md"):
            raise OSError("HOSTILE_MARKER")
        return real_link(source, destination, *args, **kwargs)

    def broken_fdopen(*args, **kwargs):
        if failure == "fdopen":
            raise OSError("HOSTILE_MARKER")
        return real_fdopen(*args, **kwargs)

    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": tracked_open,
                        "close": tracked_close, "link": broken_link, "fdopen": broken_fdopen}))
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    monkeypatch.setattr(records, "os", os)
    assert sorted(opened) == sorted(closed)
    assert not list((root.parent / "mailbox-records").glob("*.json"))
    assert not writer.checked_mailbox().messages()
    assert "id" in data(call(writer, "mailbox_publish_record", request()))


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r2_record_reads_stage_delivery_only_for_successful_flush(bound, tool):
    root, writer, _ = bound
    delivery = root.parent / "delivery"
    reader = mcp.Connection(root, "a/lane/review", "host-one", "a/lane/review", 1,
                            records=True, delivery_dir=delivery)
    call(writer, "mailbox_publish_record", request())
    args = {"message_id": "record-1"} if tool == "mailbox_read_record" else {}
    assert not call(reader, tool, args).get("isError")
    assert reader.returned == ["record-1"]
    assert invoke(root, "delivery", delivery_dir=delivery, message_id="record-1")["message"]["state"] == "published"
    reader.begin_response()  # Failed output flush: the server discards the staged response.
    reader.record_read()
    assert invoke(root, "delivery", delivery_dir=delivery, message_id="record-1")["message"]["state"] == "published"
    for _ in range(2):
        assert not call(reader, tool, args).get("isError")
        reader.record_read()  # The existing transport calls this only after a successful flush.
    state = invoke(root, "delivery", delivery_dir=delivery, message_id="record-1")["message"]
    assert state["state"] == "read" and state["read_by"]["generation"] == 1
    assert len(list(delivery.glob("reads/**/*.json"))) == 1
    assert data(call(reader, tool, dict(args, fields=["unknown"]))) == codec.CodecError("E_SELECTOR").as_dict()
    assert reader.returned == []


@pytest.mark.parametrize("relation", ["equal", "root-ancestor", "symlink-equal", "symlink-child", "symlink-parent",
                                     "root-alias-equal", "root-alias-child", "root-alias-parent"])
def test_r2_record_store_disjointness_precedes_storage_io(tmp_path, monkeypatch, relation):
    make_store(tmp_path).close()
    root = tmp_path / ("mailbox-records" if relation == "equal" else "mailbox")
    root.mkdir()
    if relation == "root-ancestor":
        root = Path(root.anchor)
    elif relation.startswith("symlink"):
        target = root if relation == "symlink-equal" else root.parent
        if relation == "symlink-child":
            target = root / "child"
            target.mkdir()
        symlink_or_skip(target, root.parent / "mailbox-records", target_is_directory=True)
    elif relation.startswith("root-alias"):
        actual = tmp_path / "actual"
        if relation == "root-alias-parent":
            actual.mkdir()
            actual = actual / "nested"
        root.rename(actual)
        symlink_or_skip(actual, root, target_is_directory=True)
        target = actual.parent if relation == "root-alias-parent" else actual
        if relation == "root-alias-child":
            target = actual / "child"
            target.mkdir()
        symlink_or_skip(target, root.parent / "mailbox-records", target_is_directory=True)

    def forbidden(*args, **kwargs):
        raise AssertionError("overlap reached storage I/O")

    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": forbidden, "mkdir": forbidden}))
    with pytest.raises(codec.CodecError) as error:
        with records.record_store(codec, root, write=True):
            raise AssertionError("overlap admitted")
    assert error.value.as_dict() == codec.CodecError("E_AUTH").as_dict()


@pytest.mark.parametrize("enabled,present", [(False, False), (False, True), (True, False)])
def test_r2_optional_record_adapter_preserves_standalone_service(pilot, tmp_path, enabled, present):  # noqa: F811
    root, _ = pilot
    source = tmp_path / "standalone-tools"
    source.mkdir()
    for path in HELPER.parent.glob("hierarchy_*.py"):
        if present or path.name != "hierarchy_mailbox_records.py":
            shutil.copy2(path, source / path.name)
    shutil.copytree(HELPER.parent / "hierarchy_templates", source / "hierarchy_templates")
    names = ["mailbox_publish_record", "mailbox_read_record", "mailbox_digest"]
    frames = [{"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {
        "name": name, "arguments": {}}} for index, name in enumerate(names)]
    frames += [{"jsonrpc": "2.0", "id": 5, "method": "tools/list"},
               {"jsonrpc": "2.0", "id": 4, "method": "ping"}]
    entry = "hierarchy_mailbox_mcp.py" if enabled else "hierarchy_mailbox.py"
    argv = [sys.executable, "-I", "-B", str(source / entry), "--root", str(root), "serve",
            "--endpoint", "a/lane/review", "--host", "host-one", "--session", "a/lane/review", "--generation", "1"]
    if enabled:
        argv.append("--records")
    run = subprocess.run(argv, input="".join(json.dumps(frame) + "\n" for frame in frames),
                         capture_output=True, text=True, timeout=15)
    assert run.returncode == 0 and not run.stderr, run.stdout + run.stderr
    replies = [json.loads(line) for line in run.stdout.splitlines()]
    for name, reply in zip(names, replies):
        value = reply["result"]
        assert value["isError"] is True
        if enabled:
            assert data(value) == {"error": {"code": "E_AUTH", "message": "record adapter unavailable from this checkout"}}
        else:
            assert data(value) == {"error": "unknown mailbox tool: " + name}
    assert replies[-1]["result"] == {}
    assert not set(names) & {tool["name"] for tool in replies[-2]["result"]["tools"]}


def test_r2_authorization_and_cursor_errors_keep_their_codes(bound):
    root, writer, reader = bound
    call(writer, "mailbox_publish_record", request())
    assert data(call(reader, "mailbox_digest", {"after_message_id": "missing"})) == codec.CodecError("E_REF").as_dict()
    brief = root.parent / "brief.md"
    draft = invoke(root, "draft-handoff", {"endpoint": "a/lane/review", "host": "host-one", "session": "successor",
                   "outgoing_stopped": True, "briefs": [{"path": str(brief),
                   "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]})
    invoke(root, "bind", draft)
    assert data(call(reader, "mailbox_digest", {})) == auth_error("binding")


def test_r2_sent_and_received_records_authorize_refs_at_both_ends(bound):
    root, writer, reader = bound
    # Sending and receiving each grant access, including when the peer cites it back.
    rid = data(call(writer, "mailbox_publish_record", request()))["id"]
    content = json.dumps({"fields": {}, "body": "reference", "refs": {"target": rid}})
    assert "id" in data(call(writer, "mailbox_publish_record", request("sent-ref", content=content)))
    # The receiver can legitimately reference the record back to its publisher.
    args = request("reply-record", to="a/orchestrator", content=content)
    assert "id" in data(call(reader, "mailbox_publish_record", args))
    result = data(call(writer, "mailbox_read_record", {"message_id": "reply-record"}))
    assert result["data"]["refs"]["target"]["ref"] == rid[:16]
    result = data(call(writer, "mailbox_read_record", {"message_id": "reply-record", "fields": ["body"]}))
    assert result["data"]["body"] == "reference"


def test_r2_foreign_message_id_retry_is_authorized_before_record_io(bound, monkeypatch):
    root, writer, reader = bound
    call(writer, "mailbox_publish_record", request())
    real_open = os.open
    def guarded(path, *args, **kwargs):
        if str(path).endswith(".json"):
            raise AssertionError("foreign retry reached record I/O")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "open": guarded}))
    assert data(call(reader, "mailbox_publish_record", request(to="a/orchestrator"))) == auth_error("message_id")


def test_r2_equal_store_is_refused_before_mailbox_lock_io(bound, monkeypatch):
    root, _, _ = bound
    overlap = root.parent / "other" / "mailbox-records"
    shutil.copytree(root, overlap)
    writer = connection(overlap)
    real_open = os.open
    def guarded(path, *args, **kwargs):
        if str(path).endswith(".write.lock"):
            raise AssertionError("overlapping configuration reached writer I/O")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(mailbox_module, "os", SimpleNamespace(**{**vars(os), "open": guarded}))
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()


@pytest.mark.parametrize("failure", ["pending", "lock", "link-after"])
def test_r2_cleanup_failure_after_commit_returns_success_and_stops_growth(bound, monkeypatch, failure):
    root, writer, reader = bound
    real_unlink, real_link = os.unlink, os.link
    def refused(path, *args, **kwargs):
        if path == (".pending-stub" if failure == "pending" else ".publish.lock") and failure != "link-after":
            raise PermissionError("HOSTILE_MARKER")
        return real_unlink(path, *args, **kwargs)
    def linked(source, destination, *args, **kwargs):
        result = real_link(source, destination, *args, **kwargs)
        if failure == "link-after" and str(destination).endswith(".md"):
            raise OSError("HOSTILE_MARKER")
        return result
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "unlink": refused, "link": linked}))
    published = call(writer, "mailbox_publish_record", request())
    assert not published.get("isError"), published
    assert data(published)["id"]
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"
    if failure == "link-after":
        assert data(call(writer, "mailbox_publish_record", request()))["id"] == data(published)["id"]
    else:
        assert data(call(writer, "mailbox_publish_record", request("second"))) == auth_error("lock")
    assert len(list((root.parent / "mailbox-records").glob("*.json"))) == 1
    assert list(writer.checked_mailbox().messages()) == ["record-1"]


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
@pytest.mark.parametrize("boundary", ["busy", "stale"])
def test_r2_receipt_failures_match_the_existing_read_path(bound, tool, boundary, capsys):
    root, writer, _ = bound
    delivery = root.parent / "delivery"
    reader = mcp.Connection(root, "a/lane/review", "host-one", "a/lane/review", 1,
                            records=True, delivery_dir=delivery)
    call(writer, "mailbox_publish_record", request())
    args = {"message_id": "record-1"} if tool == "mailbox_read_record" else {}
    assert not call(reader, tool, args).get("isError")
    if boundary == "busy":
        with mcp.writer_lock(root):
            reader.record_read()
        expected = "mailbox writer is busy; inspect an abandoned lock before retrying"
    else:
        brief = root.parent / "brief.md"
        draft = invoke(root, "draft-handoff", {"endpoint": "a/lane/review", "host": "host-one", "session": "successor",
                       "outgoing_stopped": True, "briefs": [{"path": str(brief),
                       "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]})
        invoke(root, "bind", draft)
        reader.record_read()
        expected = "stale or mismatched sender binding"
    assert capsys.readouterr().err == "read receipt not recorded: " + expected + "\n"
    assert reader.returned == []
    assert invoke(root, "delivery", delivery_dir=delivery, message_id="record-1")["message"]["state"] == "published"
    if boundary == "stale":
        assert data(call(reader, tool, args)) == auth_error("binding")
        reader = mcp.Connection(root, "a/lane/review", "host-one", "successor", 2,
                                records=True, delivery_dir=delivery)
    assert not call(reader, tool, args).get("isError")
    reader.record_read()
    assert invoke(root, "delivery", delivery_dir=delivery, message_id="record-1")["message"]["state"] == "read"


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r2_failed_transport_flush_never_records_delivery(bound, tool, monkeypatch):
    root, writer, _ = bound
    delivery = root.parent / "delivery"
    call(writer, "mailbox_publish_record", request())
    args = {"message_id": "record-1"} if tool == "mailbox_read_record" else {}
    request_frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}}
    raw = (json.dumps(request_frame) + "\n").encode()
    class BrokenOutput:
        def __init__(self):
            self.buffer = self
            self.data = b""
        def write(self, data):
            self.data += data
        def flush(self):
            raise BrokenPipeError("simulated flush failure")
        def fileno(self):
            return 987
    output = BrokenOutput()
    def opened(path, flags):
        assert path == os.devnull and flags == os.O_WRONLY
        return 777
    def duped(source, destination):
        assert (source, destination) == (777, 987)
    monkeypatch.setattr(mcp, "sys", SimpleNamespace(**{**vars(sys),
                        "stdin": SimpleNamespace(buffer=BytesIO(raw)), "stdout": output}))
    monkeypatch.setattr(mcp, "os", SimpleNamespace(**{**vars(os), "open": opened, "dup2": duped}))
    assert mcp.serve(root, "a/lane/review", "host-one", "a/lane/review", 1,
                     records=True, delivery_dir=delivery) == 0
    assert not json.loads(output.data)["result"].get("isError")
    assert invoke(root, "delivery", delivery_dir=delivery, message_id="record-1")["message"]["state"] == "published"


def test_r2_shared_store_serializes_commits_without_patching_the_pinned_writer(bound, monkeypatch):
    root, writer, _ = bound
    second, legacy = root.parent / "second-mailbox", root.parent / "legacy-mailbox"
    shutil.copytree(root, second)
    shutil.copytree(root, legacy)
    entered, contended, release = Event(), Event(), Event()
    real_open, real_link, pinned_writer = os.open, os.link, mailbox_module.publish_file
    def opened(path, *args, **kwargs):
        try:
            return real_open(path, *args, **kwargs)
        except FileExistsError:
            if path in (".publish.lock", ".records-store.lock"):
                contended.set()
            raise
    def linked(source, destination, *args, **kwargs):
        if str(destination).endswith(".md") and not entered.is_set():
            entered.set()
            assert release.wait(5), "publication boundary was not released"
        return real_link(source, destination, *args, **kwargs)
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": opened, "link": linked}))
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(call, writer, "mailbox_publish_record", request())
        try:
            assert entered.wait(5), "first publisher did not reach its commit boundary"
            other = pool.submit(call, connection(second), "mailbox_publish_record", request("second",
                content=json.dumps({"fields": {}, "body": "second", "refs": {}})))
            assert contended.wait(5), "second mailbox did not encounter the shared store reservation"
            assert mailbox_module.publish_file is pinned_writer
            invoke(legacy, "publish", message(recipient="a/lane/review", identifier="legacy"))
        finally:
            release.set()
        assert not first.result(timeout=5).get("isError")
        assert not other.result(timeout=5).get("isError")
    assert mailbox_module.publish_file is pinned_writer
    assert len(list((root.parent / "mailbox-records").glob("*.json"))) == 2
    assert not (root.parent / "mailbox-records" / ".publish.lock").exists()
    assert not (root.parent / "mailbox-records" / ".pending-stub").exists()


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
@pytest.mark.parametrize("configured", [False, True])
def test_r2_real_stdio_receipts_are_opt_in_and_follow_successful_delivery(bound, tool, configured):
    root, writer, _ = bound
    delivery = root.parent / "delivery"
    call(writer, "mailbox_publish_record", request())
    args = {"message_id": "record-1"} if tool == "mailbox_read_record" else {}
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}}
    argv = [sys.executable, "-I", "-B", str(HELPER.with_name("hierarchy_mailbox_mcp.py")),
            "--root", str(root), "serve", "--records", "--endpoint", "a/lane/review",
            "--host", "host-one", "--session", "a/lane/review", "--generation", "1"]
    if configured:
        argv += ["--delivery-dir", str(delivery)]
    run = subprocess.run(argv, input=json.dumps(frame) + "\n", capture_output=True, text=True, timeout=15)
    assert run.returncode == 0 and not run.stderr, run.stdout + run.stderr
    assert not json.loads(run.stdout)["result"].get("isError")
    state = invoke(root, "delivery", delivery_dir=delivery, message_id="record-1")["message"]
    assert state["state"] == ("read" if configured else "published")
    if not configured:
        assert not delivery.exists()


def auth_error(cause):
    value = codec.CodecError("E_AUTH").as_dict()
    value["error"]["message"] = {
        "binding": "endpoint binding refused", "reference": "record authorization refused",
        "lock": "publication lock timed out", "mailbox_lock": "mailbox writer lock timed out",
        "scope": "mailbox route or role refused",
        "identity": "record root identity unavailable or invalid",
        "attribution": "record attribution does not match mailbox message",
        "message_id": "message_id belongs to another sender binding; choose a new message_id",
        "cited_reference": "cited record access refused",
    }[cause]
    value["error"]["next_action"] = {
        "binding": "refresh the connection from the current acknowledged endpoint binding",
        "reference": "cite only records sent, received or delegated to this endpoint",
        "lock": "inspect <parent>/.records-store.lock and <store>/.publish.lock for abandoned reservations before retrying",
        "mailbox_lock": "inspect the mailbox .write.lock before retrying",
        "scope": "choose a permitted route and message role for this endpoint",
        "identity": "restore the complete .root-id from a trusted backup; initialize a fresh root separately",
        "attribution": "read the original code-published stub for this record",
        "message_id": "choose a new message_id for this sender binding",
        "cited_reference": "select fields without refs (e.g. body) or ask the sender to delegate the cited records",
    }[cause]
    return value


def publish_limit(grants=False, history=False):
    if history:
        return {"error": {"code": "E_LIMIT", "message": "mailbox history limit reached",
                          "next_action": "ask the owner to resolve the mailbox history limit"}}
    return {"error": {"code": "E_LIMIT", "message": "record grant limit exceeded" if grants else "record publication limit exceeded",
                      "next_action": "reduce delegated references or ask the owner to inspect the grant index" if grants else
                      "split the record or reduce its body, fields or references"}}


@pytest.mark.parametrize("verdict", ["ACCEPT", "REQUEST_CHANGES"])
def test_r3_argon_foreign_retry_probe_never_opens_the_guessed_record(bound, monkeypatch, verdict):
    root, _, _ = bound
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    manifest["endpoints"].update({"a/decider": {}, "a/lane/writer": {"kind": "implementer"}})
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "a" / "decider").mkdir()
    for endpoint in ("a/decider", "a/lane/writer"):
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    attacker = connection(root, "a/lane/writer")
    fields = {"reasoning_summary": "review", "findings": [], "checked": [], "coverage_gaps": "",
              "verdict": "REQUEST_CHANGES", "prior_findings": []}
    private = request("private-review", to="a/decider", kind="review.v1",
                      content=json.dumps({"fields": fields, "body": "private", "refs": {}}))
    rid = data(call(connection(root), "mailbox_publish_record", private))["id"]
    real_open = os.open
    opened = []
    def guarded(path, *args, **kwargs):
        if str(path) == rid + ".json":
            opened.append(path)
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "open": guarded}))
    forged = "aegis-record/1 sha256=" + rid + " kind=review.v1\nverdict: " + verdict
    assert not call(attacker, "mailbox_publish", {"message_id": "probe", "to": "a/orchestrator",
                                                 "type": "info", "body": forged}).get("isError")
    answer = call(attacker, "mailbox_publish_record", request("probe", to="a/orchestrator",
        content=json.dumps({"fields": {}, "body": "x", "refs": {}})))
    assert data(answer) == auth_error("reference")
    assert opened == []
    for endpoint in ("a/orchestrator", "a/decider"):
        assert data(call(connection(root, endpoint), "mailbox_read_record", {"message_id": "private-review"}))["from"] == "a/orchestrator"
    assert data(call(connection(root), "mailbox_publish_record", private))["id"] == rid
    references = json.dumps({"fields": {}, "body": "cite", "refs": {"review": rid}})
    assert "id" in data(call(connection(root, "a/decider"), "mailbox_publish_record",
        request("reference-back", to="a/orchestrator", content=references)))
    digest = data(call(connection(root), "mailbox_digest", {"after_message_id": "probe"}))
    assert digest["messages"][0]["record"]["data"]["refs"]["review"]["ref"] == rid[:16]


@pytest.mark.parametrize("known", [False, True])
def test_r3_denied_and_unknown_refs_have_identical_refusals_without_record_io(bound, monkeypatch, known):
    root, writer, reader = bound
    private = data(call(writer, "mailbox_publish_record", request("private", to="a/front-door")))["id"]
    rid = private if known else "0" * 64
    real_open = os.open
    def guarded(path, *args, **kwargs):
        if str(path).endswith(".json"):
            raise AssertionError("denied reference opened a record")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "open": guarded}))
    args = request("denied", to="a/orchestrator", content=json.dumps({
        "fields": {}, "body": "probe", "refs": {"target": rid}}))
    assert data(call(reader, "mailbox_publish_record", args)) == auth_error("reference")


def test_r3_forged_received_reference_does_not_authorize_foreign_record_io(bound, monkeypatch):
    root, writer, reader = bound
    rid = data(call(writer, "mailbox_publish_record", request("private", to="a/front-door")))["id"]
    attacker = connection(root, "b/orchestrator")
    forged = "aegis-record/1 sha256=" + rid + " kind=text"
    assert not call(attacker, "mailbox_publish", {"message_id": "forged", "to": "a/orchestrator",
                                                "type": "info", "body": forged}).get("isError")
    # The foreign author of the forged stub has no code-recorded grant to the private record.
    real_open = os.open
    def guarded(path, *args, **kwargs):
        if str(path) == rid + ".json":
            raise AssertionError("forged grant opened a foreign record")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(codec_store, "os", SimpleNamespace(**{**vars(os), "open": guarded}))
    args = request("denied", to="a/orchestrator", content=json.dumps({"fields": {}, "body": "probe", "refs": {"target": rid}}))
    assert data(call(attacker, "mailbox_publish_record", args)) == auth_error("reference")


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r3_lane_forwards_reviews_and_delegation_survives_digest_window(bound, tool):
    root, lead, reviewer = bound
    # The lead receives a review from a sibling hierarchy and forwards it to its lane.
    source = connection(root, "b/orchestrator")
    rid = data(call(source, "mailbox_publish_record", request("review", to="a/orchestrator")))["id"]
    forwarded = request("forwarded", content=json.dumps({"fields": {}, "body": "forwarded", "refs": {"review": rid}}))
    assert "id" in data(call(lead, "mailbox_publish_record", forwarded))
    # The lane can forward the delegated review to the lead without receiving its original stub.
    assert "id" in data(call(reviewer, "mailbox_publish_record", request("lane-forward", to="a/orchestrator",
        content=json.dumps({"fields": {}, "body": "lane review", "refs": {"review": rid}}))))
    if tool == "mailbox_read_record":
        args = {"message_id": "forwarded"}
        view = data(call(reviewer, tool, args))
    else:
        # Read a window of reference-bearing messages through the same authorization rule.
        assert "id" in data(call(lead, "mailbox_publish_record", request("later", content=forwarded["content"])))
        result = data(call(reviewer, tool, {"after_message_id": "forwarded", "limit": 1}))
        view = result["messages"][0]["record"]
    assert view["data"]["refs"]["review"]["ref"] == rid[:16]


@pytest.mark.parametrize("case,code", [("route", "E_AUTH"), ("dispatch", "E_AUTH"),
                                      ("reply", "E_REF"), ("history", "E_LIMIT"), ("unknown", "E_FORMAT")])
def test_r3_pinned_refusal_mapping_is_explicit(bound, monkeypatch, case, code):
    root, writer, reader = bound
    args = request()
    if case == "route":
        writer, args = reader, request(to="b/front-door")
    elif case == "dispatch":
        writer, args = reader, request(to="a/orchestrator", type="dispatch", brief={
            "path": str(root.parent / "brief.md"), "sha256": hashlib.sha256((root.parent / "brief.md").read_bytes()).hexdigest()})
    elif case == "reply":
        args["in_reply_to"] = "missing"
    elif case == "history":
        assert "id" in data(call(writer, "mailbox_publish_record", request("first")))
        monkeypatch.setattr(mailbox_module, "MAX_RECORDS", 1)
    else:
        def refused(self, request, **kwargs):
            raise ValueError("HOSTILE_MARKER")
        monkeypatch.setattr(mcp.Mailbox, "validate_message", refused)
    result = data(call(writer, "mailbox_publish_record", args))
    expected = auth_error("scope") if code == "E_AUTH" else publish_limit(history=True) if case == "history" else codec.CodecError(code).as_dict()
    assert result == expected


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r3_symlink_mailbox_entry_maps_to_auth_for_both_reads(bound, tool):
    root, writer, reader = bound
    call(writer, "mailbox_publish_record", request())
    entry = Path(writer.checked_mailbox().messages()["record-1"]["path"])
    saved = entry.with_suffix(".saved")
    entry.rename(saved)
    symlink_or_skip(saved, entry)
    args = {"message_id": "record-1"} if tool == "mailbox_read_record" else {}
    assert data(call(reader, tool, args)) == codec.CodecError("E_AUTH").as_dict()


def test_r3_cross_mount_link_stages_in_destination_and_keeps_record_first(bound, monkeypatch):
    root, writer, reader = bound
    real_link = os.link
    links = []
    def within_directory(source, target, *args, **kwargs):
        if str(target).endswith(".md"):
            source_fd, target_fd = kwargs["src_dir_fd"], kwargs["dst_dir_fd"]
            if source_fd != target_fd:
                raise OSError(errno.EXDEV, "cross-device link")
            assert len(list((root.parent / "mailbox-records").glob("*.json"))) == 1
            assert os.fstat(target_fd).st_ino == (root / "a" / "lane").stat().st_ino
            links.append((source, source_fd, target_fd))
        return real_link(source, target, *args, **kwargs)
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "link": within_directory}))
    result = call(writer, "mailbox_publish_record", request())
    assert not result.get("isError"), result
    assert len(links) == 1
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"
    assert not list(root.rglob(".pending-stub"))


@pytest.mark.parametrize("relation", ["root", "ancestor"])
def test_r3_store_descriptor_alias_identity_is_refused_before_store_binding(bound, monkeypatch, relation):
    root, _, _ = bound
    target = root if relation == "root" else root.parent
    real_open = os.open
    def aliased(path, *args, **kwargs):
        return real_open(target, *args) if path == "mailbox-records" else real_open(path, *args, **kwargs)
    def forbidden(*args, **kwargs):
        raise AssertionError("aliased store reached codec binding")
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": aliased}))
    monkeypatch.setattr(codec, "Store", forbidden)
    assert data(call(connection(root), "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()


def test_r3_identity_predicate_compares_device_and_inode():
    info = lambda device, inode: SimpleNamespace(st_dev=device, st_ino=inode)
    ancestors = [info(1, 2), info(1, 3)]
    assert records._is_root_or_ancestor(info(1, 2), ancestors)
    assert records._is_root_or_ancestor(info(1, 3), ancestors)
    assert not records._is_root_or_ancestor(info(2, 2), ancestors)
    assert not records._is_root_or_ancestor(info(1, 4), ancestors)


def test_r3_symlinked_parent_alias_cannot_put_store_in_root(bound):
    root, _, _ = bound
    alias = root.parent / "alias"
    symlink_or_skip(root.parent, alias, target_is_directory=True)
    nested = root / "nested"
    nested.mkdir()
    # Both spellings resolve to the root itself as the derived store.
    target = alias / "mailbox-records"
    symlink_or_skip(root, target, target_is_directory=True)
    with pytest.raises(codec.CodecError) as error:
        with records.record_store(codec, alias / "mailbox", write=True):
            raise AssertionError("root alias admitted")
    assert error.value.code == "E_AUTH"


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest", "mailbox_publish_record"])
def test_r3_each_referenced_record_is_read_once_per_public_call(bound, monkeypatch, tool):
    root, writer, reader = bound
    rid = data(call(writer, "mailbox_publish_record", request("source")))["id"]
    content = json.dumps({"fields": {}, "body": "references", "refs": {"one": rid, "two": rid}})
    for identifier in ("a-wrapper", "b-wrapper"):
        assert "id" in data(call(writer, "mailbox_publish_record", request(identifier, content=content)))
    real_read = codec_store.Store._read_bytes
    reads = []
    def counted(self, reference, rootfd, budget=None, expected_size=None):
        if reference == rid:
            reads.append(budget)
        return real_read(self, reference, rootfd, budget, expected_size)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", counted)
    args = {"message_id": "a-wrapper"} if tool == "mailbox_read_record" else {}
    if tool == "mailbox_publish_record":
        reader, args = writer, request("c-wrapper", content=content)
    assert not call(reader, tool, args).get("isError")
    assert len(reads) == 1
    assert reads[0] is not None


def large_request(identifier, *, sender="a/orchestrator", to="a/lane/review", size=262100):
    meta = {"from": sender, "host": "host-one", "session": sender, "created_at": mailbox_module.timestamp()}
    content = {"fields": {}, "body": identifier, "refs": {}}
    initial = len(codec.canonical(codec.compose("text", json.dumps(content).encode(), meta)))
    content["body"] += "x" * (size - initial)
    assert len(codec.canonical(codec.compose("text", json.dumps(content).encode(), meta))) == size
    return request(identifier, to=to, content=json.dumps(content))


def grant_entry(path):
    return codec.parse(path.read_bytes())["fields"]["value"]


def test_r4_legacy_stub_copy_neither_revokes_nor_grants(bound):
    root, writer, reader = bound
    published = data(call(writer, "mailbox_publish_record", request()))
    stub = reader.checked_mailbox().messages()["record-1"]["message"]["body"]
    outsider = connection(root, "b/orchestrator")
    assert not call(outsider, "mailbox_publish", {"message_id": "paste", "to": "a/orchestrator",
        "type": "info", "body": stub + "\ninnocent paste"}).get("isError")
    assert data(call(writer, "mailbox_publish_record", request())) == published
    assert data(call(writer, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"
    assert data(call(reader, "mailbox_digest", {}))["messages"][0]["record"]["from"] == "a/orchestrator"
    content = json.dumps({"fields": {}, "body": "cite", "refs": {"original": published["id"]}})
    assert "id" in data(call(reader, "mailbox_publish_record", request("cite", to="a/orchestrator", content=content)))
    assert data(call(outsider, "mailbox_publish_record", request("denied", to="a/orchestrator", content=content))) == auth_error("reference")
    # A forged received stub cannot be used as a grant either.
    victim = connection(root, "b/front-door")
    assert not call(outsider, "mailbox_publish", {"message_id": "received-paste", "to": "b/front-door",
        "type": "info", "body": stub}).get("isError")
    assert data(call(victim, "mailbox_read_record", {"message_id": "received-paste"})) == auth_error("reference")


def test_r4_delegation_and_denials_ignore_unrelated_received_record_bytes(bound, monkeypatch):
    root, lead, reviewer = bound
    source = connection(root, "b/orchestrator")
    rid = data(call(source, "mailbox_publish_record", request("original", to="a/orchestrator")))["id"]
    forwarded = json.dumps({"fields": {}, "body": "delegate", "refs": {"review": rid}})
    assert "id" in data(call(lead, "mailbox_publish_record", request("delegate", content=forwarded)))
    unrelated = set()
    for number in range(65):
        unrelated.add(data(call(lead, "mailbox_publish_record", large_request("unrelated-" + str(number))))["id"])
    assert sum((root.parent / "mailbox-records" / (item + ".json")).stat().st_size for item in unrelated) > codec.MAX_REF_BYTES
    assert not call(lead, "mailbox_publish", {"message_id": "missing-stub", "to": "a/lane/review",
        "type": "info", "body": "aegis-record/1 sha256=" + "0" * 64 + " kind=text"}).get("isError")
    private = data(call(lead, "mailbox_publish_record", request("private", to="a/front-door")))["id"]
    real_read = codec_store.Store._read_bytes
    reads = []
    def guarded(self, reference, *args, **kwargs):
        assert reference not in unrelated, "authorization scanned unrelated records"
        reads.append(reference)
        return real_read(self, reference, *args, **kwargs)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", guarded)
    result = call(reviewer, "mailbox_publish_record", request("forward", to="a/orchestrator", content=forwarded))
    assert not result.get("isError"), result
    reads.clear()
    errors = []
    for number, denied in enumerate((private, "f" * 64)):
        args = request("probe-" + str(number), to="a/orchestrator", content=json.dumps({
            "fields": {}, "body": "probe", "refs": {"denied": denied}}))
        errors.append(call(reviewer, "mailbox_publish_record", args))
    assert errors[0] == errors[1]
    assert data(errors[0]) == auth_error("reference")
    assert reads == []


def test_r4_out_of_window_delegation_uses_the_index(bound, monkeypatch):
    root, lead, reviewer = bound
    source = connection(root, "b/orchestrator")
    rid = data(call(source, "mailbox_publish_record", request("original", to="a/orchestrator")))["id"]
    content = json.dumps({"fields": {}, "body": "grant", "refs": {"original": rid}})
    grant = data(call(lead, "mailbox_publish_record", request("grant", content=content)))["id"]
    assert "id" in data(call(lead, "mailbox_publish_record", request("later")))
    real_read = codec_store.Store._read_bytes
    def guarded(self, reference, *args, **kwargs):
        assert reference != grant, "a grant outside the digest window was opened"
        return real_read(self, reference, *args, **kwargs)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", guarded)
    digest = data(call(reviewer, "mailbox_digest", {"after_message_id": "grant"}))
    assert [row["message_id"] for row in digest["messages"]] == ["later"]
    assert "id" in data(call(reviewer, "mailbox_publish_record", request("own-wrapper", to="a/orchestrator", content=content)))
    expanded = data(call(reviewer, "mailbox_read_record", {"message_id": "own-wrapper", "expand": ["original"]}))
    assert expanded["data"]["refs"]["original"]["body"] == "# Evidence\nHOSTILE_MARKER"
    assert expanded["data"]["refs"]["original"]["meta"]["from"] == "b/orchestrator"


@pytest.mark.parametrize("extra", [0, 1, None], ids=["boundary", "plus-one", "reported-64-large"])
def test_r4_publication_and_default_reads_share_the_exact_64_record_budget(bound, extra):
    root, writer, reader = bound
    refs = {}
    for number in range(63):
        refs["r" + str(number)] = data(call(writer, "mailbox_publish_record", large_request("large-" + str(number))))["id"]
    # The last reference's size adjusts total I/O to MAX_REF_BYTES or MAX_REF_BYTES + 1.
    refs["r63"] = "0" * 64
    meta = {"from": "a/orchestrator", "host": "host-one", "session": "a/orchestrator", "created_at": mailbox_module.timestamp()}
    content = {"fields": {}, "body": "wrapper", "refs": refs}
    wrapper_size = len(codec.canonical(codec.compose("text", json.dumps(content).encode(), meta)))
    last_size = 262100 if extra is None else codec.MAX_REF_BYTES - 63 * 262100 - wrapper_size + extra
    last = large_request("last", size=last_size)
    refs["r63"] = data(call(writer, "mailbox_publish_record", last))["id"]
    result = call(writer, "mailbox_publish_record", request("wrapper", content=json.dumps(content)))
    if extra is None or extra:
        assert data(result) == publish_limit()
        assert "wrapper" not in writer.checked_mailbox().messages()
    else:
        assert not result.get("isError"), result
        assert not call(reader, "mailbox_read_record", {"message_id": "wrapper"}).get("isError")
        assert not call(reader, "mailbox_digest", {"after_message_id": "last", "limit": 1}).get("isError")


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest", "mailbox_publish_record"])
def test_r4_manifest_change_keeps_auth_and_busy_lock_names_mailbox_lock(bound, tool):
    root, writer, reader = bound
    call(writer, "mailbox_publish_record", request())
    args = request("second") if tool == "mailbox_publish_record" else ({"message_id": "record-1"} if tool == "mailbox_read_record" else {})
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["writer_limit"] = 2
    (root / "manifest.json").write_text(json.dumps(manifest))
    assert data(call(writer if tool == "mailbox_publish_record" else reader, tool, args)) == auth_error("binding")


def test_r4_busy_mailbox_lock_has_its_own_next_action(bound):
    root, writer, _ = bound
    with mcp.writer_lock(root):
        assert data(call(writer, "mailbox_publish_record", request())) == auth_error("mailbox_lock")


@pytest.mark.parametrize("phase", ["checked", "operation", "codec"])
def test_r4_recursion_is_format_not_authorization(bound, monkeypatch, phase):
    root, writer, reader = bound
    call(writer, "mailbox_publish_record", request())
    def recursed(*args, **kwargs):
        raise RecursionError("HOSTILE_MARKER")
    if phase == "checked":
        monkeypatch.setattr(mcp.Connection, "checked_mailbox", recursed)
    elif phase == "operation":
        monkeypatch.setattr(records, "_view", recursed)
    else:
        monkeypatch.setattr(records, "codec_tools", recursed)
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"})) == codec.CodecError("E_FORMAT").as_dict()


def test_r4_abandoned_pending_stub_is_reclaimed_on_next_publication(bound):
    root, writer, reader = bound
    pending = root / "a" / "lane" / ".pending-stub"
    pending.write_bytes(b"interrupted prior publication")
    pending.chmod(0o600)
    first = data(call(writer, "mailbox_publish_record", request()))
    assert "id" in first
    assert not pending.exists()
    assert data(call(writer, "mailbox_publish_record", request())) == first
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"


@pytest.mark.parametrize("phase", ["before-index", "after-index"])
def test_r4_crash_leaves_no_or_complete_grants_and_retry_is_idempotent(bound, phase):
    root, writer, reader = bound
    program = '''
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import hierarchy_mailbox_mcp as mcp
import hierarchy_mailbox_records as records
real_rename, real_link = os.rename, os.link
def renamed(source, target, *args, **kwargs):
    if sys.argv[3] == 'before-index' and str(target).startswith('.grants-'):
        os._exit(91)
    return real_rename(source, target, *args, **kwargs)
def linked(source, target, *args, **kwargs):
    if sys.argv[3] == 'after-index' and str(target).endswith('.md'):
        os._exit(91)
    return real_link(source, target, *args, **kwargs)
records.os = SimpleNamespace(**dict(vars(os), rename=renamed, link=linked))
connection = mcp.Connection(Path(sys.argv[2]), 'a/orchestrator', 'host-one', 'a/orchestrator', 1, records=True)
mcp.handle(connection, {'jsonrpc':'2.0','id':1,'method':'tools/call',
                       'params':{'name':'mailbox_publish_record','arguments':json.loads(sys.argv[4])}})
raise SystemExit('crash boundary was not reached')
'''
    run = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(HELPER.parent), str(root), phase,
                          json.dumps(request())], capture_output=True, text=True, timeout=20)
    assert run.returncode == 91 and not run.stderr, run.stdout + run.stderr
    store = root.parent / "mailbox-records"
    [record] = list(store.glob("*.json"))
    grant = store / (".grants-" + record.stem)
    if phase == "before-index":
        assert not grant.exists()
    else:
        entry = grant_entry(grant)
        assert entry["id"] == record.stem and entry["author"]["from"] == "a/orchestrator"
        assert {row["endpoint"] for row in entry["grants"]} == {"a/orchestrator", "a/lane/review"}
    # Simulate the owner inspecting and clearing abandoned reservations after process death.
    (root / ".write.lock").unlink(missing_ok=True)
    (store / ".publish.lock").unlink()
    (root.parent / ".records-store.lock").unlink()
    published = data(call(writer, "mailbox_publish_record", request()))
    assert "id" in published
    assert data(call(writer, "mailbox_publish_record", request())) == published
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"
    assert list(writer.checked_mailbox().messages()) == ["record-1"]


def test_r4_grants_are_consistent_for_concurrent_publishers(bound):
    root, writer, reader = bound
    rid = data(call(writer, "mailbox_publish_record", request("source")))["id"]
    content = json.dumps({"fields": {}, "body": "delegate", "refs": {"source": rid}})
    endpoints = ("a/lane/f2", "a/lane/review", "a/front-door")
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda endpoint: call(connection(root), "mailbox_publish_record",
            request("to-" + endpoint.rsplit("/", 1)[-1], to=endpoint, content=content)), endpoints))
    assert all(not result.get("isError") for result in results), results
    entry = grant_entry(root.parent / "mailbox-records" / (".grants-" + rid))
    assert {row["endpoint"] for row in entry["grants"]} == {"a/orchestrator", *endpoints}
    for endpoint in endpoints:
        identifier = "to-" + endpoint.rsplit("/", 1)[-1]
        expanded = data(call(connection(root, endpoint), "mailbox_read_record", {
            "message_id": identifier, "fields": ["body"], "expand": ["source"]}))
        assert expanded["data"]["refs"]["source"]["body"] == "# Evidence\nHOSTILE_MARKER"


@pytest.mark.parametrize("failure", ["oversize", "symlink", "mismatch", "fdopen"])
def test_r4_grant_failures_are_bounded_local_and_close_descriptors(bound, monkeypatch, failure):
    root, writer, reader = bound
    rid = data(call(writer, "mailbox_publish_record", request()))["id"]
    store = root.parent / "mailbox-records"
    grant = store / (".grants-" + rid)
    assert grant.is_file(), "publication did not record its grant index"
    opened, closed, names = [], [], {}
    real_open, real_close, real_fdopen = os.open, os.close, os.fdopen
    def tracked(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        opened.append(fd)
        names[fd] = path
        return fd
    def close(fd):
        closed.append(fd)
        return real_close(fd)
    def refused(fd, *args, **kwargs):
        if str(names[fd]).startswith(".grants-"):
            raise OSError("HOSTILE_MARKER")
        return real_fdopen(fd, *args, **kwargs)
    if failure == "oversize":
        with grant.open("wb") as stream:
            stream.truncate(codec.MAX_BYTES + 1)
        def parsed(*args, **kwargs):
            raise AssertionError("oversized grant was parsed")
        real_parse = codec.parse
        monkeypatch.setattr(codec, "parse", parsed)
    elif failure == "symlink":
        saved = store / "grant-backup"
        grant.rename(saved)
        symlink_or_skip(saved, grant)
    elif failure == "mismatch":
        envelope = codec.parse(grant.read_bytes())
        envelope["fields"]["value"]["author"]["session"] = "foreign-session"
        envelope["meta"]["session"] = "foreign-session"
        grant.write_bytes(codec.canonical(envelope))
    else:
        monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": tracked,
                            "close": close, "fdopen": refused}))
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"})) == auth_error("reference")
    if failure == "oversize":
        monkeypatch.setattr(codec, "parse", real_parse)
    if failure == "fdopen":
        monkeypatch.setattr(records, "os", os)
        assert sorted(opened) == sorted(closed)
    # Failure of one entry never revokes an independent record's grants.
    assert "id" in data(call(writer, "mailbox_publish_record", request("independent")))


def test_r4_shared_store_grants_are_scoped_to_each_mailbox_root(bound, monkeypatch):
    root, _, _ = bound
    second = root.parent / "second-mailbox"
    outsider = root.parent / "third-mailbox"
    shutil.copytree(root, second)
    shutil.copytree(root, outsider)
    monkeypatch.setattr(mailbox_module, "timestamp", lambda: "2026-11-12T13:45:00Z")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda mailbox: data(call(connection(mailbox), "mailbox_publish_record", request())),
                                (root, second)))
    assert results[0] == results[1]
    entry = grant_entry(root.parent / "mailbox-records" / (".grants-" + results[0]["id"]))
    assert len(entry["grants"]) == 4
    for mailbox in (root, second):
        assert data(call(connection(mailbox, "a/lane/review"), "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"
    # The same endpoint spelling in an unrelated mailbox has no inherited grant.
    stub = "aegis-record/1 sha256=" + results[0]["id"] + " kind=text"
    assert not call(connection(outsider), "mailbox_publish", {"message_id": "forged", "to": "a/lane/review",
                                                            "type": "info", "body": stub}).get("isError")
    assert data(call(connection(outsider, "a/lane/review"), "mailbox_read_record", {"message_id": "forged"})) == auth_error("reference")


def test_r4_grant_write_fdopen_failure_closes_every_owned_descriptor_and_retries(bound, monkeypatch):
    root, writer, _ = bound
    opened, closed, names = [], [], {}
    real_open, real_close, real_fdopen = os.open, os.close, os.fdopen
    def opened_fd(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        names[fd] = path
        opened.append(fd)
        return fd
    def closed_fd(fd):
        closed.append(fd)
        return real_close(fd)
    def wrapped(fd, *args, **kwargs):
        if names.get(fd) == ".pending-grants":
            raise OSError("HOSTILE_MARKER")
        return real_fdopen(fd, *args, **kwargs)
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": opened_fd,
                        "close": closed_fd, "fdopen": wrapped}))
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    monkeypatch.setattr(records, "os", os)
    assert sorted(opened) == sorted(closed)
    assert not list((root.parent / "mailbox-records").glob(".grants-*"))
    assert not list((root.parent / "mailbox-records").glob("*.json"))
    assert "id" in data(call(writer, "mailbox_publish_record", request()))


def test_r4_argon_orphaned_record_and_unknown_hash_have_identical_refusals(bound, monkeypatch):
    root, writer, attacker = bound
    directory = root.parent / "mailbox-records"
    directory.mkdir(mode=0o700)
    store = make_store(directory)
    try:
        value = codec.compose("text", b'{"fields":{},"body":"private orphan","refs":{}}', {
            "from": "b/orchestrator", "host": "host-one", "session": "b/orchestrator",
            "created_at": mailbox_module.timestamp()})
        rid = store.write(value)
    finally:
        store.close()
    def forbidden(*args, **kwargs):
        raise AssertionError("orphan authorization opened payload bytes")
    monkeypatch.setattr(codec_store.Store, "_read_bytes", forbidden)
    real_read = records._RecordAccess.read
    budgets = []
    def read(self, *args, **kwargs):
        try:
            return real_read(self, *args, **kwargs)
        finally:
            budgets.append(self.io.used)
    monkeypatch.setattr(records._RecordAccess, "read", read)
    answers = []
    for number, target in enumerate((rid, "0" * 64)):
        identifier = "probe-" + str(number)
        assert not call(attacker, "mailbox_publish", {"message_id": identifier, "to": "a/orchestrator",
            "type": "info", "body": "aegis-record/1 sha256=" + target + " kind=text"}).get("isError")
        answers.append(call(attacker, "mailbox_read_record", {"message_id": identifier}))
    assert answers[0] == answers[1]
    assert data(answers[0]) == auth_error("reference")
    assert all(budget == 0 for budget in budgets)
    assert not (root / ".root-id").exists()


def test_r5_device_number_change_preserves_grants(bound, monkeypatch):
    root, writer, reader = bound
    first = data(call(writer, "mailbox_publish_record", request()))
    info, real_fstat = root.stat(), os.fstat
    def changed(fd):
        value = real_fstat(fd)
        if (value.st_dev, value.st_ino) == (info.st_dev, info.st_ino):
            return SimpleNamespace(st_dev=value.st_dev + 4096, st_ino=value.st_ino,
                                   st_mode=value.st_mode, st_uid=value.st_uid, st_size=value.st_size,
                                   st_nlink=value.st_nlink)
        return value
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "fstat": changed}))
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"
    assert data(call(writer, "mailbox_publish_record", request())) == first


def test_r5_copy_restore_preserves_stable_identity_and_grants(bound):
    root, writer, _ = bound
    published = data(call(writer, "mailbox_publish_record", request()))
    parent = root.parent / "restored"
    parent.mkdir()
    restored = parent / root.name
    shutil.copytree(root, restored)
    shutil.copytree(root.parent / "mailbox-records", parent / "mailbox-records")
    assert data(call(connection(restored, "a/lane/review"), "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"
    assert data(call(connection(restored), "mailbox_publish_record", request())) == published
    assert (restored / ".root-id").read_bytes() == (root / ".root-id").read_bytes()


def test_r5_recreated_root_cannot_inherit_grants_even_if_inode_is_reused(bound, monkeypatch):
    root, writer, _ = bound
    seed = root.parent / "fresh-seed"
    shutil.copytree(root, seed)
    rid = data(call(writer, "mailbox_publish_record", request()))["id"]
    old_info = root.stat()
    old_id = (root / ".root-id").read_bytes() if (root / ".root-id").exists() else None
    root.rename(root.parent / "retired-mailbox")
    shutil.copytree(seed, root)
    new_info, real_fstat = root.stat(), os.fstat
    def reused(fd):
        value = real_fstat(fd)
        if (value.st_dev, value.st_ino) == (new_info.st_dev, new_info.st_ino):
            return SimpleNamespace(st_dev=old_info.st_dev, st_ino=old_info.st_ino,
                                   st_mode=value.st_mode, st_uid=value.st_uid, st_size=value.st_size,
                                   st_nlink=value.st_nlink)
        return value
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "fstat": reused}))
    fresh = connection(root)
    assert "id" in data(call(fresh, "mailbox_publish_record", request("fresh", content=json.dumps({
        "fields": {}, "body": "new root content", "refs": {}}))))
    assert not call(fresh, "mailbox_publish", {"message_id": "probe", "to": "a/lane/review", "type": "info",
        "body": "aegis-record/1 sha256=" + rid + " kind=text"}).get("isError")
    assert data(call(connection(root, "a/lane/review"), "mailbox_read_record", {"message_id": "probe"})) == auth_error("reference")
    assert (root / ".root-id").read_bytes() != old_id


@pytest.mark.parametrize("failure", ["partial", "empty", "oversize", "bad", "symlink", "marker"])
def test_r5_invalid_root_identity_is_never_silently_recreated(bound, monkeypatch, failure):
    root, writer, reader = bound
    published = data(call(writer, "mailbox_publish_record", request()))
    identity, marker = root / ".root-id", root / ".records-root"
    assert identity.is_file() and not marker.exists(), "identity must be installed as one complete file"
    original = identity.read_bytes()
    if failure == "partial":
        identity.unlink()
        marker.write_bytes(records.ROOT_MARKER)
    elif failure == "empty":
        identity.write_bytes(b"")
    elif failure == "oversize":
        identity.write_bytes(b"x" * 4096)
    elif failure == "bad":
        identity.write_bytes(b"HOSTILE_MARKER\n")
    elif failure == "marker":
        marker.write_bytes(records.ROOT_MARKER)
    else:
        outside = root.parent / "foreign-identity"
        outside.write_bytes(original)
        identity.unlink()
        symlink_or_skip(outside, identity)
    before = None if not identity.exists() else identity.read_bytes()
    for name, args in (("mailbox_read_record", {"message_id": "record-1"}),
                       ("mailbox_publish_record", request("blocked"))):
        assert data(call(reader if name == "mailbox_read_record" else writer, name, args)) == auth_error("identity")
    assert (None if not identity.exists() else identity.read_bytes()) == before
    if failure == "symlink":
        assert identity.is_symlink() and outside.read_bytes() == original
        identity.unlink()
    identity.write_bytes(original)
    marker.unlink(missing_ok=True)
    identity.chmod(0o600)
    assert data(call(writer, "mailbox_publish_record", request())) == published


@pytest.mark.parametrize("options", [{}, {"fields": ["unknown"]}, {"fields": [123]}, {"max_chars": -1}])
def test_r5_cross_route_ids_refuse_before_format_or_grant_access(bound, monkeypatch, options):
    root, writer, reader = bound
    call(writer, "mailbox_publish_record", request("foreign-record", to="a/front-door"))
    for identifier, body in (("foreign-text", "ordinary"), ("foreign-bad-stub", "aegis-record/1 invalid")):
        assert not call(writer, "mailbox_publish", {"message_id": identifier, "to": "a/front-door",
                                                   "type": "info", "body": body}).get("isError")
    def forbidden(*args, **kwargs):
        raise AssertionError("cross-route lookup reached the record store")
    monkeypatch.setattr(records, "record_store", forbidden)
    answers = [call(reader, "mailbox_read_record", dict(options, message_id=identifier)) for identifier in
               ("foreign-record", "foreign-text", "foreign-bad-stub", "missing")]
    assert all(answer == answers[0] for answer in answers)
    assert data(answers[0]) == auth_error("reference")


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r5_granted_hash_attribution_refusal_has_accurate_guidance(bound, monkeypatch, tool):
    root, writer, reviewer = bound
    rid = data(call(writer, "mailbox_publish_record", request()))["id"]
    stub = "aegis-record/1 sha256=" + rid + " kind=text"
    assert not call(reviewer, "mailbox_publish", {"message_id": "paste", "to": "a/orchestrator",
        "type": "info", "body": stub}).get("isError")
    real_read, reads = codec_store.Store._read_bytes, []
    def counted(self, reference, *args, **kwargs):
        reads.append(reference)
        return real_read(self, reference, *args, **kwargs)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", counted)
    args = {"message_id": "paste"} if tool == "mailbox_read_record" else {}
    assert data(call(writer, tool, args)) == auth_error("attribution")
    assert reads == [rid], "the test must reach attribution after a granted payload read"
    assert data(call(writer, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"


def test_r5_publish_output_limit_has_publish_guidance_and_retries(bound, monkeypatch):
    root, writer, _ = bound
    maximum = records.MAX_CHARS
    monkeypatch.setattr(records, "MAX_CHARS", 10)
    assert data(call(writer, "mailbox_publish_record", request())) == publish_limit()
    assert not writer.checked_mailbox().messages()
    monkeypatch.setattr(records, "MAX_CHARS", maximum)
    published = data(call(writer, "mailbox_publish_record", request()))
    assert data(call(writer, "mailbox_publish_record", request())) == published


def test_r5_publish_grant_limit_has_grant_guidance_and_leaves_state_unchanged(bound):
    root, writer, _ = bound
    rid = data(call(writer, "mailbox_publish_record", request("source", to="a/front-door")))["id"]
    path = root.parent / "mailbox-records" / (".grants-" + rid)
    envelope = codec.parse(path.read_bytes())
    entry = envelope["fields"]["value"]
    owner = next(row for row in entry["grants"] if row["endpoint"] == "a/orchestrator")
    entry["grants"] = [owner] + [{"root": owner["root"], "endpoint": "a/lane/slot-" + str(n)} for n in range(1023)]
    raw = codec.canonical(envelope)
    path.write_bytes(raw)
    args = request("too-many", content=json.dumps({"fields": {}, "body": "delegate", "refs": {"source": rid}}))
    assert data(call(writer, "mailbox_publish_record", args)) == publish_limit(grants=True)
    assert path.read_bytes() == raw
    assert list(writer.checked_mailbox().messages()) == ["source"]


def r5_reference_wrapper(writer, monkeypatch, order):
    stamp = "2026-11-12T18:05:00Z"
    monkeypatch.setattr(mailbox_module, "timestamp", lambda: stamp)
    meta = {"from": "a/orchestrator", "host": "host-one", "session": "a/orchestrator", "created_at": stamp}
    for number in range(256):
        content = {"fields": {}, "body": "private-" + str(number), "refs": {}}
        rid = codec.record_id(codec.compose("text", json.dumps(content).encode(), meta))
        if rid.startswith("8"):
            break
    else:
        raise AssertionError("bounded private-record fixture search failed")
    assert data(call(writer, "mailbox_publish_record", request("private", to="a/front-door",
                                                              content=json.dumps(content))))["id"] == rid
    for number in range(256):
        content = {"fields": {}, "body": "wrapper-" + str(number), "refs": {"private": rid}}
        wrapper = codec.record_id(codec.compose("text", json.dumps(content).encode(), meta))
        if (wrapper < rid) == (order == "wrapper-first"):
            return rid, wrapper, request("wrapper", content=json.dumps(content))
    raise AssertionError("bounded wrapper fixture search failed")


@pytest.mark.parametrize("order", ["wrapper-first", "wrapper-last"])
def test_r5_crash_between_ref_and_wrapper_does_not_activate_delegation(bound, monkeypatch, order):
    root, writer, reviewer = bound
    rid, wrapper, args = r5_reference_wrapper(writer, monkeypatch, order)
    program = '''
import json, os, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import hierarchy_mailbox as mailbox
import hierarchy_mailbox_mcp as mcp
import hierarchy_mailbox_records as records
mailbox.timestamp = lambda: '2026-11-12T18:05:00Z'
real_rename = os.rename
def renamed(source, target, *args, **kwargs):
    value = real_rename(source, target, *args, **kwargs)
    if str(target) == '.grants-' + sys.argv[4]:
        os._exit(92)
    return value
records.os = SimpleNamespace(**dict(vars(os), rename=renamed))
connection = mcp.Connection(Path(sys.argv[2]), 'a/orchestrator', 'host-one', 'a/orchestrator', 1, records=True)
mcp.handle(connection, {'jsonrpc':'2.0','id':1,'method':'tools/call',
                       'params':{'name':'mailbox_publish_record','arguments':json.loads(sys.argv[3])}})
raise SystemExit('reference update crash boundary was not reached')
'''
    run = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(HELPER.parent), str(root),
                          json.dumps(args), rid], capture_output=True, text=True, timeout=20)
    assert run.returncode == 92 and not run.stderr, run.stdout + run.stderr
    directory = root.parent / "mailbox-records"
    assert not (directory / (".grants-" + wrapper)).exists(), "wrapper entry was not written last"
    assert any(row.get("via") == wrapper for row in grant_entry(directory / (".grants-" + rid))["grants"])
    (root / ".write.lock").unlink(missing_ok=True)
    assert (directory / ".publish.lock").is_file() and (root.parent / ".records-store.lock").is_file()
    ticks = iter((0, 6))
    with patch.object(records, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None)):
        assert data(call(writer, "mailbox_publish_record", request("blocked-r8"))) == auth_error("lock")
    (directory / ".publish.lock").unlink()
    (root.parent / ".records-store.lock").unlink()
    probe = request("probe", to="a/orchestrator", content=json.dumps({
        "fields": {}, "body": "use private", "refs": {"private": rid}}))
    assert data(call(reviewer, "mailbox_publish_record", probe)) == auth_error("reference")
    assert data(call(writer, "mailbox_publish_record", args))["id"] == wrapper
    assert data(call(writer, "mailbox_publish_record", args))["id"] == wrapper
    assert not call(reviewer, "mailbox_publish_record", probe).get("isError")


def test_r5_concurrent_reader_waits_for_complete_wrapper_grant(bound, monkeypatch):
    root, writer, reviewer = bound
    rid, wrapper, args = r5_reference_wrapper(writer, monkeypatch, "wrapper-last")
    assert not call(writer, "mailbox_publish", {"message_id": "probe", "to": "a/lane/review", "type": "info",
        "body": "aegis-record/1 sha256=" + rid + " kind=text"}).get("isError")
    entered, release = Event(), Event()
    real_rename, real_read = os.rename, codec_store.Store._read_bytes
    def renamed(source, target, *values, **options):
        result = real_rename(source, target, *values, **options)
        if target == ".grants-" + rid:
            entered.set()
            assert release.wait(5), "wrapper publication latch was not released"
        return result
    def read(self, reference, *values, **options):
        if entered.is_set() and not release.is_set() and reference == rid:
            raise AssertionError("provisional delegation opened private payload")
        return real_read(self, reference, *values, **options)
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "rename": renamed}))
    monkeypatch.setattr(codec_store.Store, "_read_bytes", read)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(call, connection(root), "mailbox_publish_record", args)
        try:
            assert entered.wait(5), "publisher did not reach its reference grant update"
            assert data(call(reviewer, "mailbox_read_record", {"message_id": "probe"})) == auth_error("reference")
        finally:
            release.set()
        assert data(future.result(timeout=10))["id"] == wrapper
    assert data(call(reviewer, "mailbox_read_record", {"message_id": "probe"}))["from"] == "a/orchestrator"


@pytest.mark.parametrize("phase,name", [("read", ".root-id"), ("create", ".pending-root-id")])
def test_r5_root_identity_fdopen_failures_close_owned_fds_and_recover(bound, monkeypatch, phase, name):
    root, writer, reader = bound
    if phase == "read":
        assert "id" in data(call(writer, "mailbox_publish_record", request()))
    opened, closed, names = [], [], {}
    real_open, real_close, real_fdopen = os.open, os.close, os.fdopen
    def opened_fd(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        opened.append(fd)
        names[fd] = path
        return fd
    def closed_fd(fd):
        closed.append(fd)
        return real_close(fd)
    def wrapped(fd, mode, *args, **kwargs):
        if names[fd] == name and mode == ("rb" if phase == "read" else "wb"):
            raise OSError("HOSTILE_MARKER")
        return real_fdopen(fd, mode, *args, **kwargs)
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": opened_fd,
                        "close": closed_fd, "fdopen": wrapped}))
    result = call(reader, "mailbox_read_record", {"message_id": "record-1"}) if phase == "read" else call(writer, "mailbox_publish_record", request())
    assert data(result) == (auth_error("identity") if phase == "read" else codec.CodecError("E_AUTH").as_dict())
    monkeypatch.setattr(records, "os", os)
    assert sorted(opened) == sorted(closed)
    if phase == "create":
        assert not (root / ".root-id").exists() and not (root / ".records-root").exists()
    published = data(call(writer, "mailbox_publish_record", request()))
    assert data(call(writer, "mailbox_publish_record", request())) == published
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"}))["from"] == "a/orchestrator"


def test_r5_concurrent_publishers_create_exactly_one_root_identity(bound, monkeypatch):
    root, _, _ = bound
    generate, generated, start = records.uuid.uuid4, [], Event()
    def token():
        value = generate()
        generated.append(value.hex)
        return value
    monkeypatch.setattr(records, "uuid", SimpleNamespace(uuid4=token))
    def publish(identifier):
        assert start.wait(5), "publisher start latch was not released"
        return call(connection(root), "mailbox_publish_record", request(identifier))
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(publish, identifier) for identifier in ("first", "second")]
        start.set()
        assert all(not future.result(timeout=10).get("isError") for future in futures)
    assert len(generated) == 1
    assert (root / ".root-id").read_bytes() == records.ROOT_MARKER + generated[0].encode("ascii") + b"\n"


def test_r6_delegated_body_expands_one_level_in_read_and_digest(bound, monkeypatch):
    root, lead, reviewer = bound
    source = connection(root, "b/orchestrator")
    leaf = data(call(source, "mailbox_publish_record", request("leaf", to="b/front-door")))["id"]
    parent_content = json.dumps({"fields": {}, "body": "delegated body", "refs": {"private": leaf}})
    parent = data(call(source, "mailbox_publish_record", request("original", to="a/orchestrator",
                                                              content=parent_content)))["id"]
    wrapper = request("wrapper", content=json.dumps({"fields": {}, "body": "wrapper", "refs": {"original": parent}}))
    assert "id" in data(call(lead, "mailbox_publish_record", wrapper))
    real_read, reads = codec_store.Store._read_bytes, []
    def read(self, rid, *args, **kwargs):
        assert rid != leaf, "one-level expansion opened a second-level private payload"
        reads.append(rid)
        return real_read(self, rid, *args, **kwargs)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", read)
    for tool, args in (("mailbox_read_record", {"message_id": "wrapper"}), ("mailbox_digest", {})):
        reads.clear()
        result = data(call(reviewer, tool, dict(args, fields=["body"], expand=["original"])))
        view = result if tool == "mailbox_read_record" else result["messages"][0]["record"]
        child = view["data"]["refs"]["original"]
        assert child["body"] == "delegated body" and child["meta"]["from"] == "b/orchestrator"
        assert child["refs"] == {"private": leaf}
        assert reads.count(parent) == 1 and len(reads) == 2
    assert data(call(reviewer, "mailbox_read_record", {"message_id": "wrapper", "expand": ["original"],
                                                     "max_chars": 200})) == codec.CodecError("E_LIMIT").as_dict()
    outsider = connection(root, "a/lane/f2")
    assert not call(lead, "mailbox_publish", {"message_id": "pasted", "to": "a/lane/f2", "type": "info",
        "body": "aegis-record/1 sha256=" + parent + " kind=text"}).get("isError")
    reads.clear()
    answers = [call(outsider, "mailbox_read_record", {"message_id": identifier})
               for identifier in ("original", "pasted", "unknown")]
    assert answers[0] == answers[1] == answers[2]
    assert data(answers[0]) == auth_error("reference") and reads == []


@pytest.mark.parametrize("expand", ["original", ["original"] * 65, ["x" * 65], ["HOSTILE_MARKER\n"]])
def test_r6_invalid_expansion_refuses_before_record_io(bound, monkeypatch, expand):
    root, writer, reader = bound
    assert "id" in data(call(writer, "mailbox_publish_record", request()))
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid expansion opened a payload")
    monkeypatch.setattr(codec_store.Store, "_read_bytes", forbidden)
    for tool, args in (("mailbox_read_record", {"message_id": "record-1"}), ("mailbox_digest", {})):
        assert data(call(reader, tool, dict(args, expand=expand))) == codec.CodecError("E_REF").as_dict()


@pytest.mark.parametrize("has_store", [False, True], ids=["missing-store", "empty-store"])
@pytest.mark.parametrize("body,code", [("ordinary", "E_FORMAT"), ("aegis-record/1 invalid", "E_FORMAT"),
    ("aegis-record/1 sha256=" + "0" * 64 + " kind=text", "reference")])
def test_r6_never_published_root_refusals_do_not_suggest_identity_restore(bound, has_store, body, code):
    root, writer, reader = bound
    directory = root.parent / "mailbox-records"
    if has_store:
        directory.mkdir(mode=0o700)
    assert not call(writer, "mailbox_publish", {"message_id": "probe", "to": "a/lane/review",
                                               "type": "info", "body": body}).get("isError")
    expected = auth_error("reference") if code == "reference" else codec.CodecError(code).as_dict()
    assert data(call(reader, "mailbox_read_record", {"message_id": "probe"})) == expected
    digest = data(call(reader, "mailbox_digest", {}))
    if body == "ordinary":
        assert digest["messages"][0]["body"] == body
    else:
        assert digest == expected
    assert directory.exists() is has_store
    assert not (root / ".root-id").exists() and not (root / ".records-root").exists()


@pytest.mark.parametrize("has_store", [False, True], ids=["missing-store", "empty-store"])
@pytest.mark.parametrize("reason", ["reference", "limit"])
def test_r6_refused_first_publish_does_not_initialize_root(bound, monkeypatch, has_store, reason):
    root, writer, _ = bound
    directory = root.parent / "mailbox-records"
    if has_store:
        directory.mkdir(mode=0o700)
    args = request()
    if reason == "reference":
        args["content"] = json.dumps({"fields": {}, "body": "ungranted", "refs": {"unknown": "0" * 64}})
        expected = auth_error("reference")
    else:
        monkeypatch.setattr(records, "MAX_CHARS", 10)
        expected = publish_limit()
    assert data(call(writer, "mailbox_publish_record", args)) == expected
    assert directory.exists() is has_store
    assert not (root / ".root-id").exists() and not (root / ".records-root").exists()
    assert not (root / ".pending-root-id").exists()
    assert not writer.checked_mailbox().messages()
    monkeypatch.setattr(records, "MAX_CHARS", 60000)
    published = data(call(writer, "mailbox_publish_record", request()))
    assert "id" in published and data(call(writer, "mailbox_publish_record", request())) == published


@pytest.mark.parametrize("phase", ["opened", "synced", "linked"])
def test_r6_crash_during_identity_initialization_recovers_on_next_publish(bound, phase):
    root, writer, reader = bound
    program = '''
import os, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import hierarchy_mailbox_mcp as mcp
import hierarchy_mailbox_records as records
real_open, real_fsync, real_link = os.open, os.fsync, os.link
pending = []
def opened(path, *args, **kwargs):
    fd = real_open(path, *args, **kwargs)
    if path == '.pending-root-id':
        pending.append(fd)
        if sys.argv[3] == 'opened':
            os._exit(93)
    return fd
def synced(fd):
    result = real_fsync(fd)
    if fd in pending and sys.argv[3] == 'synced':
        os._exit(93)
    return result
def linked(source, target, *args, **kwargs):
    result = real_link(source, target, *args, **kwargs)
    if target == '.root-id' and sys.argv[3] == 'linked':
        os._exit(93)
    return result
records.os = SimpleNamespace(**dict(vars(os), open=opened, fsync=synced, link=linked))
connection = mcp.Connection(Path(sys.argv[2]), 'a/orchestrator', 'host-one', 'a/orchestrator', 1, records=True)
mcp.handle(connection, {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{
    'name':'mailbox_publish_record','arguments':{'message_id':'first','to':'a/lane/review','type':'info',
    'kind':'text','content':'{"fields":{},"body":"first","refs":{}}'}}})
raise SystemExit('identity crash boundary was not reached')
'''
    run = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(HELPER.parent), str(root), phase],
                         capture_output=True, text=True, timeout=20)
    assert run.returncode == 93 and not run.stderr, run.stdout + run.stderr
    assert not (root / ".records-root").exists()
    assert (root / ".pending-root-id").is_file()
    identity = (root / ".root-id").read_bytes() if phase == "linked" else None
    assert (root / ".root-id").exists() is (phase == "linked")
    (root / ".write.lock").unlink(missing_ok=True)
    (root.parent / "mailbox-records" / ".publish.lock").unlink(missing_ok=True)
    (root.parent / ".records-store.lock").unlink()
    published = data(call(writer, "mailbox_publish_record", request()))
    assert "id" in published and data(call(writer, "mailbox_publish_record", request())) == published
    assert data(call(reader, "mailbox_read_record", {"message_id": "record-1"}))["data"]["body"] == "# Evidence\nHOSTILE_MARKER"
    if identity is not None:
        assert (root / ".root-id").read_bytes() == identity
    assert not (root / ".pending-root-id").exists()


def test_r6_handoff_successor_retry_gets_new_message_id_guidance_before_io(bound, monkeypatch):
    root, _, reader = bound
    args = request(to="a/orchestrator")
    assert "id" in data(call(reader, "mailbox_publish_record", args))
    brief = root.parent / "brief.md"
    draft = invoke(root, "draft-handoff", {"endpoint": "a/lane/review", "host": "host-one", "session": "successor",
        "outgoing_stopped": True, "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]})
    binding = invoke(root, "bind", draft)
    invoke(root, "ack-handoff", {"endpoint": "a/lane/review", "session": "successor", "generation": 2,
                                "checkpoint_sha256": binding["checkpoint_sha256"]})
    successor = mcp.Connection(root, "a/lane/review", "host-one", "successor", 2, records=True)
    def forbidden(*args, **kwargs):
        raise AssertionError("sender-binding collision reached the record store")
    monkeypatch.setattr(records, "record_store", forbidden)
    assert data(call(successor, "mailbox_publish_record", args)) == auth_error("message_id")


@pytest.mark.parametrize("cause", ["lock", "grants"])
def test_r6_first_identity_is_installed_only_after_shared_store_accepts(bound, monkeypatch, cause):
    root, writer, _ = bound
    directory = root.parent / "mailbox-records"
    if cause == "lock":
        directory.mkdir(mode=0o700)
        (directory / ".publish.lock").write_bytes(b"")
        ticks = iter((0, 0, 6))
        monkeypatch.setattr(records, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None))
        expected = auth_error("lock")
    else:
        sibling = root.parent / "sibling"
        shutil.copytree(root, sibling)
        monkeypatch.setattr(mailbox_module, "timestamp", lambda: "2026-11-12T02:22:00Z")
        rid = data(call(connection(sibling), "mailbox_publish_record", request()))["id"]
        path = directory / (".grants-" + rid)
        envelope = codec.parse(path.read_bytes())
        entry = envelope["fields"]["value"]
        scope = entry["grants"][0]["root"]
        entry["grants"] = [{"root": scope, "endpoint": "a/lane/slot-" + str(n)} for n in range(1024)]
        path.write_bytes(codec.canonical(envelope))
        expected = publish_limit(grants=True)
    assert data(call(writer, "mailbox_publish_record", request())) == expected
    assert not (root / ".root-id").exists() and not (root / ".pending-root-id").exists()
    assert not writer.checked_mailbox().messages()


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r7_large_delegated_record_has_its_own_selectors_and_outline(bound, monkeypatch, tool):
    root, lead, reviewer = bound
    source = connection(root, "b/orchestrator")
    content = json.dumps({"fields": {"value": {"padding": "x" * 100000}}, "body": "small delegated body", "refs": {}})
    rid = data(call(source, "mailbox_publish_record", request("original", to="a/orchestrator", kind="record", content=content)))["id"]
    assert "id" in data(call(lead, "mailbox_publish_record", request("wrapper", content=json.dumps({
        "fields": {}, "body": "wrapper body", "refs": {"original": rid}}))))
    for identifier in ("later", "last"):
        assert "id" in data(call(lead, "mailbox_publish_record", request(identifier)))
    args = {"ref": rid} if tool == "mailbox_read_record" else {"refs": [rid]}
    real_read, reads = codec_store.Store._read_bytes, []
    def read(self, reference, *values, **options):
        reads.append(reference)
        return real_read(self, reference, *values, **options)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", read)
    selected = data(call(reviewer, tool, dict(args, fields=["body"])))
    view = selected if tool == "mailbox_read_record" else selected["records"][0]
    assert view["data"]["body"] == "small delegated body"
    assert reads.count(rid) == 1
    if tool == "mailbox_digest":
        assert [row["message_id"] for row in selected["messages"]] == ["wrapper", "later", "last"]
    expected = data(call(lead, "mailbox_read_record", {"ref": rid}))
    for options in ({}, {"outline": True}):
        actual = data(call(reviewer, tool, dict(args, **options)))
        actual_view = actual if tool == "mailbox_read_record" else actual["records"][0]
        endpoint = data(call(lead, "mailbox_read_record", dict(ref=rid, **options)))
        assert actual_view == endpoint
        assert len(json.dumps(actual)) <= 60000
        assert "outline" in actual_view
    assert "outline" in expected
    assert data(call(reviewer, tool, dict(args, fields=["fields"]))) == codec.CodecError("E_LIMIT").as_dict()
    assert data(call(reviewer, tool, dict(args, fields=["body"], max_chars=10))) == codec.CodecError("E_LIMIT").as_dict()
    outsider = connection(root, "a/lane/f2")
    reads.clear()
    answers = []
    for reference in (rid, "0" * 64):
        query = {"ref": reference} if tool == "mailbox_read_record" else {"refs": [reference]}
        answers.append(call(outsider, tool, dict(query, fields=["body"])))
    assert answers[0] == answers[1] and data(answers[0]) == auth_error("reference")
    assert reads == [], "unauthorized/unknown references opened payload bytes"


@pytest.mark.parametrize("bad", ["../outside", "x" * 65, "A" * 64, ["0" * 64], "0" * 63 + "\n"])
def test_r7_reference_shape_is_refused_before_any_payload_io(bound, monkeypatch, bad):
    root, _, reader = bound
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid reference reached a store")
    monkeypatch.setattr(records, "record_store", forbidden)
    for tool, args in (("mailbox_read_record", {"ref": bad}), ("mailbox_digest", {"refs": [bad]})):
        assert data(call(reader, tool, args)) == auth_error("reference")


def test_r7_digest_authorizes_all_requested_refs_before_reading_any(bound, monkeypatch):
    root, lead, reviewer = bound
    rid = data(call(lead, "mailbox_publish_record", request()))["id"]
    def forbidden(*args, **kwargs):
        raise AssertionError("partly authorized digest opened a payload")
    monkeypatch.setattr(codec_store.Store, "_read_bytes", forbidden)
    assert data(call(reviewer, "mailbox_digest", {"refs": [rid, "0" * 64], "fields": ["body"]})) == auth_error("reference")
    assert data(call(reviewer, "mailbox_digest", {"refs": [rid] * 65})) == codec.CodecError("E_REF").as_dict()


@pytest.mark.parametrize("failure", ["unsafe-stub", "stub-open", "grant-open", "link", "identity-link-after"])
def test_r7_refused_first_commit_reclaims_only_its_store_and_identity(bound, monkeypatch, failure):
    root, writer, reviewer = bound
    directory = root.parent / "mailbox-records"
    destination = writer.checked_mailbox().route("a/orchestrator", "a/lane/review")
    pending = destination / ".pending-stub"
    real_open, real_link = os.open, os.link
    if failure == "unsafe-stub":
        pending.write_bytes(b"untrusted staging")
        pending.chmod(0o666)
    def opened(path, *args, **kwargs):
        target = ".pending-stub" if failure == "stub-open" else ".pending-grants"
        if failure in ("stub-open", "grant-open") and path == target:
            raise PermissionError("HOSTILE_MARKER")
        return real_open(path, *args, **kwargs)
    def linked(source, target, *args, **kwargs):
        if failure == "link" and str(target).endswith(".md"):
            raise PermissionError("HOSTILE_MARKER")
        result = real_link(source, target, *args, **kwargs)
        if failure == "identity-link-after" and target == ".root-id":
            raise PermissionError("HOSTILE_MARKER")
        return result
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": opened, "link": linked}))
    assert data(call(writer, "mailbox_publish_record", request())) == codec.CodecError("E_AUTH").as_dict()
    assert not (root / ".root-id").exists() and not (root / ".pending-root-id").exists()
    assert not directory.exists(), "a refused first commit retained its empty new store"
    assert not (root.parent / ".records-store.lock").exists()
    assert not call(writer, "mailbox_publish", {"message_id": "ungranted", "to": "a/lane/review", "type": "info",
        "body": "aegis-record/1 sha256=" + "0" * 64 + " kind=text"}).get("isError")
    assert data(call(reviewer, "mailbox_read_record", {"message_id": "ungranted"})) == auth_error("reference")
    monkeypatch.setattr(records, "os", os)
    if failure == "unsafe-stub":
        assert pending.read_bytes() == b"untrusted staging"
        pending.chmod(0o600)
    published = data(call(writer, "mailbox_publish_record", request()))
    assert "id" in published and data(call(writer, "mailbox_publish_record", request())) == published


@pytest.mark.parametrize("failure", ["tamper", "unsafe-grant"])
def test_r7_first_commit_preserves_a_preexisting_shared_store(bound, monkeypatch, failure):
    root, writer, reviewer = bound
    directory = root.parent / "mailbox-records"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(mailbox_module, "timestamp", lambda: "2026-11-13T05:54:00Z")
    args = request()
    value = codec.compose(args["kind"], args["content"].encode(), {"from": "a/orchestrator", "host": "host-one",
        "session": "a/orchestrator", "created_at": "2026-11-13T05:54:00Z"})
    rid = codec.record_id(value)
    existing = directory / (rid + ".json" if failure == "tamper" else ".pending-grants")
    existing.write_bytes(b"HOSTILE_MARKER")
    existing.chmod(0o600 if failure == "tamper" else 0o666)
    before = existing.read_bytes()
    expected = codec.CodecError("E_HASH" if failure == "tamper" else "E_AUTH").as_dict()
    assert data(call(writer, "mailbox_publish_record", args)) == expected
    assert not (root / ".root-id").exists() and directory.is_dir()
    assert existing.read_bytes() == before, "rollback changed preexisting owner state"
    assert not call(writer, "mailbox_publish", {"message_id": "ungranted", "to": "a/lane/review", "type": "info",
        "body": "aegis-record/1 sha256=" + rid + " kind=text"}).get("isError")
    assert data(call(reviewer, "mailbox_read_record", {"message_id": "ungranted"})) == auth_error("reference")


def test_r7_failed_first_publisher_cannot_remove_a_concurrent_publishers_store(bound, monkeypatch):
    root, writer, _ = bound
    second = root.parent / "second-mailbox"
    shutil.copytree(root, second)
    entered, attempted, release = Event(), Event(), Event()
    real_open = os.open
    def opened(path, *args, **kwargs):
        if path == ".pending-stub" and not entered.is_set():
            entered.set()
            assert release.wait(5), "failed publisher latch was not released"
            raise PermissionError("HOSTILE_MARKER")
        if path == ".records-store.lock" and entered.is_set() and not release.is_set():
            attempted.set()
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "open": opened}))
    with ThreadPoolExecutor(max_workers=2) as pool:
        failed = pool.submit(call, writer, "mailbox_publish_record", request())
        try:
            assert entered.wait(5)
            successful = pool.submit(call, connection(second), "mailbox_publish_record", request("second"))
            assert attempted.wait(5), "second publisher did not wait before binding the store"
        finally:
            release.set()
        assert data(failed.result(timeout=10)) == codec.CodecError("E_AUTH").as_dict()
        published = data(successful.result(timeout=10))
    assert not (root / ".root-id").exists() and "id" in published
    assert data(call(connection(second, "a/lane/review"), "mailbox_read_record", {"message_id": "second"}))["data"]["body"] == "# Evidence\nHOSTILE_MARKER"
    assert not (root.parent / ".records-store.lock").exists()


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r7_reference_outline_does_not_open_unselected_private_children(bound, monkeypatch, tool):
    root, lead, reviewer = bound
    source = connection(root, "b/orchestrator")
    leaf = data(call(source, "mailbox_publish_record", request("leaf", to="b/front-door")))["id"]
    rid = data(call(source, "mailbox_publish_record", request("parent", to="a/orchestrator", content=json.dumps({
        "fields": {}, "body": "selected parent", "refs": {"private": leaf}}))))["id"]
    assert "id" in data(call(lead, "mailbox_publish_record", request("wrapper", content=json.dumps({
        "fields": {}, "body": "wrapper", "refs": {"parent": rid}}))))
    real_read, reads = codec_store.Store._read_bytes, []
    def read(self, reference, *args, **kwargs):
        assert reference != leaf, "outline opened an unselected private child"
        reads.append(reference)
        return real_read(self, reference, *args, **kwargs)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", read)
    args = {"ref": rid} if tool == "mailbox_read_record" else {"refs": [rid]}
    result = data(call(reviewer, tool, dict(args, outline=True)))
    view = result if tool == "mailbox_read_record" else result["records"][0]
    assert view["kind"] == "text" and "outline" in view and "data" not in view
    assert reads.count(rid) == 1


def r8_delegated_chain(bound):
    root, lead, reviewer = bound
    source = connection(root, "b/orchestrator")
    leaf = data(call(source, "mailbox_publish_record", request("leaf", to="b/front-door")))["id"]
    parent = data(call(source, "mailbox_publish_record", request("parent", to="a/orchestrator", content=json.dumps({
        "fields": {}, "body": "parent body", "refs": {"private": leaf}}))))["id"]
    assert "id" in data(call(lead, "mailbox_publish_record", request("wrapper", content=json.dumps({
        "fields": {}, "body": "wrapper body", "refs": {"parent": parent}}))))
    other = data(call(lead, "mailbox_publish_record", request("later", content=json.dumps({
        "fields": {}, "body": "later body", "refs": {}}))))["id"]
    return root, lead, reviewer, leaf, parent, other


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r8_default_delegated_view_withholds_ungranted_children_per_row(bound, monkeypatch, tool):
    root, lead, reviewer, leaf, parent, other = r8_delegated_chain(bound)
    args = {"ref": parent} if tool == "mailbox_read_record" else {"refs": [parent, other]}
    before = data(call(lead, tool, args))
    full = before if tool == "mailbox_read_record" else before["records"][0]
    assert full["data"]["body"] == "parent body"
    assert full["data"]["refs"]["private"]["ref"] == leaf[:16]
    assert "refs_withheld" not in full
    index = root.parent / "mailbox-records" / (".grants-" + leaf)
    original_index = index.read_bytes()
    original_read, reads = codec_store.Store._read_bytes, []
    def read(self, reference, *values, **options):
        assert reference != leaf, "withholding opened an ungranted child's descriptor"
        reads.append(reference)
        return original_read(self, reference, *values, **options)
    with patch.object(codec_store.Store, "_read_bytes", read):
        result = data(call(reviewer, tool, args))
        view = result if tool == "mailbox_read_record" else result["records"][0]
        assert "outline" in view and "data" not in view and view["refs_withheld"] is True
        assert view["next_action"] == auth_error("cited_reference")["error"]["next_action"]
        assert reads.count(parent) == 1
        if tool == "mailbox_digest":
            assert {row["message_id"] for row in result["messages"]} == {"wrapper", "later"}
            assert result["records"][1]["data"]["body"] == "later body"
            assert "refs_withheld" not in result["records"][1]
        selected = data(call(reviewer, tool, dict(args, fields=["body"])))
        selected_view = selected if tool == "mailbox_read_record" else selected["records"][0]
        assert selected_view["data"]["body"] == "parent body" and "refs_withheld" not in selected_view
        assert data(call(reviewer, tool, dict(args, max_chars=10))) == codec.CodecError("E_LIMIT").as_dict()
    assert index.read_bytes() == original_index, "a read silently created a transitive grant"
    assert data(call(lead, tool, args)) == before


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
@pytest.mark.parametrize("fields", [["refs"], ["refs.private"]])
def test_r8_explicit_ungranted_refs_have_distinct_guidance(bound, monkeypatch, tool, fields):
    root, lead, reviewer, leaf, parent, _ = r8_delegated_chain(bound)
    original_read = codec_store.Store._read_bytes
    def read(self, reference, *values, **options):
        assert reference != leaf, "explicit refusal opened an ungranted child"
        return original_read(self, reference, *values, **options)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", read)
    args = {"ref": parent} if tool == "mailbox_read_record" else {"refs": [parent]}
    # refs.private is a selector for parent; do not apply it to the inbox wrapper.
    if tool == "mailbox_digest" and fields != ["refs"]:
        args["after_message_id"] = "later"
    assert data(call(reviewer, tool, dict(args, fields=fields))) == auth_error("cited_reference")


@pytest.mark.parametrize("options", [{"expand": ["private"]}, {"fields": ["body"], "expand": ["private"]}])
def test_r8_implicit_expanded_refs_use_the_marked_outline_fallback(bound, monkeypatch, options):
    root, lead, reviewer, leaf, parent, _ = r8_delegated_chain(bound)
    original_read = codec_store.Store._read_bytes
    def read(self, reference, *values, **kwargs):
        assert reference != leaf, "fallback expanded an ungranted child"
        return original_read(self, reference, *values, **kwargs)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", read)
    result = data(call(reviewer, "mailbox_read_record", dict(options, ref=parent)))
    assert "outline" in result and "data" not in result and result["refs_withheld"] is True
    assert result["next_action"] == auth_error("cited_reference")["error"]["next_action"]


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
def test_r8_fallback_does_not_hide_an_authorized_child_integrity_error(bound, tool):
    root, lead, reviewer, leaf, parent, _ = r8_delegated_chain(bound)
    (root.parent / "mailbox-records" / (leaf + ".json")).write_bytes(b"altered payload")
    args = {"ref": parent} if tool == "mailbox_read_record" else {"refs": [parent]}
    reviewer_result = data(call(reviewer, tool, args))
    view = reviewer_result if tool == "mailbox_read_record" else reviewer_result["records"][0]
    assert view["refs_withheld"] is True
    assert data(call(lead, tool, args)) == codec.CodecError("E_HASH").as_dict()


@pytest.mark.parametrize("tool", ["mailbox_read_record", "mailbox_digest"])
@pytest.mark.parametrize("options,code", [
    ({"expand": ["nosuch"]}, "E_REF"),
    ({"fields": ["not_a_field"], "expand": ["private"]}, "E_SELECTOR"),
    ({"fields": ["fields.nosuch"], "expand": ["private"]}, "E_SELECTOR"),
    ({"fields": ["not_a_field", "refs"]}, "E_SELECTOR"),
    ({"fields": ["refs", "fields.nosuch"]}, "E_SELECTOR"),
    ({"fields": ["refs.private.bad"]}, "E_SELECTOR"),
    ({"fields": ["unknown_field", "refs.private"]}, "E_SELECTOR"),
])
def test_r10_reference_request_is_validated_before_withholding(bound, monkeypatch, tool, options, code):
    root, lead, reviewer, leaf, parent, _ = r8_delegated_chain(bound)
    args = {"ref": parent} if tool == "mailbox_read_record" else {"refs": [parent], "after_message_id": "later"}
    lead_args = dict(args)
    if tool == "mailbox_digest":
        lead_args["after_message_id"] = "parent"
    expected = data(call(lead, tool, dict(lead_args, **options)))
    assert expected == codec.CodecError(code).as_dict()
    original_read, reads = codec_store.Store._read_bytes, []
    def read(self, reference, *values, **kwargs):
        assert reference != leaf, "malformed request opened a cited child's payload"
        reads.append(reference)
        return original_read(self, reference, *values, **kwargs)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", read)
    result = call(reviewer, tool, dict(args, **options))
    assert result["isError"] is True and data(result) == expected
    # Validation also precedes child reads for a caller who has the child grant.
    assert data(call(lead, tool, dict(lead_args, **options))) == expected
    fallback = data(call(reviewer, tool, args))
    view = fallback if tool == "mailbox_read_record" else fallback["records"][0]
    assert view["refs_withheld"] is True and "outline" in view and "data" not in view
    selected = data(call(reviewer, tool, dict(args, fields=["body"])))
    selected_view = selected if tool == "mailbox_read_record" else selected["records"][0]
    assert selected_view["data"]["body"] == "parent body"
    # Parent authorization still precedes record-specific request validation.
    outsider, before = connection(root, "a/lane/f2"), len(reads)
    answers = []
    for reference in (parent, "0" * 64):
        query = {"ref": reference} if tool == "mailbox_read_record" else {"refs": [reference]}
        answers.append(call(outsider, tool, dict(query, **options)))
    assert answers[0] == answers[1] and data(answers[0]) == auth_error("reference")
    assert len(reads) == before


def _mc4b_lead_views(parent):
    """Message-id read, digest inbox value view, and by-ref read of one record."""
    return (
        ("message-id", "mailbox_read_record", {"message_id": "parent"}),
        ("value", "mailbox_digest", {}),
        ("reference", "mailbox_read_record", {"ref": parent}),
    )


def _mc4b_reviewer_views(parent):
    return (
        ("mailbox_read_record", {"message_id": "wrapper"}),
        ("mailbox_digest", {}),
        ("mailbox_read_record", {"ref": parent}),
        ("mailbox_digest", {"refs": [parent]}),
    )


def _mc4b_count_reads(monkeypatch):
    original, reads, gate = codec_store.Store._read_bytes, [], Lock()

    def counted(self, reference, *values, **kwargs):
        with gate:
            reads.append(reference)
        return original(self, reference, *values, **kwargs)

    monkeypatch.setattr(codec_store.Store, "_read_bytes", counted)
    return reads


@pytest.mark.parametrize("case,options,code,tamper", [
    ("valid", {}, None, False),
    ("tampered", {}, "E_HASH", True),
    ("unknown", {"fields": ["not_a_field", "refs"]}, "E_SELECTOR", True),
    ("oversized", {"max_chars": 60001}, "E_LIMIT", True),
    ("unresolved", {"expand": ["nosuch"]}, "E_REF", True),
])
def test_mc4b_message_value_and_reference_views_share_request_refusals(bound, monkeypatch, case, options, code, tamper):
    """Record-specific options are refused before any cited child is opened."""
    # A real created_at can contain the oversized max_chars digits.
    if case == "valid":
        monkeypatch.setattr(mailbox_module, "timestamp", lambda: "2026-11-14T03:18:00.600010Z")
    root, lead, reviewer, leaf, parent, _other = r8_delegated_chain(bound)
    if tamper:
        (root.parent / "mailbox-records" / (leaf + ".json")).write_bytes(b"TAMPERED_CHILD")
    reads = _mc4b_count_reads(monkeypatch)
    expected = None if code is None else codec.CodecError(code).as_dict()
    views = {}
    for name, tool, args in _mc4b_lead_views(parent):
        before = len(reads)
        result = call(lead, tool, dict(args, **options))
        if expected is None:
            assert not result.get("isError"), result
            body = data(result)
            view = body["messages"][0]["record"] if name == "value" else body
            views[name] = view
            assert view["data"]["body"] == "parent body"
            assert view["data"]["meta"]["created_at"] == "2026-11-14T03:18:00.600010Z"
            assert leaf in reads[before:]
        else:
            refusal = data(result)
            assert result.get("isError") is True and refusal == expected
            if code == "E_LIMIT":
                assert list(options) == ["max_chars"]
                assert options["max_chars"] == records.MAX_CHARS + 1
                assert refusal["error"]["code"] == "E_LIMIT"
            text = result["content"][0]["text"]
            assert "TAMPERED_CHILD" not in text and "not_a_field" not in text and "nosuch" not in text
            if code == "E_HASH":
                assert leaf in reads[before:]
            else:
                assert leaf not in reads[before:]
            retry = call(lead, tool, dict(args, **options))
            assert retry.get("isError") is True and data(retry) == expected
            if code != "E_HASH":
                assert leaf not in reads
    if expected is None:
        assert views["value"] == views["message-id"]
        assert views["reference"]["data"] == views["message-id"]["data"]
        withheld = data(call(reviewer, "mailbox_read_record", {"ref": parent}))
        assert withheld["refs_withheld"] is True and "data" not in withheld and leaf in reads
        return
    if code == "E_HASH":
        before = len(reads)
        withheld = data(call(reviewer, "mailbox_read_record", {"ref": parent}))
        assert withheld["refs_withheld"] is True and "data" not in withheld
        assert leaf not in reads[before:]
        return
    for tool, args in _mc4b_reviewer_views(parent):
        result = call(reviewer, tool, dict(args, **options))
        assert result.get("isError") is True and data(result) == expected
        assert "TAMPERED_CHILD" not in result["content"][0]["text"]
    assert leaf not in reads


@pytest.mark.parametrize("options,code", [
    ({"expand": ["nosuch"]}, "E_REF"),
    ({"fields": ["not_a_field", "refs"]}, "E_SELECTOR"),
    ({"max_chars": 60001}, "E_LIMIT"),
])
def test_mc4b_concurrent_malformed_views_do_not_read_a_tampered_child(bound, monkeypatch, options, code):
    root, lead, reviewer, leaf, parent, _other = r8_delegated_chain(bound)
    (root.parent / "mailbox-records" / (leaf + ".json")).write_bytes(b"TAMPERED_CHILD")
    reads = _mc4b_count_reads(monkeypatch)
    expected = codec.CodecError(code).as_dict()
    workers = (
        (connection(root), "mailbox_read_record", {"message_id": "parent"}),
        (connection(root), "mailbox_digest", {}),
        (connection(root), "mailbox_read_record", {"ref": parent}),
        (connection(root, "a/lane/review"), "mailbox_read_record", {"ref": parent}),
        (connection(root, "a/lane/review"), "mailbox_read_record", {"message_id": "wrapper"}),
    )
    with ThreadPoolExecutor(max_workers=len(workers)) as pool:
        jobs = [pool.submit(call, who, tool, dict(args, **options)) for who, tool, args in workers]
        results = [job.result(timeout=10) for job in jobs]
    assert [data(result) for result in results] == [expected] * len(workers)
    assert all(result.get("isError") is True and "TAMPERED_CHILD" not in result["content"][0]["text"]
               for result in results)
    assert leaf not in reads
    assert data(call(connection(root), "mailbox_read_record", dict({"message_id": "parent"}, **options))) == expected
    assert leaf not in reads


# Captured from the pre-change renderer with timestamp 2026-11-14T00:00:00.000000Z
# and fields=["body"]. Rows 1/63/64/65 use a distinct body per message id so record
# ids differ. Hashes are of the raw tool text.
_PERF_STAMP = "2026-11-14T00:00:00.000000Z"
_PERF_DIGEST_SHA = {
    0: "5cfb4322fd01737292fab45aa9321fee2caf3b689dd11adaaeaf979c2dc091f4",
    1: "2f8ced25d43c3632630a3fc5436b5024c02d3d15f6fd97343a8260ad67b0d635",
    63: "3f156e7ef1865bd8de62b7bb7129100350fbe84afb5d015d1484f72eb3665c13",
    64: "2166ec53fd37a979a158cbfab2551ae2c427ee7c41954264db937c38984d1ea2",
    65: "e2b25ecf2b8590e10677d943518ed54d4680ac63d302f611835c1319a5201c16",
}
_PERF_REFS_SHA = "853edbd431fdd44f297846b2987f01a4abb4b69a262f9a0649d2d91340003b14"
_PERF_RETAINED_CEILING = 64 * 1024
_PERF_GRANT_FLOOR = 100 * 1024
_PERF_TRACE_DEPTH = 25
_PERF_SPANS = {}


def _perf_sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _perf_source_span(function):
    """3.9-safe filename and line range. co_lines() starts in 3.10."""
    code = function.__code__
    key = (code.co_filename, code.co_firstlineno)
    span = _PERF_SPANS.get(key)
    if span is None:
        lines, start = inspect.getsourcelines(function)
        span = (code.co_filename, start, start + len(lines) - 1)
        _PERF_SPANS[key] = span
    return span


def _perf_renderer(limit):
    from aegis_core.message_codec_format import escape_char, neutral_text
    return codec_views.Renderer(codec.require, escape_char, neutral_text, limit)


def _perf_count_renders(monkeypatch):
    renders = []
    real = codec_views.Renderer.render
    def counted(self, view, format):
        renders.append(format)
        return real(self, view, format)
    monkeypatch.setattr(codec_views.Renderer, "render", counted)
    return renders


def _perf_count_payloads(monkeypatch):
    reads = []
    real = codec_store.Store._read_bytes
    def counted(self, reference, rootfd, budget=None, expected_size=None):
        reads.append(reference)
        return real(self, reference, rootfd, budget, expected_size)
    monkeypatch.setattr(codec_store.Store, "_read_bytes", counted)
    return reads


@contextmanager
def _perf_trace_depth():
    """Trace at _PERF_TRACE_DEPTH, then restore a shallower session that was already on.

    start() ignores its argument when tracing is already active, and a 1-frame
    traceback never reaches _grant_entry. Stop and start again to raise the limit.
    """
    was_tracing = tracemalloc.is_tracing()
    previous_limit = tracemalloc.get_traceback_limit() if was_tracing else None
    restarted = not was_tracing or previous_limit < _PERF_TRACE_DEPTH
    if restarted and was_tracing:
        tracemalloc.stop()
    try:
        if restarted:
            tracemalloc.start(_PERF_TRACE_DEPTH)
        yield
    finally:
        if restarted:
            tracemalloc.stop()
            if was_tracing:
                tracemalloc.start(previous_limit)


def _perf_grant_traced():
    # format() never emits function names. A 1-frame traceback also omits
    # _grant_entry, several frames above the parser allocations. Refuse to
    # report zero when the session cannot see that caller frame.
    # Parser allocations count when that caller frame is on the traceback.
    # A record-body parse has no _grant_entry frame and stays out of the ceiling.
    assert tracemalloc.is_tracing(), "grant trace inactive"
    assert tracemalloc.get_traceback_limit() >= _PERF_TRACE_DEPTH, "grant trace depth"
    filename, start, end = _perf_source_span(records._grant_entry)
    total = 0
    for stat in tracemalloc.take_snapshot().statistics("traceback"):
        if any(frame.filename == filename and start <= frame.lineno <= end for frame in stat.traceback):
            total += stat.size
    return total


def _perf_retained(access):
    raw = 0
    for item in access.entries.values():
        if type(item) is tuple and len(item) == 2 and type(item[1]) is bytes:
            raw += len(item[1])
    return raw, _perf_grant_traced()


def _perf_assert_retained(raw, traced):
    assert raw == 0
    margin = traced - _PERF_RETAINED_CEILING
    assert traced <= _PERF_RETAINED_CEILING, "grant ceiling traced=%d ceiling=%d margin=%d" % (
        traced, _PERF_RETAINED_CEILING, margin)


def test_mc_records_perf_renderer_accounts_each_row_once():
    """Envelope, commas and array elements sum to one bounded render. No store required."""
    documents = []
    for count in (0, 1, 63, 64, 65):
        documents.append({"messages": [{"n": index, "body": "line\n\"%d" % index} for index in range(count)],
                          "next_after": None if count != 64 else "r63"})
    documents.append({"messages": [{"n": 0, "body": "a,b"}], "next_after": None,
                      "records": [{"n": 1}, {"body": "d\ne"}]})
    for value in documents:
        limit = 60000
        tool = _perf_renderer(limit)
        skeleton = {"messages": [], "next_after": value["next_after"]}
        if "records" in value:
            skeleton["records"] = []
        total = tool.json_size(skeleton, limit)
        for key in ("messages", "records"):
            if key not in value:
                continue
            populated = False
            for row in value[key]:
                total += tool.json_array_extra(row, populated, limit)
                populated = True
        rendered = _perf_renderer(limit).render(value, "json")
        assert total == len(rendered) == _perf_renderer(limit).json_size(value, limit)
        assert _perf_renderer(total).render(value, "json") == rendered
        with pytest.raises(codec.CodecError) as error:
            _perf_renderer(total - 1).render(value, "json")
        assert error.value.code == "E_LIMIT"


def _perf_request(identifier):
    return request(identifier, content=json.dumps({
        "fields": {}, "body": "# Evidence\nHOSTILE_MARKER\n" + identifier, "refs": {}}))


def test_mc_records_perf_digest_bytes_limits_and_render_count(bound, monkeypatch):
    """Real-store digests keep pre-change bytes and stop on the row that crosses the limit."""
    root, writer, reader = bound
    monkeypatch.setattr(mailbox_module, "timestamp", lambda: _PERF_STAMP)
    empty = call(reader, "mailbox_digest", {"limit": 100, "fields": ["body"]})
    assert not empty.get("isError")
    empty_text = empty["content"][0]["text"]
    assert _perf_sha(empty_text) == _PERF_DIGEST_SHA[0]
    assert data(call(reader, "mailbox_digest", {"limit": 100, "fields": ["body"], "max_chars": len(empty_text)})) == json.loads(empty_text)
    assert data(call(reader, "mailbox_digest", {"limit": 100, "fields": ["body"], "max_chars": len(empty_text) - 1})) == codec.CodecError("E_LIMIT").as_dict()
    identifiers = []
    for number in range(65):
        identifiers.append(data(call(writer, "mailbox_publish_record", _perf_request("r%02d" % number)))["id"])
    texts = {0: empty_text}
    for count in (1, 63, 64, 65):
        result = call(reader, "mailbox_digest", {"limit": count, "fields": ["body"]})
        assert not result.get("isError"), result["content"][0]["text"][:200]
        texts[count] = result["content"][0]["text"]
        assert _perf_sha(texts[count]) == _PERF_DIGEST_SHA[count]
        assert json.loads(texts[count])["messages"][0]["record"]["data"]["body"] == "# Evidence\nHOSTILE_MARKER\nr00"
    renders = _perf_count_renders(monkeypatch)
    counted = call(reader, "mailbox_digest", {"limit": 65, "fields": ["body"]})
    assert counted["content"][0]["text"] == texts[65]
    assert len(renders) == 65 + 1, len(renders)
    parsed = json.loads(texts[65])
    same_envelope = dict(parsed, messages=parsed["messages"][:-1])
    limit_64 = len(_perf_renderer(60000).render(same_envelope, "json"))
    exact = len(texts[65])
    assert data(call(reader, "mailbox_digest", {"limit": 65, "fields": ["body"], "max_chars": exact})) == parsed
    refused = call(reader, "mailbox_digest", {"limit": 65, "fields": ["body"], "max_chars": exact - 1})
    assert data(refused) == codec.CodecError("E_LIMIT").as_dict()
    assert "HOSTILE_MARKER" not in refused["content"][0]["text"]
    # One under the 64-row same-envelope size reads the crossing row and not the next one.
    reads = _perf_count_payloads(monkeypatch)
    early = call(reader, "mailbox_digest", {"limit": 65, "fields": ["body"], "max_chars": limit_64 - 1})
    assert data(early) == codec.CodecError("E_LIMIT").as_dict()
    assert identifiers[63] in reads and identifiers[64] not in reads
    reads.clear()
    boundary = call(reader, "mailbox_digest", {"limit": 65, "fields": ["body"], "max_chars": limit_64})
    assert data(boundary) == codec.CodecError("E_LIMIT").as_dict()
    assert identifiers[64] in reads
    retried = call(reader, "mailbox_digest", {"limit": 65, "fields": ["body"], "max_chars": exact})
    assert retried["content"][0]["text"] == texts[65]
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(call, connection(root, "a/lane/review"), "mailbox_digest",
                            {"limit": 65, "fields": ["body"]}) for _ in range(2)]
        concurrent = [job.result(timeout=30) for job in jobs]
    assert concurrent[0]["content"][0]["text"] == concurrent[1]["content"][0]["text"] == texts[65]
    invoke(root, "publish", message(recipient="a/lane/review", identifier="z-legacy",
                                    body="ordinary\u202etext\nline"))
    legacy_renders = _perf_count_renders(monkeypatch)
    legacy = call(reader, "mailbox_digest", {"after_message_id": "r64", "limit": 100, "fields": ["body"]})
    assert not legacy.get("isError"), legacy["content"][0]["text"][:200]
    legacy_text = legacy["content"][0]["text"]
    assert "\u202e" not in legacy_text and "\\n" in legacy_text and "\n" not in legacy_text
    assert json.loads(legacy_text)["messages"] == [{
        "message_id": "z-legacy", "from": "a/orchestrator", "type": "info", "untrusted": True,
        "body": "ordinary\u202etext\nline"}]
    assert len(legacy_renders) <= 1 + 1
    assert len(legacy_renders) == 1


def test_mc_records_perf_large_grant_read_bounds_retained_bytes(bound, monkeypatch):
    """A large grant authorizes the same view without retaining its original bytes."""
    root, writer, reader = bound
    monkeypatch.setattr(mailbox_module, "timestamp", lambda: _PERF_STAMP)
    published = data(call(writer, "mailbox_publish_record", request("r00")))
    rid = published["id"]
    small = call(reader, "mailbox_read_record", {"message_id": "r00", "fields": ["body"]})
    assert not small.get("isError")
    small_text = small["content"][0]["text"]
    refs = call(reader, "mailbox_digest", {"limit": 100, "fields": ["body"], "refs": [rid]})
    assert not refs.get("isError")
    assert _perf_sha(refs["content"][0]["text"]) == _PERF_REFS_SHA
    grant = root.parent / "mailbox-records" / (".grants-" + rid)
    envelope = codec.parse(grant.read_bytes())
    entry = envelope["fields"]["value"]
    scope = entry["grants"][0]["root"]
    entry["grants"] = list(entry["grants"]) + [
        {"root": scope, "endpoint": ("a/lane/pad-" + ("x" * 200) + "-%03d" % number)[:256]}
        for number in range(400)
    ]
    padded = codec.canonical(envelope)
    assert len(padded) > _PERF_GRANT_FLOOR
    grant.write_bytes(padded)
    with pytest.raises(AssertionError) as raw_probe:
        _perf_assert_retained(1, 0)
    assert "grant ceiling" not in str(raw_probe.value)
    samples = []
    phase = {"name": "allowed"}
    plant = {"on": True, "traced": 0}
    real_authorize = records._RecordAccess.authorize
    def sampling(self, reference, *args, **kwargs):
        # Measure after refusal frames unwind. An active traceback keeps the
        # grant locals alive, so a finally-block sample would count a temporary.
        failure = None
        result = None
        try:
            result = real_authorize(self, reference, *args, **kwargs)
        except Exception as error:
            failure = error.with_traceback(None)
        if plant["on"] and failure is None:
            retained, discarded = records._grant_entry(self.codec, self.store, reference)
            if type(retained) is dict:
                self.facts[reference] = {
                    "author": retained.get("author"), "kind": retained.get("kind"), "parsed": retained}
            retained = None
            discarded = None
        gc.collect()
        raw, traced = _perf_retained(self)
        if plant["on"]:
            plant["traced"] = traced
            _perf_assert_retained(raw, traced)
        else:
            samples.append((phase["name"], raw, traced))
        if failure is not None:
            raise failure
        return result
    monkeypatch.setattr(records._RecordAccess, "authorize", sampling)
    # Enter from a 1-frame session when nothing else is tracing, so the lift
    # below is what makes the planted grant visible.
    shallow_owned = False
    if not tracemalloc.is_tracing():
        tracemalloc.start(1)
        shallow_owned = True
    try:
        if shallow_owned:
            assert tracemalloc.get_traceback_limit() == 1
        with _perf_trace_depth():
            gc.collect()
            tracemalloc.clear_traces()
            with pytest.raises(AssertionError, match="grant ceiling traced=") as planted:
                call(reader, "mailbox_read_record", {"message_id": "r00", "fields": ["body"]})
            margin = plant["traced"] - _PERF_RETAINED_CEILING
            assert plant["traced"] > _PERF_GRANT_FLOOR
            assert ("grant ceiling traced=%d ceiling=%d margin=%d" % (
                plant["traced"], _PERF_RETAINED_CEILING, margin)) in str(planted.value)
            plant["on"] = False
            gc.collect()
            tracemalloc.clear_traces()
            again = call(reader, "mailbox_read_record", {"message_id": "r00", "fields": ["body"]})
            digested = call(reader, "mailbox_digest", {"limit": 100, "fields": ["body"]})
            assert again["content"][0]["text"] == small_text
            assert json.loads(digested["content"][0]["text"])["messages"][0]["record"] == json.loads(small_text)
            denied_entry = codec.parse(padded)
            denied_entry["fields"]["value"]["grants"] = [
                row for row in denied_entry["fields"]["value"]["grants"] if row["endpoint"] != "a/lane/review"
            ]
            grant.write_bytes(codec.canonical(denied_entry))
            phase["name"] = "denied"
            denied = call(reader, "mailbox_read_record", {"message_id": "r00", "fields": ["body"]})
            assert data(denied) == auth_error("reference")
            assert "HOSTILE_MARKER" not in denied["content"][0]["text"]
        if shallow_owned:
            assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 1
    finally:
        if shallow_owned and tracemalloc.is_tracing():
            tracemalloc.stop()
    assert any(name == "allowed" for name, _raw, _traced in samples)
    assert any(name == "denied" for name, _raw, _traced in samples)
    for _name, raw, traced in samples:
        _perf_assert_retained(raw, traced)
        assert plant["traced"] > traced * 10
    grant.write_bytes(padded)
    monkeypatch.setattr(records._RecordAccess, "authorize", real_authorize)
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(call, connection(root, "a/lane/review"), "mailbox_read_record",
                            {"message_id": "r00", "fields": ["body"]}) for _ in range(2)]
        concurrent = [job.result(timeout=20) for job in jobs]
    assert concurrent[0]["content"][0]["text"] == concurrent[1]["content"][0]["text"] == small_text


def test_mc_records_perf_pythontracemalloc_keeps_the_grant_ceiling(tmp_path):
    """PYTHONTRACEMALLOC=1 still raises the planted ceiling and passes the real read."""
    store = make_store(tmp_path)
    store.close()
    env = os.environ.copy()
    env["PYTHONTRACEMALLOC"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    root = Path(__file__).resolve().parents[2]
    child_base = tmp_path / "child"
    child_base.mkdir()
    completed = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/integration/test_hierarchy_mailbox_records.py::test_mc_records_perf_large_grant_read_bounds_retained_bytes",
         "-p", "no:cacheprovider", "--basetemp", str(child_base), "-q", "--tb=line"],
        cwd=str(root), env=env, capture_output=True, text=True, timeout=180, check=False)
    assert completed.returncode == 0, completed.stdout[-1500:] + completed.stderr[-1500:]
    assert "1 passed" in completed.stdout


def test_mc_records_perf_publish_rollback_restores_original_bytes(bound, monkeypatch):
    """A mid-publish link failure restores grant bytes, then a retry and a reader both succeed."""
    root, writer, reader = bound
    monkeypatch.setattr(mailbox_module, "timestamp", lambda: _PERF_STAMP)
    source = data(call(writer, "mailbox_publish_record", request("source")))
    unrelated_content = json.dumps({"fields": {}, "body": "# Evidence\nHOSTILE_MARKER\nunrelated", "refs": {}})
    unrelated = data(call(writer, "mailbox_publish_record", request("unrelated", content=unrelated_content)))
    directory = root.parent / "mailbox-records"
    source_grant = directory / (".grants-" + source["id"])
    unrelated_grant = directory / (".grants-" + unrelated["id"])
    original = source_grant.read_bytes()
    unrelated_bytes = unrelated_grant.read_bytes()
    real_link = os.link
    def linked(src, target, *args, **kwargs):
        if str(target).endswith(".md"):
            raise OSError(errno.EIO, "injected")
        return real_link(src, target, *args, **kwargs)
    monkeypatch.setattr(records, "os", SimpleNamespace(**{**vars(os), "link": linked}))
    content = json.dumps({"fields": {}, "body": "delegate", "refs": {"source": source["id"]}})
    # a/front-door has no direct grant, so a successful retry must add a via row.
    delegate = request("delegate", to="a/front-door", content=content)
    failed = call(writer, "mailbox_publish_record", delegate)
    assert data(failed) == codec.CodecError("E_AUTH").as_dict()
    assert "HOSTILE_MARKER" not in failed["content"][0]["text"]
    assert source_grant.read_bytes() == original
    assert unrelated_grant.read_bytes() == unrelated_bytes
    assert sorted(path.name for path in directory.glob(".grants-*")) == sorted(
        [".grants-" + source["id"], ".grants-" + unrelated["id"]])
    assert set(writer.checked_mailbox().messages()) == {"source", "unrelated"}
    monkeypatch.setattr(records, "os", os)
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [
            pool.submit(call, connection(root, "a/lane/review"), "mailbox_read_record",
                        {"message_id": name, "fields": ["body"]})
            for name in ("source", "unrelated")
        ]
        read_back = [job.result(timeout=20) for job in jobs]
    assert all(not result.get("isError") for result in read_back)
    assert source_grant.read_bytes() == original
    retried = data(call(writer, "mailbox_publish_record", delegate))
    assert retried == data(call(writer, "mailbox_publish_record", delegate))
    assert "id" in retried
    assert source_grant.read_bytes() != original
    assert unrelated_grant.read_bytes() == unrelated_bytes
    assert data(call(reader, "mailbox_read_record", {"message_id": "source", "fields": ["body"]}))["data"]["body"] == "# Evidence\nHOSTILE_MARKER"
