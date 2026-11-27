"""Read-only doctor through its public CLI and callable entry point."""
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools import hierarchy_mailbox as hm


HELPER = Path(__file__).resolve().parents[2] / "tools/hierarchy_mailbox_doctor.py"
INDEX_STATUS = {"status": "equal", "differences": []}


def doctor():
    return importlib.import_module("tools.hierarchy_mailbox_doctor")


def make_store(tmp_path):
    if not doctor().descriptor_reads_supported():
        pytest.skip("doctor reads require directory descriptors and O_NOFOLLOW")
    root = tmp_path / "mailbox"
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                "endpoints": {"a/front-door": {}, "a/orchestrator": {}, "a/root": {}},
                "counterparts": []}
    hm.initialize(root, manifest)
    box = hm.Mailbox(root)
    for endpoint in manifest["endpoints"]:
        box.bind({"endpoint": endpoint, "host": "host", "session": "writer" if endpoint == "a/orchestrator" else endpoint,
                  "expected_generation": 0})
    box.publish({"message_id": "seed", "from": "a/orchestrator", "to": "a/front-door",
                 "host": "host", "session": "writer", "binding_generation": 1,
                 "type": "info", "body": "Evidence only."})
    return root


@pytest.fixture
def store(tmp_path):
    return make_store(tmp_path)


def run_main(root, capsys, *args, code=0):
    actual = doctor().main([str(root), "--json", *args])
    captured = capsys.readouterr()
    assert actual == code, captured.out + captured.err
    assert captured.err == ""
    return json.loads(captured.out)


def snapshot(root):
    return {str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in root.rglob("*") if path.is_file()}


def test_healthy_cli_is_read_only(store, capsys):
    before = snapshot(store)
    report = run_main(store, capsys)
    assert report["schema"] == "aegis.hierarchy-mailbox-doctor/v1"
    assert report["healthy"] is True
    assert report["cap"] == {"count": 1, "limit": 10000, "headroom": 9999}
    assert report["issues"] == [] and report["lock"] == {"status": "absent"}
    assert report["index"] == INDEX_STATUS
    assert snapshot(store) == before
    result = subprocess.run([sys.executable, "-B", str(HELPER), str(store)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0 and not result.stderr
    assert "healthy" in result.stdout and "index: equal" in result.stdout
    assert snapshot(store) == before


def test_all_malformed_files_and_reply_failures_are_reported(store, capsys):
    folder = store / "a/front-door"
    source = next(folder.glob("*.md"))
    (folder / "broken.md").write_text("not a message", encoding="utf-8")
    (folder / "invalid.md").write_bytes(b"\xff")
    raw = source.read_text()
    header, body = raw[4:].split("\n---\n\n", 1)
    message = hm.strict_json(header)
    message.update(message_id="reply", in_reply_to="absent")
    (folder / "reply.md").write_bytes(b"---\n" + hm.encoded(message) + b"\n---\n\n" + body.encode())
    report = run_main(store, capsys, code=1)
    assert report["cap"]["count"] == 4
    malformed = {Path(issue["path"]).name for issue in report["issues"]
                 if issue["code"] == "MD_MESSAGE"}
    assert malformed == {"broken.md", "invalid.md", "reply.md"}


def test_duplicate_and_wrong_folder_use_pinned_validation(store, capsys):
    source = next((store / "a/front-door").glob("*.md"))
    (source.parent / "duplicate.md").write_bytes(source.read_bytes())
    (store / "a/root/wrong.md").write_bytes(source.read_bytes())
    report = run_main(store, capsys, code=1)
    codes = [issue["code"] for issue in report["issues"]]
    assert "MD_DUPLICATE" in codes and "MD_MESSAGE" in codes


@pytest.mark.parametrize("alive", [True, False])
def test_lock_and_pending_are_reported_without_takeover(store, capsys, monkeypatch, alive):
    module = doctor()
    pid = os.getpid()
    (store / ".write.lock").write_bytes(hm.encoded({"pid": pid, "created_at": hm.timestamp()}))
    (store / "a/front-door/.pending-orphan").write_bytes(b"partial")
    def kill(target, signal):
        assert (target, signal) == (pid, 0)
        if not alive:
            raise ProcessLookupError(errno.ESRCH, "gone")
    monkeypatch.setattr(module, "os", OSProxy(kill=kill))
    before = snapshot(store)
    report = run_main(store, capsys, code=1)
    assert report["lock"] == {"status": "alive" if alive else "dead", "pid": pid}
    assert {issue["code"] for issue in report["issues"]} >= {"MD_PENDING"}
    assert snapshot(store) == before
    assert module.main([str(store)]) == 1
    assert "pid " + str(pid) in capsys.readouterr().out


def checkpoint(root):
    brief = root.parent / "brief.md"
    brief.write_bytes(b"retained checkpoint\n")
    cp = {"outgoing_stopped": True,
          "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}],
          "sources": [], "lease_refs": [], "completed_checks": [],
          "pending_message_ids": [], "last_acknowledgment_ids": []}
    record = {"schema": "aegis.role-binding/v1", "endpoint": "a/orchestrator", "host": "host",
              "session": "successor", "generation": 2, "created_at": hm.timestamp(),
              "checkpoint": cp, "checkpoint_sha256": hm.digest(cp)}
    (root / "bindings/a/orchestrator/000002.json").write_bytes(hm.encoded(record))
    return brief


@pytest.mark.parametrize("damage", ["changed", "missing"])
def test_checkpoint_brief_drift(store, capsys, damage):
    brief = checkpoint(store)
    assert run_main(store, capsys)["healthy"]
    if damage == "changed":
        brief.write_bytes(b"changed bytes\n")
    else:
        brief.unlink()
    report = run_main(store, capsys, code=1)
    assert any(issue["code"] == "MD_BRIEF" and issue["path"] == "brief.md"
               for issue in report["issues"])


@pytest.mark.parametrize("raw", [b"{}", b'{"pid":true,"created_at":"bad"}', b"[" * 100])
def test_malformed_lock_is_a_problem(store, capsys, raw):
    (store / ".write.lock").write_bytes(raw)
    report = run_main(store, capsys, code=1)
    assert report["lock"] == {"status": "malformed"}
    assert any(issue["code"] == "MD_LOCK" for issue in report["issues"])


@pytest.mark.parametrize("limit", ["MAX_FILES", "MAX_TOTAL_BYTES", "MAX_FILE_BYTES"])
def test_limits_refuse_before_parsing(store, capsys, monkeypatch, limit):
    module = doctor()
    monkeypatch.setattr(module, limit, 1)
    def parse(_raw):
        pytest.fail("over-budget input reached JSON parsing")
    monkeypatch.setattr(module, "hm", SimpleNamespace(**{**vars(hm), "strict_json": parse}))
    report = run_main(store, capsys, code=2)
    assert report["error"]["code"] == "MD_LIMIT"


def test_cap_uses_all_message_files(store, capsys, monkeypatch):
    monkeypatch.setattr(doctor(), "MESSAGE_CAP", 1)
    report = run_main(store, capsys, code=1)
    assert report["cap"] == {"count": 1, "limit": 1, "headroom": 0}
    assert any(issue["code"] == "MD_CAP" for issue in report["issues"])


def test_unsupported_platform_has_fixed_refusal(tmp_path, monkeypatch, capsys):
    module = doctor()
    monkeypatch.setattr(module, "descriptor_reads_supported", lambda: False)
    report = run_main(tmp_path / "missing", capsys, code=2)
    assert report["error"]["code"] == "MD_PLATFORM"


@pytest.mark.parametrize("args", [[], ["relative"], ["--unknown-secret-value"]])
def test_usage_never_echoes_input(args, capsys):
    assert doctor().main(args) == 2
    captured = capsys.readouterr()
    assert "MD_USAGE" in captured.out and not captured.err
    assert "unknown-secret-value" not in captured.out


class OSProxy:
    def __init__(self, **overrides):
        self.overrides = overrides

    def __getattr__(self, name):
        return self.overrides.get(name, getattr(os, name))


def symlink_or_skip(source, target, directory=False):
    try:
        target.symlink_to(source, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")


def test_symlink_component_refuses(store, capsys):
    target = store / "a/front-door"
    moved = store / "a/old-front-door"
    target.rename(moved)
    symlink_or_skip(moved, target, directory=True)
    report = run_main(store, capsys, code=2)
    assert report["error"]["code"] == "MD_PATH"


def test_rename_swap_cannot_read_outside_bytes(store, capsys, monkeypatch):
    module = doctor()
    folder = store / "a/front-door"
    victim = next(folder.glob("*.md"))
    outside = store.parent / "outside"
    outside.mkdir()
    (outside / victim.name).write_bytes(b"DO NOT READ")
    real_open = os.open
    swapped = False
    def opened(path, flags, *args, **kwargs):
        nonlocal swapped
        if str(path) == "front-door" and not swapped:
            swapped = True
            folder.rename(store / "a/retained")
            symlink_or_skip(outside, folder, directory=True)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(module, "os", OSProxy(open=opened))
    report = run_main(store, capsys, code=2)
    assert swapped and report["error"]["code"] == "MD_PATH"


def test_display_canonicalizes_redacts_then_truncates(store, capsys):
    # Fullwidth characters and a format control must not bypass the shared secret table.
    token = "ｇｈｐ_" + "A" * 30
    path = store / "a/front-door" / ("x" * 180 + "-" + token + "\u200b.md")
    path.write_bytes(b"bad")
    report = run_main(store, capsys, code=1)
    field = next(issue["path"] for issue in report["issues"] if issue["code"] == "MD_MESSAGE")
    assert "A" * 10 not in field and "ｇ" not in field and "\u200b" not in field
    assert len(field) <= doctor().MAX_DISPLAY + 3


def test_descriptors_close_on_read_failure(store, capsys, monkeypatch):
    module = doctor()
    opened, closed = [], []
    real_open, real_close = os.open, os.close
    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def close_fd(fd):
        closed.append(fd)
        return real_close(fd)
    def read_fd(_fd, _count):
        raise OSError(errno.EIO, "private-input-must-not-be-echoed")
    monkeypatch.setattr(module, "os", OSProxy(open=open_fd, close=close_fd, read=read_fd))
    report = run_main(store, capsys, code=2)
    assert report["error"]["code"] == "MD_IO"
    assert sorted(opened) == sorted(closed)


def test_missing_input_and_invalid_manifest_have_fixed_refusals(store, capsys):
    assert run_main(store / "missing", capsys, code=2)["error"]["code"] == "MD_IO"
    (store / "manifest.json").write_bytes(b'{"secret-never-echoed":1}')
    report = run_main(store, capsys, code=2)
    assert report["error"]["code"] == "MD_DATA"
    assert "secret-never-echoed" not in json.dumps(report)


def test_large_root_argument_refuses_before_path_parsing(capsys):
    report = run_main("/" + "x" * (doctor().MAX_PATH_BYTES + 1), capsys, code=2)
    assert report["error"]["code"] == "MD_LIMIT"


def test_readiness_metadata_outside_root_is_not_a_pending_mailbox_file(store, capsys):
    # Stored readiness is metadata only; it must not contaminate pending discovery.
    folder = store / "a/front-door"
    source = next(folder.glob("*.md"))
    header, body = source.read_text()[4:].split("\n---\n\n", 1)
    original = hm.strict_json(header)
    dispatch = {**original, "message_id": "dispatch", "from": "a/orchestrator", "to": "a/root"}
    (store / "a/root" / source.name).write_bytes(b"---\n" + hm.encoded(dispatch) + b"\n---\n\n" + body.encode())
    source.unlink()
    worktree = store.parent / ".pending-worktree"
    worktree.mkdir()
    ack = {**original, "message_id": "ack", "from": "a/root", "to": "a/orchestrator",
           "type": "ack", "acknowledgment": "accepted", "in_reply_to": "dispatch",
           "readiness": {"worktree": str(worktree), "scan_workspace": str(worktree), "branch": "feature",
                         "base_revision": "a" * 40, "lease_ref": "refs/aegis/lanes/test", "lease_oid": "b" * 40,
                         "lease_expires_at": "2020-01-01T00:00:00Z", "owned_paths": ["test.py"],
                         "scan_evidence": "claim", "hook_evidence": "claim", "enforcement_tier": "advisory"}}
    (store / "a/orchestrator/ack.md").write_bytes(b"---\n" + hm.encoded(ack) + b"\n---\n\n" + body.encode())
    report = run_main(store, capsys)
    assert report["issues"] == []


def test_growth_between_preflight_and_read_refuses_before_parser(store, capsys, monkeypatch):
    module = doctor()
    real_open = os.open
    def opened(path, flags, *args, **kwargs):
        if str(path) == "manifest.json":
            (store / "manifest.json").write_bytes(b"x" * (module.MAX_FILE_BYTES + 1))
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(module, "os", OSProxy(open=opened))
    assert run_main(store, capsys, code=2)["error"]["code"] == "MD_LIMIT"


def test_root_rename_keeps_reads_on_the_pinned_identity(store, capsys, monkeypatch):
    module = doctor()
    real_open = os.open
    moved = store.parent / "retained-mailbox"
    outside = store.parent / "outside"
    outside.mkdir()
    swapped = False
    def opened(path, flags, *args, **kwargs):
        nonlocal swapped
        if str(path) == "manifest.json" and not swapped:
            swapped = True
            store.rename(moved)
            symlink_or_skip(outside, store, directory=True)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(module, "os", OSProxy(open=opened))
    report = run_main(store, capsys)
    assert swapped and report["cap"]["count"] == 1


def test_permission_denied_lock_probe_reports_unknown(store, capsys, monkeypatch):
    module = doctor()
    (store / ".write.lock").write_bytes(hm.encoded({"pid": os.getpid(), "created_at": hm.timestamp()}))
    def denied(_pid, _signal):
        raise PermissionError(errno.EPERM, "private detail")
    monkeypatch.setattr(module, "os", OSProxy(kill=denied))
    assert run_main(store, capsys, code=1)["lock"]["status"] == "unknown"


def test_index_divergence_is_reported_without_repair(store, capsys, monkeypatch):
    # Change the real OS input between the doctor's pinned snapshot and the
    # index's fresh reads. Both encodings are valid; neither reader is mocked.
    module = doctor()
    source = next((store / "a/front-door").glob("*.md"))
    original = source.read_bytes()
    changed = original.replace(b"Evidence only.", b"Changed evidence.")
    real_open = os.open
    opens = 0
    def opened(path, flags, *args, **kwargs):
        nonlocal opens
        if str(path) == source.name:
            opens += 1
            if opens == 2:
                source.write_bytes(changed)
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(module, "os", OSProxy(open=opened))
    report = run_main(store, capsys, code=1)
    assert report["index"]["status"] == "diverged"
    assert any(item["kind"] == "mailbox_index_divergence" for item in report["index"]["differences"])
    assert any(item["code"] == "MD_INDEX" for item in report["issues"])
    assert source.read_bytes() == changed


def test_index_fdopen_failure_closes_descriptors_and_is_not_hidden(store, capsys, monkeypatch):
    module = doctor()
    source = next((store / "a/front-door").glob("*.md"))
    changed = source.read_bytes().replace(b"Evidence only.", b"Changed evidence.")
    real_open, real_close = os.open, os.close
    opened, closed = [], []
    reads = 0
    transfers = 0
    def open_fd(path, flags, *args, **kwargs):
        nonlocal reads
        if str(path) == source.name:
            reads += 1
            if reads == 2:
                source.write_bytes(changed)
        fd = real_open(path, flags, *args, **kwargs)
        opened.append(fd)
        return fd
    def close_fd(fd):
        closed.append(fd)
        return real_close(fd)
    def fdopen(_fd, _mode):
        nonlocal transfers
        transfers += 1
        raise OSError(errno.EIO, "private fdopen failure")
    monkeypatch.setattr(module, "os", OSProxy(open=open_fd, close=close_fd, fdopen=fdopen))
    assert run_main(store, capsys, code=2)["error"]["code"] == "MD_IO"
    assert transfers and sorted(opened) == sorted(closed)


def test_missing_stored_brief_metadata_keeps_pinned_stored_semantics(store, capsys):
    # Stored messages carry an inert brief reference; checkpoints verify its bytes.
    source = next((store / "a/front-door").glob("*.md"))
    header, body = source.read_text()[4:].split("\n---\n\n", 1)
    message = hm.strict_json(header)
    message["brief"] = {"path": str(store.parent / "absent.md"), "sha256": "a" * 64}
    source.write_bytes(b"---\n" + hm.encoded(message) + b"\n---\n\n" + body.encode())
    assert hm.Mailbox(store).messages()
    assert run_main(store, capsys)["index"] == INDEX_STATUS


@pytest.mark.parametrize("malformed", [False, True], ids=["healthy", "one-malformed"])
def test_multifolder_diagnostic_work_has_linear_counts(store, capsys, monkeypatch, malformed):
    module = doctor()
    manifest = hm.strict_json((store / "manifest.json").read_text())
    for hierarchy in ("b", "c", "d"):
        for role in ("front-door", "orchestrator", "root"):
            manifest["endpoints"][hierarchy + "/" + role] = {}
            (store / hierarchy / role).mkdir(parents=True)
    (store / "manifest.json").write_bytes(hm.encoded(manifest))
    seed = next((store / "a/front-door").glob("*.md"))
    header, body = seed.read_text()[4:].split("\n---\n\n", 1)
    template = hm.strict_json(header)
    for endpoint in manifest["endpoints"]:
        hierarchy, role = endpoint.split("/")
        sender = hierarchy + ("/front-door" if role == "orchestrator" else "/orchestrator")
        for number in range(8):
            identifier = endpoint.replace("/", "-") + "-" + str(number)
            message = {**template, "message_id": identifier, "from": sender, "to": endpoint}
            (store / endpoint / (identifier + ".md")).write_bytes(
                b"---\n" + hm.encoded(message) + b"\n---\n\n" + body.encode())
    broken = store / "d/root/zz-bad.md"
    if malformed:
        broken.write_bytes(b"not a message")
    folders = {store / endpoint for endpoint in manifest["endpoints"]}
    folders |= {store / "across" / role for role in hm.ACROSS_ROLES}
    entries = sum(len(list(folder.iterdir())) for folder in folders)
    counts = {"folder_checks": 0, "listings": 0, "parses": 0}
    diagnostic = {}
    real_encode, real_scandir, real_parse = os.fsencode, os.scandir, hm.strict_json
    real_index_module = module.index_module
    def fsencode(value):
        # Every descriptor probe/listing path passes the lexical filesystem
        # encoder, even when its metadata or listing is already cached.
        if Path(value) in folders:
            counts["folder_checks"] += 1
        return real_encode(value)
    def scandir(*args, **kwargs):
        counts["listings"] += 1
        return real_scandir(*args, **kwargs)
    def parse(raw):
        if '"aegis.mailbox/v1"' in raw:
            counts["parses"] += 1
        return real_parse(raw)
    def index(box, **kwargs):
        assert kwargs == {"mode": "shadow"}
        diagnostic.update(counts)  # Exclude the separate shadow comparison.
        return real_index_module.MailboxIndex(box, **kwargs)
    monkeypatch.setattr(module, "os", OSProxy(fsencode=fsencode, scandir=scandir))
    monkeypatch.setattr(module, "hm", SimpleNamespace(**{**vars(hm), "strict_json": parse}))
    monkeypatch.setattr(module, "index_module", SimpleNamespace(**{**vars(real_index_module), "MailboxIndex": index}))
    report = run_main(store, capsys, code=1 if malformed else 0)
    assert report["cap"]["count"] == entries
    assert diagnostic["folder_checks"] <= 6 * entries + 10 * len(folders), diagnostic
    assert diagnostic["listings"] <= 2 * len(folders), diagnostic
    assert diagnostic["parses"] <= (3 if malformed else 1) * entries, diagnostic
    if malformed:
        assert any(issue["code"] == "MD_MESSAGE" and issue["path"].endswith("zz-bad.md")
                   for issue in report["issues"])
    else:
        assert diagnostic["parses"] == entries


@pytest.mark.parametrize("control", ["\n", "\t", "\r", "\x07", "\x80"], ids=["LF", "TAB", "CR", "C0", "C1"])
@pytest.mark.parametrize("sink", ["issue", "mailbox"])
@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_control_before_token_is_redacted_in_every_sink(store, capsys, control, sink, as_json):
    module = doctor()
    token = "ghp_" + "A" * 30
    label = "x" + control + token
    if sink == "issue":
        (store / "a/front-door" / (label + ".md")).write_bytes(b"bad")
    else:
        target = store.parent / label
        store.rename(target)
        store = target
    assert module.main([str(store), *(["--json"] if as_json else [])]) == (1 if sink == "issue" else 0)
    captured = capsys.readouterr()
    assert not captured.err
    assert token not in captured.out and "A" * 30 not in captured.out
    if as_json:
        report = json.loads(captured.out)
        value = (next(issue["path"] for issue in report["issues"] if issue["code"] == "MD_MESSAGE")
                 if sink == "issue" else report["mailbox"])
    else:
        value = captured.out
    assert "REDACTED" in value
