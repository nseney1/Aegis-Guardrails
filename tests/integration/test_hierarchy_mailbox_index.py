"""Public mailbox/index equivalence, corruption, and filesystem boundary controls."""
import hashlib
import errno
import importlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import pytest

from tools import hierarchy_mailbox as hm


POSIX = pytest.mark.skipif(os.name != "posix", reason="POSIX filesystem semantics")
NUMBER_LITERALS = [pytest.param(value, id=name) for value, name in
                   [("1e999", "positive_overflow"), ("-1e999", "negative_overflow"),
                    ("NaN", "nan"), ("Infinity", "infinity"), ("-Infinity", "negative_infinity")]]
if hasattr(sys, "get_int_max_str_digits") and 0 < sys.get_int_max_str_digits() < 5000:
    NUMBER_LITERALS.append(pytest.param("9" * 5000, id="huge_int"))


def index_module():
    return importlib.import_module("tools.hierarchy_mailbox_index")


def symlink_or_skip(link, target):
    try:
        os.symlink(str(target), str(link), target_is_directory=Path(target).is_dir())
    except (OSError, NotImplementedError) as exc:
        pytest.skip("symlinks unavailable here: %s" % exc)


def key_order(value):
    if isinstance(value, dict):
        return [(key, key_order(item)) for key, item in value.items()]
    if isinstance(value, list):
        return [key_order(item) for item in value]
    return None


def stub_messages(monkeypatch, index, value):
    injected = []

    def replacement():
        injected.append(True)
        return value

    monkeypatch.setattr(index, "messages", replacement)
    return injected


def request(identifier, sender="a/orchestrator", recipient="a/lane/review", **extra):
    return {"message_id": identifier, "from": sender, "to": recipient,
            "host": "test-host", "session": sender, "binding_generation": 1,
            "type": "info", "body": "original body", **extra}


@pytest.fixture
def mailbox(tmp_path):
    root = tmp_path / "mailbox"
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                "endpoints": {"a/front-door": {}, "a/orchestrator": {}, "a/root": {},
                              "a/lane/review": {"kind": "reviewer"}}, "counterparts": []}
    hm.initialize(root, manifest)
    box = hm.Mailbox(root)
    for endpoint in manifest["endpoints"]:
        box.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                  "expected_generation": 0})
    box.publish(request("seed"))
    return box


def snapshot(root):
    return {str(p.relative_to(root)): ("directory" if p.is_dir() else
            hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(root.rglob("*"))}


def caught(call):
    try:
        call()
    except Exception as exc:
        return type(exc), str(exc)
    pytest.fail("expected a fail-closed exception")


def rewrite(path, message):
    header = {k: v for k, v in message.items() if k != "body"}
    path.write_bytes(b"---\n" + hm.encoded(header) + b"\n---\n\n" + message["body"].encode())


DEFECTS = ["missing_header", "bad_json", "duplicate_key", "nonfinite", "utf8", "unknown_field",
           "wrong_folder", "duplicate_id", "missing_reply", "reverse_reply", "non_md", "symlink",
           "pending_symlink", "directory_entry", "oversized_message", "missing_folder", "folder_symlink"]


def inject(box, defect):
    seed = box.messages()["seed"]
    original = Path(seed["path"])
    path = original.parent / "zz-bad.md"
    msg = {**seed["message"], "message_id": "bad"}
    raw = {"missing_header": b"hello", "bad_json": b"---\n{\n---\n\nbody",
           "duplicate_key": b'---\n{"x":1,"x":2}\n---\n\nbody',
           "nonfinite": b'---\n{"x":NaN}\n---\n\nbody', "utf8": b"\xff",
           "oversized_message": b"x" * (hm.MAX_BYTES + 1)}
    if defect in raw:
        path.write_bytes(raw[defect])
    elif defect == "unknown_field":
        rewrite(path, {**msg, "surprise": True})
    elif defect == "wrong_folder":
        rewrite(box.root / "a/orchestrator/zz-bad.md", msg)
    elif defect == "duplicate_id":
        path.write_bytes(original.read_bytes())
    elif defect == "missing_reply":
        rewrite(path, {**msg, "in_reply_to": "absent"})
    elif defect == "reverse_reply":
        rewrite(path, {**msg, "in_reply_to": "seed"})
    elif defect == "non_md":
        path.with_suffix(".txt").write_text("unexpected")
    elif defect in {"symlink", "pending_symlink"}:
        target = path if defect == "symlink" else path.parent / ".pending-bad"
        symlink_or_skip(target, original)
    elif defect == "directory_entry":
        path.mkdir()
    elif defect in {"missing_folder", "folder_symlink"}:
        folder = box.root / "across/front-door"
        folder.rmdir()
        if defect == "folder_symlink":
            symlink_or_skip(folder, original.parent)


@pytest.mark.parametrize("defect", DEFECTS)
@pytest.mark.parametrize("warm", [False, True])
def test_errors_equal_pinned_scan(mailbox, defect, warm):
    cls = index_module().MailboxIndex
    if warm:
        cls(mailbox).messages()
    inject(mailbox, defect)
    expected = caught(mailbox.messages)
    assert caught(lambda: cls(mailbox).messages()) == expected


@pytest.mark.parametrize("warm", [False, True])
def test_record_limit_on_every_read(mailbox, monkeypatch, warm):
    cls = index_module().MailboxIndex
    if warm:
        cls(mailbox).messages()
    monkeypatch.setattr(hm, "MAX_RECORDS", 1)
    # Publish the new record before lowering the scan limit below the count.
    record = mailbox.messages()["seed"]
    rewrite(Path(record["path"]).parent / "zz-extra.md", {**record["message"], "message_id": "extra"})
    assert caught(lambda: cls(mailbox).messages()) == caught(mailbox.messages)


POISONS = ["truncated", "invalid_json", "duplicate_key", "nonfinite", "schema", "manifest_sha256",
           "source_sha256", "oversized", "non_ascii_key", "odd_entry",
           "unknown_key", "traversal", "invalid_stat", "invalid_validity"]


@pytest.mark.parametrize("poison", POISONS)
def test_poisoned_cache_never_changes_result(mailbox, poison, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = mailbox.messages()
    assert index.messages() == expected
    data = json.loads(index.cache_path.read_bytes())
    entry = next(iter(data["entries"].values()))
    if poison == "truncated":
        raw = b'{"schema":'
    elif poison == "invalid_json":
        raw = b"not JSON"
    elif poison == "duplicate_key":
        raw = b'{"schema":1,"schema":2}'
    elif poison == "nonfinite":
        raw = b'{"schema":NaN}'
    elif poison == "oversized":
        monkeypatch.setattr(module, "MAX_CACHE_BYTES", 4096)
        raw = b" " * (module.MAX_CACHE_BYTES + 1)
    else:
        if poison in {"schema", "manifest_sha256", "source_sha256"}:
            data[poison] = "wrong"
        elif poison == "non_ascii_key":
            data["\u0435ntries"] = {}
        elif poison == "odd_entry":
            data["entries"] = []
        elif poison == "unknown_key":
            entry["surprise"] = True
        elif poison == "traversal":
            data["entries"]["../escape.md"] = data["entries"].pop(next(iter(data["entries"])))
        elif poison == "invalid_stat":
            entry["key"][0] = True
        elif poison == "invalid_validity":
            entry["valid"] = "true"
        raw = hm.encoded(data)
    index.cache_path.write_bytes(raw)
    before = snapshot(mailbox.root)
    assert index.messages() == expected
    assert module.MailboxIndex(mailbox).messages() == expected
    assert snapshot(mailbox.root) == before


@pytest.mark.parametrize("forge_sha", [False, True])
@pytest.mark.parametrize("invalid", [False, True])
def test_valid_cache_forgery_detected_by_shadow_and_verify(mailbox, forge_sha, invalid):
    """Same-user cache authenticity is outside Track U; the oracle detects it."""
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    data = hm.strict_json(index.cache_path.read_text())
    entry = next(iter(data["entries"].values()))
    original_sha = entry["sha256"]
    entry["message"]["body"] = "attacker body"
    if invalid:
        entry["message"]["type"] = "invalid-type"
    if forge_sha:
        header = {k: v for k, v in entry["message"].items() if k != "body"}
        entry["sha256"] = hashlib.sha256(b"---\n" + hm.encoded(header) + b"\n---\n\nattacker body").hexdigest()
    index.cache_path.write_bytes(hm.encoded(data))
    assert index.messages() != expected
    assert module.compare(mailbox, index)
    differences = index.verify()
    assert differences
    if forge_sha:
        assert any(item["kind"] == "content_changed" and item["new_sha256"] == original_sha
                   for item in differences)
    else:
        assert any(item["kind"] == "cache_header_changed" for item in differences)
    assert index.messages() == expected
    assert module.compare(mailbox, index) == []


def test_cross_process_reuses_cache(mailbox):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    mailbox.publish(request("new-note"))
    script = '''import json,sys
from tools import hierarchy_mailbox as hm
from tools.hierarchy_mailbox_index import MailboxIndex
reads=[]
real=MailboxIndex._read_message
def spy(self,path):
    reads.append(str(path))
    return real(self,path)
MailboxIndex._read_message=spy
result=MailboxIndex(hm.Mailbox(sys.argv[1])).messages()
print(json.dumps({"result":result,"reads":reads}))
'''
    result = subprocess.run([sys.executable, "-B", "-c", script, str(mailbox.root)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    observed = hm.strict_json(result.stdout)
    assert observed["result"] == mailbox.messages()
    assert len(observed["reads"]) == 1
    assert len(observed["result"]) == len(expected) + 1


@pytest.mark.parametrize("unsafe", ["directory_symlink", "file_symlink", "directory_writable",
                                         "file_writable", "directory_owner", "file_owner"])
@pytest.mark.parametrize("same_instance", [False, True])
@POSIX
def test_unsafe_cache_refused(mailbox, tmp_path, monkeypatch, unsafe, same_instance):
    module = index_module()
    directory = tmp_path / "cache"
    index = module.MailboxIndex(mailbox, directory)
    index.messages()
    if unsafe == "directory_symlink":
        moved = tmp_path / "moved"
        directory.rename(moved)
        symlink_or_skip(directory, moved)
    elif unsafe == "file_symlink":
        target = tmp_path / "target.json"
        index.cache_path.rename(target)
        symlink_or_skip(index.cache_path, target)
    elif unsafe.endswith("writable"):
        (directory if unsafe.startswith("directory") else index.cache_path).chmod(0o770)
    else:
        real_fstat, real_stat, real_lstat = os.fstat, os.stat, Path.lstat
        target = directory if unsafe.startswith("directory") else index.cache_path
        inode = target.stat().st_ino
        injected = []

        def foreign_uid(descriptor):
            value = real_fstat(descriptor)
            if value.st_ino == inode:
                injected.append("fstat")
                fields = list(value)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return value

        monkeypatch.setattr(os, "fstat", foreign_uid)

        def foreign_stat(*args, **kwargs):
            value = real_stat(*args, **kwargs)
            if value.st_ino == inode:
                injected.append("stat")
                fields = list(value)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return value

        monkeypatch.setattr(os, "stat", foreign_stat)

        def foreign_lstat(path, *args, **kwargs):
            value = real_lstat(path, *args, **kwargs)
            if value.st_ino == inode:
                injected.append("Path.lstat")
                fields = list(value)
                fields[4] = os.getuid() + 1
                return os.stat_result(fields)
            return value

        monkeypatch.setattr(Path, "lstat", foreign_lstat)
    before = snapshot(mailbox.root)
    error_type, error = caught(lambda: (index if same_instance else
                                      module.MailboxIndex(mailbox, directory)).messages())
    assert issubclass(error_type, ValueError)
    assert any(word in error for word in ("symlink", "owner", "owned", "writable"))
    assert "private directory" in error
    if unsafe.endswith("owner"):
        assert injected
    assert snapshot(mailbox.root) == before


@pytest.mark.parametrize("where", ["inside", "equal", "ancestor"])
def test_overlapping_directory_refused(mailbox, where):
    cls = index_module().MailboxIndex
    directory = {"inside": mailbox.root / "cache", "equal": mailbox.root,
                 "ancestor": mailbox.root.parent}[where]
    before = snapshot(mailbox.root)
    assert issubclass(caught(lambda: cls(mailbox, directory).messages())[0], ValueError)
    assert snapshot(mailbox.root) == before


def test_warm_open_parses_only_one_new_file(mailbox, monkeypatch):
    module = index_module()
    for i in range(12):
        mailbox.publish(request("note-%02d" % i))
    index = module.MailboxIndex(mailbox)
    before = snapshot(mailbox.root)
    assert index.messages() == mailbox.messages()
    assert snapshot(mailbox.root) == before
    real_read = module.MailboxIndex._read_message
    reads = []

    def spy(self, path):
        reads.append(path)
        return real_read(self, path)

    monkeypatch.setattr(module.MailboxIndex, "_read_message", spy)
    # A new instance exercises the persisted cache as well as same-instance reads.
    mailbox.publish(request("new-note"))
    newer = module.MailboxIndex(mailbox)
    assert newer.messages() == mailbox.messages()
    assert len(reads) == 1
    reads.clear()
    assert newer.get("seed") == mailbox.messages()["seed"]
    assert newer.get("absent") is None
    assert not reads
    if os.name == "posix":
        assert stat.S_IMODE(newer.directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(newer.cache_path.stat().st_mode) == 0o600


@pytest.mark.parametrize("verify_first", [pytest.param(False, marks=POSIX), True])
def test_preserved_mtime_content_change(mailbox, monkeypatch, verify_first):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    record = index.messages()["seed"]
    path = Path(record["path"])
    old_raw, old_stat = path.read_bytes(), path.stat()
    new_raw = old_raw.replace(b"original body", b"modified body")
    path.write_bytes(new_raw)
    os.utime(path, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
    expected = [{"path": str(path), "old_sha256": hashlib.sha256(old_raw).hexdigest(),
                 "new_sha256": hashlib.sha256(new_raw).hexdigest(), "kind": "content_changed"}]
    if verify_first:
        # Even a stale stat-key observer cannot bypass the explicit rehash hook.
        injected = []

        def unchanged(value):
            injected.append(True)
            return module.MailboxIndex._key(old_stat)

        monkeypatch.setattr(index, "_key", unchanged)
        assert index.verify() == expected
        assert injected
    else:
        assert path.stat().st_ctime_ns != old_stat.st_ctime_ns
        assert index.messages() == mailbox.messages()
        assert index.content_changed == expected
    assert index.verify() == []


def test_r3_cached_brief_path_requires_shadow_or_verify(mailbox, tmp_path):
    module = index_module()
    brief_dir = tmp_path / "briefs"
    brief_dir.mkdir()
    brief_path = brief_dir / "task.md"
    brief_path.write_text("Review the task.\n")
    brief = {"path": str(brief_path), "sha256": hashlib.sha256(brief_path.read_bytes()).hexdigest()}
    mailbox.publish(request("dispatch", type="dispatch", brief=brief))
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    moved = tmp_path / "old-briefs"
    brief_dir.rename(moved)
    symlink_or_skip(brief_dir, moved)
    assert index.messages() == expected
    assert module.compare(mailbox, index)
    assert caught(index.verify) == caught(mailbox.messages)


def test_shadow_equivalence_and_divergence(mailbox, tmp_path, monkeypatch):
    module = index_module()
    brief_path = tmp_path / "task.md"
    brief_path.write_text("Review and report.\n")
    brief = {"path": str(brief_path), "sha256": hashlib.sha256(brief_path.read_bytes()).hexdigest()}
    mailbox.publish(request("dispatch", type="dispatch", brief=brief))
    mailbox.publish(request("ack", "a/lane/review", "a/orchestrator", type="ack",
                            acknowledgment="received", in_reply_to="dispatch"))
    mailbox.publish(request("job", recipient="a/root", type="job_request", brief=brief))
    mailbox.publish(request("receipt", "a/root", "a/orchestrator", type="job_receipt",
                            in_reply_to="job", receipt={"state": "started"}))
    index = module.MailboxIndex(mailbox)
    before = snapshot(mailbox.root)
    actual = index.messages()
    assert list(actual) == list(mailbox.messages())
    assert hm.encoded(actual) == hm.encoded(mailbox.messages())
    assert module.compare(mailbox, index) == []
    injected = stub_messages(monkeypatch, index, {})
    differences = module.compare(mailbox, index)
    assert injected == [True]
    assert differences
    log = index.directory / "divergence.jsonl"
    assert len(log.read_text().splitlines()) == 1
    assert hm.strict_json(log.read_text())["differences"] == differences
    assert snapshot(mailbox.root) == before


def test_atomic_write_failure_keeps_previous_cache(mailbox, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    index.messages()
    previous = index.cache_path.read_bytes()
    mailbox.publish(request("later"))

    injected = []

    def crash(*args, **kwargs):
        injected.append(True)
        raise OSError("injected replace failure")

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "replace", crash)
        with pytest.warns(RuntimeWarning, match="mailbox cache write failed"):
            assert index.messages() == mailbox.messages()
        assert "injected replace failure" in index.last_write_error
    assert injected
    assert index.cache_path.read_bytes() == previous
    assert sorted(p.name for p in index.directory.iterdir()) == [index.cache_path.name]
    assert module.MailboxIndex(mailbox).messages() == mailbox.messages()


def test_pending_file_ignored_and_mailbox_untouched(mailbox):
    module = index_module()
    (mailbox.root / "a/lane/.pending-orphan").write_bytes(b"partial")
    before = snapshot(mailbox.root)
    index = module.MailboxIndex(mailbox)
    assert index.messages() == mailbox.messages()
    assert index.verify() == []
    assert module.compare(mailbox, index) == []
    assert snapshot(mailbox.root) == before


def test_validation_cost_measurement(mailbox, tmp_path, record_property):
    module = index_module()
    brief_path = tmp_path / "measure.md"
    brief_path.write_text("Measurement brief.\n")
    brief = {"path": str(brief_path), "sha256": hashlib.sha256(brief_path.read_bytes()).hexdigest()}
    for i in range(60):
        mailbox.publish(request("measure-%02d" % i, brief=brief))
    index = module.MailboxIndex(mailbox)
    records = index.messages()
    start = time.perf_counter()
    for _ in range(3):
        for record in records.values():
            mailbox.validate_message(record["message"], stored=True)
    validation = (time.perf_counter() - start) / 3
    start = time.perf_counter()
    for _ in range(3):
        assert mailbox.messages() == records
    full = (time.perf_counter() - start) / 3
    start = time.perf_counter()
    for _ in range(3):
        assert index.messages() == records
    warm = (time.perf_counter() - start) / 3
    measurement = {"records": len(records), "validation_seconds": validation,
                   "full_scan_seconds": full, "warm_seconds": warm, "validation_fraction": validation / full}
    record_property("mailbox_index_cost", json.dumps(measurement))
    print("MB1_COST " + json.dumps(measurement))


@pytest.mark.parametrize("api", ["get", "messages"])
def test_r3_optimization_counted_operations(mailbox, monkeypatch, api, record_property):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    counts = {"reads": 0, "validations": 0, "source_reads": 0, "parses": 0, "manifest_digests": 0}
    real_read, real_validate = hm.read_bytes, mailbox.validate_message
    real_source, real_parse, real_digest = Path.read_bytes, hm.strict_json, hm.digest

    def read(path):
        if mailbox.root in Path(path).parents:
            counts["reads"] += 1
        return real_read(path)

    def validate(*args, **kwargs):
        counts["validations"] += 1
        return real_validate(*args, **kwargs)

    def source(path):
        if path == Path(hm.__file__):
            counts["source_reads"] += 1
        return real_source(path)

    def parse(raw):
        counts["parses"] += 1
        return real_parse(raw)

    def digest(value):
        if value is mailbox.manifest:
            counts["manifest_digests"] += 1
        return real_digest(value)

    monkeypatch.setattr(hm, "read_bytes", read)
    monkeypatch.setattr(mailbox, "validate_message", validate)
    monkeypatch.setattr(Path, "read_bytes", source)
    monkeypatch.setattr(hm, "strict_json", parse)
    monkeypatch.setattr(hm, "digest", digest)
    call = (lambda: index.get("seed")) if api == "get" else index.messages
    actual = call()
    assert actual == (expected["seed"] if api == "get" else expected)
    assert counts == dict.fromkeys(counts, 0)
    mailbox.publish(request("one-more"))
    counts.update(dict.fromkeys(counts, 0))
    call()
    assert counts == {"reads": 1, "validations": 1, "source_reads": 0, "parses": 1, "manifest_digests": 0}
    counts.update(dict.fromkeys(counts, 0))
    call()
    assert counts == dict.fromkeys(counts, 0)
    counts.update(dict.fromkeys(counts, 0))
    module.MailboxIndex(mailbox).get("seed")
    assert counts == {"reads": 0, "validations": 0, "source_reads": 1, "parses": 1, "manifest_digests": 1}
    record_property("counted_operations_" + api, "warm=0; publish=1 read,1 validation,1 parse; source=0")


@pytest.mark.parametrize("api", ["get", "messages"])
def test_r3_caller_cannot_mutate_index_state(mailbox, api):
    index = index_module().MailboxIndex(mailbox)
    expected = mailbox.messages()["seed"]
    actual = index.get("seed") if api == "get" else index.messages()["seed"]
    actual["message"]["body"] = "changed by caller"
    actual["message"]["verification"]["lease"] = "changed by caller"
    assert index.get("seed") == expected


@pytest.mark.parametrize("opening", ["cold", "same", "fresh"])
def test_r3_recursive_key_order_preserved(mailbox, opening):
    module = index_module()
    seed = mailbox.messages()["seed"]
    header = {key: value for key, value in reversed(list(seed["message"].items())) if key != "body"}
    header["verification"] = dict(reversed(list(header["verification"].items())))
    Path(seed["path"]).write_bytes(b"---\n" + json.dumps(header).encode() + b"\n---\n\noriginal body")
    expected = mailbox.messages()
    index = module.MailboxIndex(mailbox)
    if opening != "cold":
        index.messages()
    if opening == "fresh":
        index = module.MailboxIndex(mailbox)
    actual = index.messages()
    assert actual == expected
    assert key_order(actual) == key_order(expected)


def test_r3_compare_detects_order_only_difference(mailbox, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    actual = index.messages()
    actual["seed"]["message"] = dict(reversed(list(actual["seed"]["message"].items())))
    injected = stub_messages(monkeypatch, index, actual)
    assert hm.encoded(actual) == hm.encoded(mailbox.messages())
    assert module.compare(mailbox, index)
    assert injected == [True]
    assert len((index.directory / "divergence.jsonl").read_text().splitlines()) == 1


@pytest.mark.parametrize("literal", NUMBER_LITERALS)
@pytest.mark.parametrize("api", ["messages", "verify"])
def test_r3_unencodable_cache_is_discarded(mailbox, literal, api):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    data = json.loads(index.cache_path.read_bytes())
    next(iter(data["entries"].values()))["message"]["body"] = "NUMBER"
    raw = json.dumps(data).replace('"NUMBER"', literal).encode()
    index.cache_path.write_bytes(raw)
    if api == "verify":
        assert index.verify() == []
    assert index.messages() == expected
    assert module.compare(mailbox, index) == []


@POSIX
@pytest.mark.parametrize("target", ["cache", "log"])
def test_r3_hardlinked_cache_files_refused(mailbox, monkeypatch, target):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    seed = index.messages()["seed"]
    path = index.cache_path if target == "cache" else index.directory / "divergence.jsonl"
    if path.exists():
        path.unlink()
    os.link(seed["path"], path)
    before = snapshot(mailbox.root)
    if target == "log":
        injected = stub_messages(monkeypatch, index, {})
        def call():
            return module.compare(mailbox, index)
    else:
        call = index.messages
    error_type, error = caught(call)
    assert error_type is ValueError or issubclass(error_type, ValueError)
    assert "link" in error and "private directory" in error
    assert snapshot(mailbox.root) == before
    if target == "log":
        assert injected == [True]


@POSIX
@pytest.mark.parametrize("target", ["cache", "log"])
def test_r3_directory_swap_never_writes_mailbox(mailbox, tmp_path, monkeypatch, target):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    index.messages()
    mailbox.publish(request("new-after-swap"))
    before = snapshot(mailbox.root)
    real_open = os.open
    swapped, violations = [], []
    moved = tmp_path / "moved-cache"

    def intercept(path, flags, *args, **kwargs):
        name = Path(path).name
        selected = name.startswith(".index-") if target == "cache" else name == "divergence.jsonl"
        if flags & os.O_CREAT and selected and not swapped:
            index.directory.rename(moved)
            symlink_or_skip(index.directory, mailbox.root)
            swapped.append(True)
        descriptor = real_open(path, flags, *args, **kwargs)
        if selected and flags & os.O_CREAT:
            violations.extend(p.name for p in mailbox.root.iterdir()
                              if p.name.startswith(".index-") or p.name == "divergence.jsonl")
        return descriptor

    monkeypatch.setattr(os, "open", intercept)
    if target == "log":
        injected_messages = stub_messages(monkeypatch, index, {})
        def call():
            return module.compare(mailbox, index)
    else:
        call = index.messages
    try:
        call()
    except ValueError:
        pass  # Refusing the raced path is also safe.
    assert swapped
    assert violations == []
    assert snapshot(mailbox.root) == before
    if target == "log":
        assert injected_messages == [True]


def test_r3_divergence_log_cap_reported(mailbox, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    index.messages()
    log = index.directory / "divergence.jsonl"
    log.write_bytes(b"x" * 256)
    log.chmod(0o600)
    monkeypatch.setattr(module, "MAX_DIVERGENCE_BYTES", 256, raising=False)
    injected = stub_messages(monkeypatch, index, {})
    differences = module.compare(mailbox, index)
    assert log.stat().st_size == 256
    assert any(item["kind"] == "divergence_log_full" for item in differences)
    assert injected == [True]


@pytest.mark.parametrize("boundary", ["create", "fsync", "replace", "mkdir"])
@pytest.mark.parametrize("anchored", [pytest.param(True, marks=POSIX), False])
def test_r3_cache_write_failure_returns_valid_read(mailbox, monkeypatch, boundary, anchored):
    module = index_module()
    monkeypatch.setattr(module, "DIR_FD", anchored)
    index = module.MailboxIndex(mailbox)
    if boundary != "mkdir":
        index.messages()
    mailbox.publish(request("after-build"))
    expected = mailbox.messages()
    real_open, real_mkdir, real_path_mkdir = os.open, os.mkdir, Path.mkdir
    injected = []

    def fail(*args, **kwargs):
        injected.append(boundary)
        raise OSError(errno.ENOSPC, "injected " + boundary + " failure")

    def fail_create(path, flags, *args, **kwargs):
        if flags & os.O_CREAT and Path(path).name.startswith(".index-"):
            return fail()
        return real_open(path, flags, *args, **kwargs)

    def fail_mkdir(path, *args, **kwargs):
        if Path(path).name == index.directory.name:
            return fail()
        return real_mkdir(path, *args, **kwargs)

    def fail_path_mkdir(path, *args, **kwargs):
        if path.name == index.directory.name:
            return fail()
        return real_path_mkdir(path, *args, **kwargs)

    if boundary == "create":
        monkeypatch.setattr(os, "open", fail_create)
    elif boundary == "mkdir":
        monkeypatch.setattr(os, "mkdir", fail_mkdir)
        monkeypatch.setattr(Path, "mkdir", fail_path_mkdir)
    else:
        monkeypatch.setattr(os, boundary, fail)
    with pytest.warns(RuntimeWarning, match="mailbox cache write failed"):
        assert index.messages() == expected
    assert "injected " + boundary + " failure" in index.last_write_error
    assert injected


@pytest.mark.parametrize("unlink_fails", [False, True])
def test_r3_old_temp_sweep_is_bounded_and_optional(mailbox, monkeypatch, unlink_fails):
    index = index_module().MailboxIndex(mailbox)
    index.messages()
    old = index.directory / ".index-old.tmp"
    recent = index.directory / ".index-recent.tmp"
    unrelated = index.directory / "unrelated.tmp"
    for path in (old, recent, unrelated):
        path.write_bytes(b"not a cache")
        path.chmod(0o600)
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    if unlink_fails:
        real_unlink = os.unlink
        injected = []

        def fail_old(path, *args, **kwargs):
            if Path(path).name == old.name:
                injected.append(True)
                raise OSError(errno.EACCES, "injected cleanup refusal")
            return real_unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", fail_old)
    assert index.messages() == mailbox.messages()
    assert old.exists() is unlink_fails
    assert recent.exists() and unrelated.exists()
    if unlink_fails:
        assert injected


def test_r3_vanished_entry_retries_once(mailbox, monkeypatch):
    index = index_module().MailboxIndex(mailbox)
    seed = index.messages()["seed"]
    real_lstat = Path.lstat
    injected = []

    def vanished(path, *args, **kwargs):
        if str(path) == seed["path"] and not injected:
            injected.append(True)
            raise FileNotFoundError(errno.ENOENT, "injected vanishing entry", str(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", vanished)
    assert index.messages() == mailbox.messages()
    assert injected == [True]


def test_r3_folder_ancestors_checked_once(mailbox, monkeypatch):
    index = index_module().MailboxIndex(mailbox)
    index.messages()
    counts = {}
    real_lstat = Path.lstat

    def lstat(path, *args, **kwargs):
        counts[path] = counts.get(path, 0) + 1
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    index.get("seed")
    assert counts[mailbox.root] == 1


@POSIX
@pytest.mark.parametrize("mode", [0o500, 0o400])
def test_r3_read_only_cache_directory_returns_valid_read(mailbox, mode):
    index = index_module().MailboxIndex(mailbox)
    index.messages()
    mailbox.publish(request("new-with-readonly-cache"))
    expected = mailbox.messages()
    index.directory.chmod(mode)
    try:
        with pytest.warns(RuntimeWarning, match="mailbox cache write failed"):
            assert index.messages() == expected
        assert index.last_write_error
    finally:
        index.directory.chmod(0o700)


@pytest.mark.skipif(os.environ.get("AEGIS_MB1_SLOW") != "1", reason="opt in with AEGIS_MB1_SLOW=1")
def test_r3_ac1_10k_warm_get(mailbox, record_property):
    """Fixture files use pinned validation and the pinned no-replace publisher."""
    seed = mailbox.messages()["seed"]
    for i in range(1, 10000):
        message = {**seed["message"], "message_id": "scale-%05d" % i}
        destination = mailbox.validate_message(message, stored=True)
        header = {k: v for k, v in message.items() if k != "body"}
        raw = b"---\n" + hm.encoded(header) + b"\n---\n\n" + message["body"].encode()
        name = Path(seed["path"]).name.replace("-seed.md", "-" + message["message_id"] + ".md")
        hm.publish_file(destination / name, raw)
    expected_all = mailbox.messages()
    expected = expected_all["seed"]
    index = index_module().MailboxIndex(mailbox)
    index.messages()
    start = time.perf_counter()
    actual = index.get("seed")
    elapsed = time.perf_counter() - start
    record_property("ac1_get_seconds", elapsed)
    assert actual == expected and key_order(actual) == key_order(expected)
    assert elapsed < 0.2
    start = time.perf_counter()
    actual_all = index.messages()
    elapsed = time.perf_counter() - start
    record_property("ac1_messages_seconds", elapsed)
    assert actual_all == expected_all and key_order(actual_all) == key_order(expected_all)
    assert elapsed < 0.2


@pytest.mark.parametrize("removed, victims", [(True, 1), (False, 1), (True, 2)])
def test_r4_vanish_between_stat_and_read(mailbox, monkeypatch, removed, victims):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    paths = {Path(mailbox.publish(request("vanish-%d" % i))["path"]) for i in range(victims)}
    real_open = Path.open
    injected = []

    def vanish(path, *args, **kwargs):
        if path in paths and path not in injected and args and args[0] == "rb":
            injected.append(path)
            if removed:
                path.unlink()
            raise FileNotFoundError(errno.ENOENT, "injected stat/read disappearance", str(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", vanish)
    if removed and victims == 1:
        assert index.messages() == expected
    else:
        assert issubclass(caught(index.messages)[0], module.IndexDivergence)
    assert len(injected) == victims


def test_r4_fallback_write_reuses_memory_immediately(mailbox, monkeypatch):
    module = index_module()
    monkeypatch.setattr(module, "DIR_FD", False)
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    parsed = []
    real_parse = hm.strict_json

    def parse(raw):
        parsed.append(True)
        return real_parse(raw)

    monkeypatch.setattr(hm, "strict_json", parse)
    assert index.messages() == expected
    assert parsed == []
    mailbox.publish(request("fallback-new"))
    parsed.clear()
    index.get("seed")
    assert len(parsed) == 1  # Only the new message, not the just-written cache.
    parsed.clear()
    index.get("seed")
    assert parsed == []


@pytest.mark.parametrize("name", ["caf\u00e9.md", "space name.md"])
def test_r4_unicode_filename_fresh_instance_reuses_entries(mailbox, monkeypatch, name):
    module = index_module()
    seed = Path(mailbox.messages()["seed"]["path"])
    seed.rename(seed.with_name(name))
    expected = mailbox.messages()
    module.MailboxIndex(mailbox).messages()
    real_read = module.MailboxIndex._read_message
    reads = []

    def read(self, path):
        reads.append(path)
        return real_read(self, path)

    monkeypatch.setattr(module.MailboxIndex, "_read_message", read)
    assert module.MailboxIndex(mailbox).messages() == expected
    assert reads == []
    new = mailbox.publish(request("unicode-new"))
    assert module.MailboxIndex(mailbox).get("unicode-new") == {"path": new["path"], "message": new["message"]}
    assert reads == [Path(new["path"])]


@POSIX
@pytest.mark.parametrize("busy", [False, True])
def test_r4_log_cap_checked_under_bounded_flock(mailbox, monkeypatch, busy):
    import fcntl
    module = index_module()
    index = module.MailboxIndex(mailbox)
    index.messages()
    log = index.directory / "divergence.jsonl"
    log.touch(mode=0o600)
    monkeypatch.setattr(module, "MAX_DIVERGENCE_BYTES", 512)
    monkeypatch.setattr(module, "LOG_LOCK_TIMEOUT_SECONDS", 0, raising=False)
    stub = stub_messages(monkeypatch, index, {})
    real_flock = fcntl.flock
    locks = []

    def interleave(descriptor, operation):
        locks.append(operation)
        if operation & fcntl.LOCK_EX:
            assert operation & fcntl.LOCK_NB
            if busy:
                raise BlockingIOError(errno.EWOULDBLOCK, "injected log contention")
            real_flock(descriptor, operation)
            # A competing append completed before this lock was granted.
            with log.open("ab") as other:
                other.write(b"x" * 512)
        else:
            real_flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", interleave)
    differences = module.compare(mailbox, index)
    assert locks and stub == [True]
    if busy:
        assert any(item["kind"] == "divergence_log_busy" for item in differences)
        assert log.stat().st_size == 0
        assert len(locks) == 1
    else:
        assert locks[-1] == fcntl.LOCK_UN
        assert any(item["kind"] == "divergence_log_full" for item in differences)
        assert log.stat().st_size == 512


def test_r4_budget_failure_is_remembered_until_count_grows(mailbox, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    expected = index.messages()
    budget = index.cache_path.stat().st_size - 1
    index.cache_path.unlink()
    monkeypatch.setattr(module, "MAX_CACHE_BYTES", budget)
    encoded = []
    real_dumps = json.dumps

    def dumps(value, *args, **kwargs):
        if isinstance(value, dict) and "message" in value and "key" in value:
            encoded.append(True)
        return real_dumps(value, *args, **kwargs)

    monkeypatch.setattr(json, "dumps", dumps)
    with pytest.warns(RuntimeWarning, match="cache disabled for this mailbox size"):
        assert index.messages() == expected
    assert encoded == [True]
    assert "MAX_CACHE_BYTES in tools/hierarchy_mailbox_index.py" in index.last_write_error
    encoded.clear()
    assert index.messages() == expected
    assert encoded == []
    mailbox.publish(request("larger"))
    with pytest.warns(RuntimeWarning, match="cache disabled for this mailbox size"):
        assert index.messages() == mailbox.messages()
    assert encoded == [True]


def test_r4_messages_does_not_use_generic_deepcopy(mailbox, monkeypatch):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    index.messages()
    copied = []
    real_copy = module.copy.deepcopy

    def deepcopy(value, *args, **kwargs):
        copied.append(True)
        return real_copy(value, *args, **kwargs)

    monkeypatch.setattr(module.copy, "deepcopy", deepcopy)
    assert index.messages() == mailbox.messages()
    assert copied == []
    assert index.get("seed") == mailbox.messages()["seed"]
    assert copied == [True]


@POSIX
@pytest.mark.parametrize("target", ["cache", "log"])
@pytest.mark.parametrize("mode", [0o640, 0o604])
def test_r4_readable_cache_files_refused(mailbox, monkeypatch, target, mode):
    module = index_module()
    index = module.MailboxIndex(mailbox)
    index.messages()
    path = index.cache_path if target == "cache" else index.directory / "divergence.jsonl"
    if target == "log":
        path.touch(mode=0o600)
        injected = stub_messages(monkeypatch, index, {})
    path.chmod(mode)
    before = snapshot(mailbox.root)
    call = index.messages if target == "cache" else lambda: module.compare(mailbox, index)
    error_type, message = caught(call)
    assert issubclass(error_type, ValueError)
    assert "readable" in message and "private directory" in message
    assert snapshot(mailbox.root) == before
    if target == "log":
        assert injected == [True]


def test_r4_readiness_paths_require_shadow_or_verify(tmp_path):
    from tests.integration.test_hierarchy_mailbox import readiness
    module = index_module()
    root = tmp_path / "mailbox"
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                "endpoints": {"a/front-door": {}, "a/orchestrator": {},
                              "a/lane/write": {"kind": "implementer"}}, "counterparts": []}
    hm.initialize(root, manifest)
    box = hm.Mailbox(root)
    for endpoint in manifest["endpoints"]:
        box.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint, "expected_generation": 0})
    folder = tmp_path / "worktrees"
    folder.mkdir()
    evidence = readiness(folder)
    brief_path = tmp_path / "packet.md"
    brief_path.write_text("Review the cache.\n")
    brief = {"path": str(brief_path), "sha256": hashlib.sha256(brief_path.read_bytes()).hexdigest()}
    box.publish(request("dispatch", recipient="a/lane/write", type="dispatch", brief=brief))
    box.publish(request("accepted", "a/lane/write", "a/orchestrator", type="ack", acknowledgment="accepted",
                        in_reply_to="dispatch", readiness=evidence))
    index = module.MailboxIndex(box)
    expected = index.messages()
    moved = tmp_path / "old-worktrees"
    folder.rename(moved)
    symlink_or_skip(folder, moved)
    assert evidence["worktree"] == evidence["scan_workspace"]
    assert index.messages() == expected
    assert module.compare(box, index)
    assert caught(index.verify) == caught(box.messages)
    assert "readiness.worktree" in module.__doc__ and "scan_workspace" in module.__doc__
