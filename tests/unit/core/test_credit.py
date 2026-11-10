"""Exposure persistence follows the ledger currently on disk, within one process."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from time import time_ns
from types import SimpleNamespace

import pytest

from aegis_core import credit, credit_memo, storage
from aegis_core.errors import PathTraversalError
from aegis_core.telemetry_engine import ledger
from tests.conftest import symlink_or_skip


@pytest.fixture(autouse=True, params=["native", "portable"])
def snapshot_capabilities(request, monkeypatch):
    """Keep every exposure assertion on the native and portable memo paths."""
    if request.param == "portable":
        monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(vars(credit_memo.os), supports_dir_fd=set())))


@contextmanager
def _settle_ledger(root, monkeypatch):
    """Settle only the enclosed I/O, retaining a distinguishable backdated mtime."""
    path = ledger.ledger_path(root)
    old = time_ns() - 10_000_000_000
    os.utime(path, ns=(old, old))
    with monkeypatch.context() as patch:
        patch.setattr(storage, "time", SimpleNamespace(**dict(vars(time), time_ns=lambda: time_ns() + 3_000_000_000)))
        yield path


def test_windows_creation_time_and_descriptor_change_time_share_generation(tmp_path, monkeypatch):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    monkeypatch.setattr(storage, "_COMPARE_CTIME", False)
    path = ledger.ledger_path(tmp_path)
    identity = path.stat()

    def creation(info):
        if (info.st_dev, info.st_ino) != (identity.st_dev, identity.st_ino):
            return info
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields["st_ctime_ns"] = 1
        return SimpleNamespace(**fields)

    monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(vars(credit_memo.os),
        stat=lambda *a, **kw: creation(os.stat(*a, **kw)),
        lstat=lambda *a, **kw: creation(os.lstat(*a, **kw)))))
    calls, real_read = [], credit.read_rows

    def read(root):
        calls.append(root)
        return real_read(root)

    monkeypatch.setattr(credit, "read_rows", read)
    with _settle_ledger(tmp_path, monkeypatch):
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    assert calls == [tmp_path]


def test_reset_before_append_report_under_clock_skew_never_fills(tmp_path, monkeypatch):
    real_fsync = os.fsync
    path = ledger.ledger_path(tmp_path)
    resets = []

    def fsync(fd):
        real_fsync(fd)
        if not resets and path.exists() and path.stat().st_size:
            data = path.read_bytes()
            replacement = data.replace(b'"rule":"rule-a"', b'"rule":"rule-b"')
            assert data != replacement and len(data) == len(replacement)
            path.write_bytes(replacement)
            resets.append(True)

    # Model process clocks ahead of the file clock: even apparently settled
    # append evidence cannot certify a row erased before its report is captured.
    monkeypatch.setattr(credit_memo, "time_ns", lambda: time_ns() + 10_000_000_000)
    with monkeypatch.context() as patch:
        patch.setattr(storage, "time", SimpleNamespace(**dict(vars(time), time_ns=lambda: time_ns() + 3_000_000_000)))
        patch.setattr(storage, "os", SimpleNamespace(**dict(vars(credit_memo.os), fsync=fsync)))
        assert len(credit.record_exposure(tmp_path, "host", "session", ["rule-a"])) == 1
    assert resets == [True]
    assert [row["rule"] for row in credit.record_exposure(tmp_path, "host", "session", ["rule-a"])] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-b", "rule-a"]


@pytest.mark.parametrize("operation", ["read", "append"])
def test_delayed_fill_with_coarse_unchanged_stamps_stays_ineligible(tmp_path, monkeypatch, operation):
    credit.record_exposure(tmp_path, "host", "session", ["rule-c", "rule-a", "rule-d"])
    credit_memo.reset()
    path = ledger.ledger_path(tmp_path)
    identity = path.stat()
    tick = time_ns() - 500_000_000
    real_read = credit.read_rows

    def coarse(info):
        if (info.st_dev, info.st_ino) != (identity.st_dev, identity.st_ino):
            return info
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields.update(st_mtime_ns=tick, st_ctime_ns=tick)
        return SimpleNamespace(**fields)

    def read(root):
        rows = real_read(root)
        data = path.read_bytes()
        replacement = data.replace(b'"rule":"rule-a"', b'"rule":"rule-b"')
        assert data != replacement and len(data) == len(replacement)
        path.write_bytes(replacement)
        return rows

    io = SimpleNamespace(**dict(vars(credit_memo.os),
        stat=lambda *a, **kw: coarse(os.stat(*a, **kw)),
        lstat=lambda *a, **kw: coarse(os.lstat(*a, **kw)),
        fstat=lambda fd: coarse(os.fstat(fd))))
    monkeypatch.setattr(storage, "os", io)
    monkeypatch.setattr(credit_memo, "os", io)
    monkeypatch.setattr(credit_memo, "time_ns", lambda: tick + 10_000_000_000)
    with monkeypatch.context() as patch:
        patch.setattr(storage, "time", SimpleNamespace(**dict(vars(time), time_ns=lambda: tick + 500_000_000)))
        patch.setattr(credit, "read_rows", read)
        rules = ["rule-a"] if operation == "read" else ["rule-a", "rule-e"]
        credit.record_exposure(tmp_path, "other-host", "session", rules)
    assert [row["rule"] for row in credit.record_exposure(tmp_path, "other-host", "session", ["rule-a"])] == ["rule-a"]


@pytest.mark.parametrize("settled_read", [False, True], ids=["after-append", "after-settled-read"])
def test_multirow_reset_preserving_both_samples_misses(tmp_path, monkeypatch, settled_read):
    paths = ["src/package/module_%02d.py" % i for i in range(20)]
    stamp = "2026-11-10T12:00:00Z"
    credit.record_exposure(tmp_path, "host", "session", ["rule-c", "rule-a", "rule-d"], paths=paths, ts=stamp)
    if settled_read:
        credit_memo.reset()
        with _settle_ledger(tmp_path, monkeypatch):
            assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths, ts=stamp) == []
    path = ledger.ledger_path(tmp_path)
    original, info = path.read_bytes(), path.stat()
    code = (
        "import json, sys\n"
        "from aegis_core import credit\n"
        "from aegis_core.telemetry_engine import ledger\n"
        "args = json.load(sys.stdin)\n"
        "ledger.ledger_path(args['root']).write_bytes(b'')\n"
        "rows = credit.record_exposure(args['root'], 'host', 'session', ['rule-c', 'rule-b', 'rule-d'], "
        "paths=args['paths'], ts=args['stamp'])\n"
        "assert [row['rule'] for row in rows] == ['rule-c', 'rule-b', 'rule-d']\n"
    )
    subprocess.run([sys.executable, "-c", code],
                   input=json.dumps({"root": str(tmp_path), "paths": paths, "stamp": stamp}),
                   cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, check=True, timeout=30)
    replacement = path.read_bytes()
    assert path.stat().st_ino == info.st_ino
    assert len(original) == len(replacement)
    assert original[:256] == replacement[:256]
    assert original[-256:] == replacement[-256:]
    assert original != replacement

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths, ts=stamp)

    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-c", "rule-b", "rule-d", "rule-a"]


@pytest.mark.parametrize("phase", ["read", "append", "read-before-append"])
def test_multirow_reset_during_fill_cannot_certify_removed_rule(tmp_path, monkeypatch, phase):
    paths = ["src/package/module_%02d.py" % i for i in range(20)]
    stamp = "2026-11-10T12:00:00Z"
    credit.record_exposure(tmp_path, "host", "session", ["rule-c", "rule-a", "rule-d"], paths=paths, ts=stamp)
    real_read, real_append = credit.read_rows, ledger.append_rows

    def reset():
        path = ledger.ledger_path(tmp_path)
        data = path.read_bytes()
        replacement = data.replace(b'"rule":"rule-a"', b'"rule":"rule-b"')
        assert data[:256] == replacement[:256] and data[-256:] == replacement[-256:]
        assert len(data) == len(replacement) and data != replacement
        path.write_bytes(replacement)

    def read(root):
        rows = real_read(root)
        reset()
        return rows

    def append(root, rows):
        written = real_append(root, rows)
        reset()
        return written

    with monkeypatch.context() as patch:
        patch.setattr(credit if phase != "append" else ledger,
                      "read_rows" if phase != "append" else "append_rows",
                      read if phase != "append" else append)
        rules = ["rule-a"] if phase == "read" else ["rule-a", "rule-e"]
        written = credit.record_exposure(tmp_path, "other-host", "session", rules, paths=paths, ts=stamp)
        assert [row["rule"] for row in written] == ([] if phase == "read" else ["rule-e"])

    assert [row["rule"] for row in credit.record_exposure(
        tmp_path, "other-host", "session", ["rule-a"], paths=paths, ts=stamp)] == ["rule-a"]
    assert [row["rule"] for row in real_read(tmp_path)] == (
        ["rule-c", "rule-b", "rule-d"] + ([] if phase == "read" else ["rule-e"]) + ["rule-a"])


@pytest.mark.parametrize("operation", ["read", "append"])
@pytest.mark.parametrize("racy_field", ["mtime", "ctime"])
@pytest.mark.parametrize("age_ns", [0, 1_999_999_999, 2_000_000_000, 2_000_000_001, -1])
def test_racy_timestamp_refuses_memo_until_settled(tmp_path, monkeypatch, age_ns, operation, racy_field):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    credit_memo.reset()
    path = ledger.ledger_path(tmp_path)
    identity = path.stat()
    tick = time_ns() - 10_000_000_000

    def stamps(info):
        if (info.st_dev, info.st_ino) != (identity.st_dev, identity.st_ino):
            return info
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields.update(st_mtime_ns=tick if racy_field == "mtime" else tick - 10_000_000_000,
                      st_ctime_ns=tick if racy_field == "ctime" else tick - 10_000_000_000)
        return SimpleNamespace(**fields)

    io = SimpleNamespace(**dict(vars(credit_memo.os),
        stat=lambda *a, **kw: stamps(os.stat(*a, **kw)),
        lstat=lambda *a, **kw: stamps(os.lstat(*a, **kw)),
        fstat=lambda fd: stamps(os.fstat(fd))))
    monkeypatch.setattr(storage, "os", io)
    monkeypatch.setattr(credit_memo, "os", io)
    # Boundary-only clock: the snapshot remains on the real clock, while the
    # authoritative I/O starts at a precise offset from a controlled stat tick.
    with monkeypatch.context() as patch:
        patch.setattr(storage, "time", SimpleNamespace(**dict(vars(time), time_ns=lambda: tick + age_ns)))
        rule = "rule-a" if operation == "read" else "rule-b"
        written = credit.record_exposure(tmp_path, "host", "session", [rule])
    assert [row["rule"] for row in written] == ([] if operation == "read" else [rule])
    calls, real_read = [], credit.read_rows

    def read(root):
        calls.append(root)
        return real_read(root)

    monkeypatch.setattr(credit, "read_rows", read)
    with monkeypatch.context() as patch:
        patch.setattr(storage, "time", SimpleNamespace(**dict(vars(time), time_ns=lambda: tick + age_ns)))
        assert credit.record_exposure(tmp_path, "host", "session", [rule]) == []
    read_eligible = age_ns > 2_000_000_000 or (racy_field == "ctime" and not storage._COMPARE_CTIME)
    eligible = operation == "read" and read_eligible
    assert calls == ([] if eligible else [tmp_path])
    # Appends never fill, even with old stamps under file-clock skew. Only the
    # next settled authoritative read can establish the memo.
    calls.clear()
    with monkeypatch.context() as patch:
        patch.setattr(storage, "time", SimpleNamespace(**dict(vars(time), time_ns=lambda: tick + 3_000_000_000)))
        assert credit.record_exposure(tmp_path, "host", "session", [rule]) == []
    assert calls == ([] if read_eligible else [tmp_path])
    calls.clear()
    assert credit.record_exposure(tmp_path, "host", "session", [rule]) == []
    assert calls == []


@pytest.mark.parametrize("field", ["st_mtime_ns", "st_ctime_ns"])
def test_either_generation_stamp_alone_invalidates_memo(tmp_path, monkeypatch, field):
    if field == "st_ctime_ns" and not storage._COMPARE_CTIME:
        pytest.skip("Windows creation time cannot be compared with descriptor change time")
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    with _settle_ledger(tmp_path, monkeypatch):
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    info = ledger.ledger_path(tmp_path).stat()
    calls, real_lock = [], credit.ledger_locked

    def changed(value):
        if (value.st_dev, value.st_ino) == (info.st_dev, info.st_ino):
            fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
            fields[field] += 1
            return SimpleNamespace(**fields)
        return value

    def lock(root):
        calls.append(root)
        return real_lock(root)

    monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(
        vars(credit_memo.os), stat=lambda *a, **kw: changed(os.stat(*a, **kw)),
        lstat=lambda *a, **kw: changed(os.lstat(*a, **kw)),
        fstat=lambda fd: changed(os.fstat(fd)))))
    monkeypatch.setattr(credit, "ledger_locked", lock)
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    assert calls == [tmp_path]


@pytest.mark.parametrize("change", ["delete", "replace", "truncate"])
def test_exposure_is_written_again_after_ledger_changes(tmp_path, change):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    original = path.stat()
    if change == "delete":
        path.unlink()
    elif change == "replace":
        replacement = path.with_name("replacement.jsonl")
        # A larger replacement isolates identity validation from the size check.
        replacement.write_text("\n" * (original.st_size + 1), encoding="utf-8")
        replacement.replace(path)
        assert path.stat().st_ino != original.st_ino
    else:
        path.write_text("", encoding="utf-8")
        assert path.stat().st_ino == original.st_ino

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])

    assert [row["rule"] for row in written] == ["rule-a"]
    assert [(row["session"], row["rule"]) for row in credit.read_rows(tmp_path)] == [
        ("session", "rule-a"),
    ]


@pytest.mark.parametrize("append_other_row", [False, True], ids=["unchanged", "grown"])
@pytest.mark.parametrize("file_count", [0, 20], ids=["short", "long"])
def test_rescan_checks_generation_without_reads_and_any_append_misses(tmp_path, monkeypatch, append_other_row, file_count):
    paths = ["src/package/module_%02d.py" % i for i in range(file_count)]
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths)
    with _settle_ledger(tmp_path, monkeypatch):
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths) == []
    path = ledger.ledger_path(tmp_path)
    if append_other_row:
        ledger.append_rows(tmp_path, [{"v": ledger.LEDGER_VERSION, "event": "exposure", "rule": "rule-b"}])
    calls = []
    opened, reads, seeks = [], [], []
    descriptors = set()
    real_lock, real_read = credit.ledger_locked, credit.read_rows
    real_open, real_fd_read, real_seek = os.open, os.read, os.lseek

    def open_file(file, *args, **kwargs):
        fd = real_open(file, *args, **kwargs)
        if os.fspath(file) in (os.fspath(path), path.name):
            opened.append(file)
            descriptors.add(fd)
        return fd

    def fd_read(fd, size):
        if fd in descriptors:
            reads.append(size)
        return real_fd_read(fd, size)

    def seek(fd, offset, whence):
        if fd in descriptors:
            seeks.append((offset, whence))
        return real_seek(fd, offset, whence)

    def lock(root):
        calls.append("lock")
        return real_lock(root)

    def read(root):
        calls.append("read")
        return real_read(root)

    monkeypatch.setattr(credit, "ledger_locked", lock)
    monkeypatch.setattr(credit, "read_rows", read)
    monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(
        vars(credit_memo.os), open=open_file, read=fd_read, lseek=seek)))
    monkeypatch.setattr(credit_memo.atomicio, "os", SimpleNamespace(**dict(vars(credit_memo.os), open=open_file)))
    if append_other_row:
        with _settle_ledger(tmp_path, monkeypatch):
            assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths) == []
    else:
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths) == []
    assert calls == (["lock", "read"] if append_other_row else [])
    assert len(opened) == (3 if append_other_row else 1)
    assert reads == seeks == []
    calls.clear()
    opened.clear()
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths) == []
    assert calls == []
    assert len(opened) == 1
    assert reads == seeks == []
    expected = ["rule-a", "rule-b"] if append_other_row else ["rule-a"]
    assert [row["rule"] for row in real_read(tmp_path)] == expected


def test_equal_length_reset_with_matching_tail_from_another_process_restores_exposure(tmp_path):
    paths = ["src/package/module_%02d.py" % i for i in range(20)]
    stamp = "2026-11-10T12:00:00Z"
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths, ts=stamp)
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths, ts=stamp) == []
    path = ledger.ledger_path(tmp_path)
    original, identity = path.read_bytes(), path.stat()
    code = (
        "import json, sys\n"
        "from aegis_core import credit\n"
        "from aegis_core.telemetry_engine import ledger\n"
        "args = json.load(sys.stdin)\n"
        "ledger.ledger_path(args['root']).write_bytes(b'')\n"
        "written = credit.record_exposure(args['root'], 'host', 'session', ['rule-b'], paths=args['paths'], ts=args['stamp'])\n"
        "assert [row['rule'] for row in written] == ['rule-b']\n"
    )
    subprocess.run([sys.executable, "-c", code],
                   input=json.dumps({"root": str(tmp_path), "paths": paths, "stamp": stamp}),
                   cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, check=True, timeout=30)
    replacement = path.read_bytes()
    assert (path.stat().st_dev, path.stat().st_ino) == (identity.st_dev, identity.st_ino)
    assert len(replacement) == len(original)
    assert replacement[-ledger._TAIL_CHECK_BYTES:] == original[-ledger._TAIL_CHECK_BYTES:]
    assert replacement[:ledger._TAIL_CHECK_BYTES] != original[:ledger._TAIL_CHECK_BYTES]

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths, ts=stamp)

    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-b", "rule-a"]


def test_fill_preserves_the_head_used_by_its_locked_read_when_it_also_appends(tmp_path, monkeypatch):
    paths = ["src/package/module_%02d.py" % i for i in range(20)]
    stamp = "2026-11-10T12:00:00Z"
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=paths, ts=stamp)
    path = ledger.ledger_path(tmp_path)
    original = path.read_bytes()
    assert original.count(b'"rule":"rule-a"') == 1
    replacement = original.replace(b'"rule":"rule-a"', b'"rule":"rule-b"')
    real_read = credit.read_rows

    def read(root):
        rows = real_read(root)
        path.write_bytes(replacement)
        return rows

    with monkeypatch.context() as patch:
        patch.setattr(credit, "read_rows", read)
        written = credit.record_exposure(tmp_path, "other-host", "session", ["rule-a", "rule-c"], paths=paths, ts=stamp)
    assert [row["rule"] for row in written] == ["rule-c"]
    assert [row["rule"] for row in real_read(tmp_path)] == ["rule-b", "rule-c"]

    written = credit.record_exposure(tmp_path, "other-host", "session", ["rule-a"], paths=paths, ts=stamp)

    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in real_read(tmp_path)] == ["rule-b", "rule-c", "rule-a"]


def test_new_exposure_after_replacement_does_not_revalidate_old_memo(tmp_path):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    replacement = path.with_name("replacement.jsonl")
    replacement.write_text("", encoding="utf-8")
    replacement.replace(path)

    credit.record_exposure(tmp_path, "host", "session", ["rule-b"])
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])

    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-b", "rule-a"]


@pytest.fixture(scope="module")
def shared_root(tmp_path_factory):
    return tmp_path_factory.mktemp("credit-shared-root")


@pytest.mark.parametrize("case", ["first", "second"])
def test_credit_caches_do_not_leak_between_tests(shared_root, case):
    # Both cases use the same root, host and session in one worker.
    assert credit.witnessed_exposed_rules(shared_root, "host", "session") == set()
    assert len(credit.record_exposure(shared_root, "host", "session", ["rule-a"])) == 1
    assert credit.witnessed_exposed_rules(shared_root, "host", "session") == {"rule-a"}
    ledger.ledger_path(shared_root).unlink()


@pytest.mark.parametrize("change", ["truncate-regrow", "delete-recreate"])
def test_reset_that_regrows_past_the_cached_size_restores_exposure(tmp_path, change):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    original = path.stat()
    original_tail = path.read_bytes()[-ledger._TAIL_CHECK_BYTES:]
    replacement = (json.dumps({"v": ledger.LEDGER_VERSION, "event": "exposure", "rule": "other",
                               "padding": "x" * (original.st_size + 1)}) + "\n").encode("utf-8")
    if change == "truncate-regrow":
        with path.open("r+b") as stream:
            stream.truncate(0)
            stream.write(replacement)
        assert path.stat().st_ino == original.st_ino
    else:
        # Deletion may allocate a fresh inode. The in-place branch above provides
        # deterministic same-inode coverage; both branches must restore the row.
        path.unlink()
        path.write_bytes(replacement)
    assert len(replacement) > original.st_size
    assert replacement[max(0, original.st_size - ledger._TAIL_CHECK_BYTES):original.st_size] != original_tail

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])

    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["other", "rule-a"]


def test_replacement_while_waiting_for_lock_drops_old_rules(tmp_path, monkeypatch):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    real_lock = credit.ledger_locked

    @contextmanager
    def replacing_lock(root):
        with real_lock(root) as site:
            replacement = path.with_name("replacement.jsonl")
            replacement.write_text("", encoding="utf-8")
            replacement.replace(path)
            yield site

    with monkeypatch.context() as patch:
        patch.setattr(credit, "ledger_locked", replacing_lock)
        credit.record_exposure(tmp_path, "host", "session", ["rule-b"])

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-b", "rule-a"]


@pytest.mark.parametrize("error", [PermissionError, NotADirectoryError])
def test_fast_path_stat_error_falls_back_to_the_locked_read(tmp_path, monkeypatch, error):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    with _settle_ledger(tmp_path, monkeypatch):
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    path = ledger.ledger_path(tmp_path)
    real_stat, real_fstat, real_lock = os.stat, os.fstat, credit.ledger_locked
    identity = path.stat()
    errors, locks = [], []

    def check(info):
        if not errors and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            errors.append(error)
            raise error("injected cache metadata failure")
        return info

    def lock(root):
        locks.append(root)
        return real_lock(root)

    monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(vars(credit_memo.os),
        stat=lambda *args, **kwargs: check(real_stat(*args, **kwargs)),
        fstat=lambda fd: check(real_fstat(fd)))))
    monkeypatch.setattr(credit, "ledger_locked", lock)
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    assert errors == [error]
    assert locks == [tmp_path]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-a"]


def test_post_append_stat_error_does_not_hide_a_successful_write(tmp_path, monkeypatch):
    real_fsync, real_fstat = os.fsync, os.fstat
    appended, errors = [], []

    def fsync(fd):
        result = real_fsync(fd)
        info = real_fstat(fd)
        if info.st_size:
            appended.append((info.st_dev, info.st_ino))
        return result

    def fstat(fd):
        info = real_fstat(fd)
        if appended and not errors and (info.st_dev, info.st_ino) == appended[0]:
            errors.append("stat")
            raise PermissionError("injected post-append metadata failure")
        return info

    monkeypatch.setattr(storage, "os", SimpleNamespace(**dict(vars(credit_memo.os), fsync=fsync, fstat=fstat)))
    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]
    assert errors == ["stat"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-a"]
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []


def test_a_changed_ledger_site_gets_its_own_exposure(tmp_path, monkeypatch):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    original = ledger.ledger_path(tmp_path)
    moved_root = tmp_path / "new-site"
    moved_root.mkdir()
    real_site = storage.ledger_site

    def moved_site(root, create=True):
        return real_site(moved_root if root == tmp_path else root, create=create)

    monkeypatch.setattr(storage, "ledger_site", moved_site)
    monkeypatch.setattr(ledger, "ledger_site", moved_site)
    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])

    assert [row["rule"] for row in written] == ["rule-a"]
    assert ledger.ledger_path(tmp_path) != original
    assert original.exists()
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-a"]


def test_snapshot_open_error_falls_back_without_duplicating_rows(tmp_path, monkeypatch):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    with _settle_ledger(tmp_path, monkeypatch):
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    path = ledger.ledger_path(tmp_path)
    real_open, real_lock = os.open, credit.ledger_locked
    errors, locks = [], []

    def open_file(file, *args, **kwargs):
        if not errors and os.fspath(file) in (os.fspath(path), path.name):
            errors.append("open")
            raise OSError("injected snapshot open failure")
        return real_open(file, *args, **kwargs)

    def lock(root):
        locks.append(root)
        return real_lock(root)

    monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(vars(credit_memo.os), open=open_file)))
    monkeypatch.setattr(credit_memo.atomicio, "os", SimpleNamespace(**dict(vars(credit_memo.os), open=open_file)))
    monkeypatch.setattr(credit, "ledger_locked", lock)
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    assert errors == ["open"]
    assert locks == [tmp_path]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-a"]


@pytest.mark.parametrize("replacement", ["directory", "symlink"])
def test_parent_swap_during_cache_open_cannot_validate_the_old_ledger(tmp_path, monkeypatch, replacement):
    if (not hasattr(credit_memo.os, "O_DIRECTORY") or not hasattr(credit_memo.os, "O_NOFOLLOW")
            or not {"open", "stat"} <= {f.__name__ for f in credit_memo.os.supports_dir_fd}
            or "stat" not in {f.__name__ for f in credit_memo.os.supports_follow_symlinks}):
        pytest.skip("descriptor-relative no-follow operations unavailable")
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    with _settle_ledger(tmp_path, monkeypatch):
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    path = ledger.ledger_path(tmp_path)
    backup = path.parent.with_name("old-state")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_ledger = outside / path.name
    outside_ledger.write_text("outside sentinel\n", encoding="utf-8")
    real_open = os.open
    swapped = []

    def open_file(file, *args, **kwargs):
        if not swapped and os.fspath(file) == path.name and "dir_fd" in kwargs:
            swapped.append(file)
            path.parent.rename(backup)
            if replacement == "symlink":
                path.parent.symlink_to(outside, target_is_directory=True)
            else:
                path.parent.mkdir()
                path.write_text("", encoding="utf-8")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(vars(credit_memo.os), open=open_file)))
    if replacement == "symlink":
        with pytest.raises(PathTraversalError) as refused:
            credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
        assert refused.value.code == "ERR_PATH_TRAVERSAL"
    else:
        written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
        assert [row["rule"] for row in written] == ["rule-a"]
        assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-a"]
    assert swapped == [path.name]
    assert outside_ledger.read_text(encoding="utf-8") == "outside sentinel\n"


def test_argon_truncation_then_detection_regrowth_restores_exposure(tmp_path):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    size = path.stat().st_size
    path.write_bytes(b"")
    credit.record_detection(tmp_path, "rule-b", "x" * size, "eval", disposition="caught")
    assert path.stat().st_size >= size

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])

    assert [row["rule"] for row in written] == ["rule-a"]
    assert [(row["event"], row["rule"]) for row in credit.read_rows(tmp_path)] == [
        ("detection", "rule-b"), ("exposure", "rule-a"),
    ]


def test_argon_symlink_to_the_renamed_ledger_is_refused(tmp_path):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    moved = path.with_name("moved.jsonl")
    path.rename(moved)
    symlink_or_skip(moved, path)

    with pytest.raises(PathTraversalError) as refused:
        credit.record_exposure(tmp_path, "host", "session", ["rule-a"])

    assert refused.value.code == "ERR_PATH_TRAVERSAL"
    assert [json.loads(line)["rule"] for line in moved.read_text(encoding="utf-8").splitlines()] == ["rule-a"]


def test_argon_two_root_spellings_share_the_memo_and_its_invalidation(tmp_path, monkeypatch):
    root, alternate = str(tmp_path), str(tmp_path) + "/."
    stamp = "2026-11-10T12:00:00Z"
    credit.record_exposure(root, "host", "session", ["rule-a"], ts=stamp)
    with _settle_ledger(root, monkeypatch):
        assert credit.record_exposure(root, "host", "session", ["rule-a"], ts=stamp) == []
    calls = []
    real_lock = credit.ledger_locked

    def lock(workspace):
        calls.append(workspace)
        return real_lock(workspace)

    with monkeypatch.context() as patch:
        patch.setattr(credit, "ledger_locked", lock)
        assert credit.record_exposure(alternate, "host", "session", ["rule-a"], ts=stamp) == []

    path = ledger.ledger_path(root)
    size = path.stat().st_size
    path.write_bytes(b"")
    credit.record_exposure(alternate, "host", "session", ["rule-b"], ts=stamp)
    assert path.stat().st_size == size
    written = credit.record_exposure(root, "host", "session", ["rule-a"], ts=stamp)
    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(root)] == ["rule-b", "rule-a"]
    assert calls == []


@pytest.mark.parametrize("reset", ["empty", "prior-rows", "partial-append", "replacement"])
def test_reset_between_append_and_memo_fill_restores_exposure(tmp_path, monkeypatch, reset):
    credit.record_exposure(tmp_path, "host", "session", ["rule-b"], paths=["x" * 512])
    path = ledger.ledger_path(tmp_path)
    before = path.read_bytes()
    real_append = ledger.append_rows

    def append(root, rows):
        result = real_append(root, rows)
        if reset == "replacement":
            replacement = path.with_name("replacement.jsonl")
            replacement.write_bytes(before + b"\n" * (path.stat().st_size + 1))
            replacement.replace(path)
        else:
            content = b"" if reset == "empty" else before
            if reset == "partial-append":
                content = path.read_bytes()[:-1]
                # Remove part of the row, not only its optional final newline.
                content = content[:-len(content[len(before):]) // 2]
            path.write_bytes(content)
        return result

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "append_rows", append)
        written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])

    assert [row["rule"] for row in written] == ["rule-a"]
    expected = ["rule-a"] if reset == "empty" else ["rule-b", "rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == expected


def test_reset_between_locked_read_and_fill_without_append_restores_exposure(tmp_path, monkeypatch):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    real_read = credit.read_rows

    def read(root):
        result = real_read(root)
        path.write_bytes(b"")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(credit, "read_rows", read)
        assert credit.record_exposure(tmp_path, "other-host", "session", ["rule-a"]) == []

    written = credit.record_exposure(tmp_path, "other-host", "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in real_read(tmp_path)] == ["rule-a"]


@pytest.mark.parametrize("initially_missing", [False, True])
def test_blank_regrowth_after_append_does_not_certify_missing_exposure(tmp_path, monkeypatch, initially_missing):
    if not initially_missing:
        credit.record_exposure(tmp_path, "host", "session", ["rule-b"])
    path = ledger.ledger_path(tmp_path)
    real_append = ledger.append_rows

    def append(root, rows, **kwargs):
        result = real_append(root, rows, **kwargs)
        path.write_bytes(b"\n" * (path.stat().st_size + 512))
        return result

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "append_rows", append)
        assert [row["rule"] for row in credit.record_exposure(tmp_path, "host", "session", ["rule-a"])] == ["rule-a"]

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-a"]


def test_blank_regrowth_after_no_append_read_does_not_certify_missing_exposure(tmp_path, monkeypatch):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    path = ledger.ledger_path(tmp_path)
    real_read = credit.read_rows

    def read(root, **kwargs):
        rows = real_read(root, **kwargs)
        path.write_bytes(b"\n" * (path.stat().st_size + 512))
        return rows

    with monkeypatch.context() as patch:
        patch.setattr(credit, "read_rows", read)
        assert credit.record_exposure(tmp_path, "other-host", "session", ["rule-a"]) == []

    written = credit.record_exposure(tmp_path, "other-host", "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in real_read(tmp_path)] == ["rule-a"]


def test_replacement_of_initially_missing_ledger_cannot_certify_its_matching_tail(tmp_path, monkeypatch):
    path = ledger.ledger_path(tmp_path)
    assert not path.exists()
    real_append = ledger.append_rows
    identities = []

    def append(root, rows, **kwargs):
        result = real_append(root, rows, **kwargs)
        data, info = path.read_bytes(), path.stat()
        replacement = path.with_name("replacement.jsonl")
        # Keep the entire bounded tail, but no complete row. Only the descriptor
        # identity proves that this file is not the one the append wrote.
        replacement.write_bytes(b"\n" * (len(data) - ledger._TAIL_CHECK_BYTES) + data[-ledger._TAIL_CHECK_BYTES:])
        replacement.replace(path)
        identities.extend([(info.st_dev, info.st_ino), (path.stat().st_dev, path.stat().st_ino)])
        return result

    with monkeypatch.context() as patch:
        patch.setattr(ledger, "append_rows", append)
        assert [row["rule"] for row in credit.record_exposure(tmp_path, "host", "session", ["rule-a"], paths=["x" * 512])] == ["rule-a"]
    assert identities[0] != identities[1]

    written = credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]
    assert [row["rule"] for row in credit.read_rows(tmp_path)] == ["rule-a"]


@pytest.mark.parametrize("trace", ["first-replace", "append-detection", "read-detection"])
def test_argon_0735_reset_traces_restore_exposure(tmp_path, monkeypatch, trace):
    if trace != "first-replace":
        credit.record_exposure(tmp_path, "host", "session", ["rule-a" if trace == "read-detection" else "rule-b"])
    path = ledger.ledger_path(tmp_path)
    real_append, real_read = ledger.append_rows, credit.read_rows

    def reset():
        before = path.stat()
        if trace == "first-replace":
            replacement = path.with_name("replacement.jsonl")
            replacement.write_bytes(b"\n" * before.st_size)
            replacement.replace(path)
            assert path.stat().st_size == before.st_size
        else:
            detection = {"v": ledger.LEDGER_VERSION, "event": "detection", "rule": "rule-d",
                         "padding": "x" * before.st_size}
            path.write_text(json.dumps(detection) + "\n", encoding="utf-8")
            assert path.stat().st_size >= before.st_size
            assert (path.stat().st_dev, path.stat().st_ino) == (before.st_dev, before.st_ino)

    def append(root, rows, **kwargs):
        written = real_append(root, rows, **kwargs)
        reset()
        return written

    def read(root, **kwargs):
        rows = real_read(root, **kwargs)
        reset()
        return rows

    host = "other-host" if trace == "read-detection" else "host"
    with monkeypatch.context() as patch:
        if trace == "read-detection":
            patch.setattr(credit, "read_rows", read)
        else:
            patch.setattr(ledger, "append_rows", append)
        written = credit.record_exposure(tmp_path, host, "session", ["rule-a"])
        assert [row["rule"] for row in written] == ([] if trace == "read-detection" else ["rule-a"])

    written = credit.record_exposure(tmp_path, host, "session", ["rule-a"])
    assert [row["rule"] for row in written] == ["rule-a"]
    expected = ["rule-a"] if trace == "first-replace" else ["rule-d", "rule-a"]
    assert [row["rule"] for row in real_read(tmp_path)] == expected


@pytest.mark.parametrize("ancestor", ["state", "aegis"])
@pytest.mark.parametrize("phase", ["hit", "fill"])
def test_portable_ancestor_substitution_misses_and_reaches_typed_refusal(tmp_path, monkeypatch, ancestor, phase):
    if phase == "fill" and os.name == "nt":
        pytest.skip("Windows cannot rename the directory of the held ledger lock")
    monkeypatch.setattr(credit_memo, "os", SimpleNamespace(**dict(vars(credit_memo.os), supports_dir_fd=set())))
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    if phase == "hit":
        with _settle_ledger(tmp_path, monkeypatch):
            assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    path = ledger.ledger_path(tmp_path)
    directory = path.parent if ancestor == "state" else path.parent.parent
    backup = directory.with_name("old-" + directory.name)
    # Probe privileges before injecting into product I/O; Windows can skip only
    # the symlink-dependent case while all portable cache assertions still run.
    probe = tmp_path / "symlink-probe"
    symlink_or_skip(directory, probe, target_is_directory=True)
    probe.unlink()
    real_open, real_append = os.open, ledger.append_rows
    swapped = []

    def swap():
        directory.rename(backup)
        symlink_or_skip(backup, directory, target_is_directory=True)
        swapped.append(directory)

    def open_file(file, *args, **kwargs):
        flags = args[0] if args else kwargs.get("flags", os.O_RDONLY)
        if phase == "hit" and not swapped and os.fspath(file) == os.fspath(path) and not flags & (os.O_WRONLY | os.O_RDWR):
            swap()
        return real_open(file, *args, **kwargs)

    def append(root, rows, **kwargs):
        result = real_append(root, rows, **kwargs)
        swap()
        return result

    with monkeypatch.context() as patch:
        patch.setattr(credit_memo, "os", SimpleNamespace(**dict(vars(credit_memo.os), open=open_file)))
        patch.setattr(credit_memo.atomicio, "os", SimpleNamespace(**dict(vars(credit_memo.os), open=open_file)))
        if phase == "fill":
            patch.setattr(ledger, "append_rows", append)
            assert [row["rule"] for row in credit.record_exposure(tmp_path, "host", "session", ["rule-b"])] == ["rule-b"]
        else:
            with pytest.raises(PathTraversalError) as refused:
                credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
            assert refused.value.code == "ERR_PATH_TRAVERSAL"
    assert swapped == [directory]

    if phase == "fill":
        # Restore the real directory before the next lookup, so the lookup itself
        # cannot mask whether the substituted ancestor incorrectly filled a memo.
        directory.unlink()
        backup.rename(directory)
        locks = []
        real_lock = credit.ledger_locked

        def lock(root):
            locks.append(root)
            return real_lock(root)

        monkeypatch.setattr(credit, "ledger_locked", lock)
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-b"]) == []
        assert locks == [tmp_path]


def test_warm_exposure_resolves_the_ledger_site_once(tmp_path, monkeypatch):
    credit.record_exposure(tmp_path, "host", "session", ["rule-a"])
    with _settle_ledger(tmp_path, monkeypatch):
        assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    real_site = storage.ledger_site
    calls = []

    def site(root, create=True):
        calls.append((root, create))
        return real_site(root, create=create)

    monkeypatch.setattr(storage, "ledger_site", site)
    monkeypatch.setattr(ledger, "ledger_site", site)
    assert credit.record_exposure(tmp_path, "host", "session", ["rule-a"]) == []
    assert calls == [(tmp_path, False)]


def test_linked_worktrees_share_one_persistence_memo(tmp_path, monkeypatch):
    home, root, linked = tmp_path / "home", tmp_path / "repo", tmp_path / "linked"
    home.mkdir()
    root.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("GIT_CONFIG_GLOBAL", raising=False)

    def git(*args):
        return subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.com",
                               *args], check=True, capture_output=True, text=True, timeout=30)

    git("init", "-q")
    git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "fixture")
    git("worktree", "add", "--detach", str(linked), "HEAD")
    assert ledger.ledger_path(root) == ledger.ledger_path(linked)
    credit.record_exposure(root, "host", "session", ["rule-a"])
    with _settle_ledger(root, monkeypatch):
        assert credit.record_exposure(root, "host", "session", ["rule-a"]) == []
    calls = []
    real_lock = credit.ledger_locked

    def lock(workspace):
        calls.append(workspace)
        return real_lock(workspace)

    monkeypatch.setattr(credit, "ledger_locked", lock)
    assert credit.record_exposure(linked, "host", "session", ["rule-a"]) == []
    assert [row["rule"] for row in credit.read_rows(linked)] == ["rule-a"]
    assert calls == []


@pytest.fixture(scope="module")
def shared_scan_workspace(tmp_path_factory):
    root = tmp_path_factory.mktemp("shared-scan-workspace")
    rules = root / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    (rules / "trap-scan-cache.md").write_text(
        "---\nid: trap-scan-cache\ntype: trap\ntarget_paths: ['src/*.py']\n"
        "hypothesis: h\nprediction: p\n---\nGuidance\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (root / "home").mkdir()
    return root


@pytest.mark.parametrize("case", ["first", "second"])
def test_shared_workspace_and_session_record_scan_rows_in_each_test(shared_scan_workspace, monkeypatch, case):
    from aegis_core import scan_compliance
    from aegis_mcp.handlers.core import handle_scan

    root = shared_scan_workspace
    monkeypatch.setenv("HOME", str(root / "home"))
    monkeypatch.setenv("USERPROFILE", str(root / "home"))
    monkeypatch.setattr(scan_compliance, "utc_now", lambda: datetime(2026, 11, 10, 12, tzinfo=timezone.utc))
    result = handle_scan({"workspace": str(root), "files": ["src/app.py"],
                          "_host": "claude-code", "_session": "shared-session"})
    assert result.get("status") != "FAIL", result
    assert result["relevant_rules"]
    path = scan_compliance.activity_path(root)
    assert path.exists()
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [(row["event"], row["session"], row["files"]) for row in rows] == [
        ("scan", "shared-session", ["src/app.py"]),
    ]
    path.unlink()
