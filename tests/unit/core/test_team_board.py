"""Board public API: legacy wire parity, refusal atomicity and confined storage."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Event
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_board as core
from aegis_core import team_mailbox_store as storage
from aegis_core.team_mailbox_primitives import BusyError, MailboxRefusal, RoleTables
from aegis_core.workspace.layout import UserLayout
from tools import hierarchy_board as legacy


NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
ROLES = RoleTables(writes={"owner": {"initialize", "configure", "publish", "disposition",
                                      "move_position", "tombstone"},
                          "child": {"publish", "disposition", "move_position"}})
OPTIONS = dict(clock=lambda: NOW, roles=ROLES, hosts={"test-host": object()}, caller_role="owner")
CHANNEL = {"channel": "alpha", "orchestrator": "a/orchestrator", "source": "owner"}
GRANT = {"channel": "alpha", "endpoint": "a/lane/one", "access": "post", "source": "owner"}


@pytest.fixture(autouse=True)
def owner_plane(tmp_path, monkeypatch):
    layout = UserLayout(tmp_path / "owner")
    layout.aegis_dir.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(storage, "pwd", SimpleNamespace(
        getpwuid=lambda uid: SimpleNamespace(pw_dir=str(layout.home))))
    return layout.aegis_dir


def make_store(tmp_path, name="board"):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / name
    core.initialize(root, **OPTIONS)
    with core.Board(root, **OPTIONS) as board:
        board.configure("channel", CHANNEL)
        board.configure("grant", GRANT)
    return root


def post(key="one", **changes):
    return {"channel": "alpha", "key": key, "kind": "note", "body": "hello", **changes}


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def refused(reason):
    return pytest.raises(MailboxRefusal, match="^mailbox refused: " + reason + "$")


def plant_grant_history(root, target):
    """Append exact grant events so a cap test does not depend on the publish rate limit."""
    events = root / "events"
    names = sorted(path.name for path in events.iterdir() if core.EVENT_NAME.fullmatch(path.name))
    seq = int(names[-1][:8])
    raw = (events / names[-1]).read_bytes()
    previous = hashlib.sha256(raw).hexdigest()
    while seq < target:
        seq += 1
        event = {"schema": core.SCHEMA, "seq": seq, "at": "2026-11-16T12:00:00.000000Z", "kind": "grant",
                 "data": {"access": "read", "channel": "alpha", "endpoint": "a/lane/e%06d" % seq,
                          "source": "owner"}, "prev": previous}
        event["digest"] = core.event_digest(event)
        raw = core.encoded(event) + b"\n"
        (events / ("%08d.json" % seq)).write_bytes(raw)
        previous = hashlib.sha256(raw).hexdigest()
    return seq


class WaitClock:
    def __init__(self, after_sleep=lambda: None):
        self.elapsed = 0.0
        self.after_sleep = after_sleep

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        assert seconds > 0
        self.elapsed = round(self.elapsed + seconds, 8)
        self.after_sleep()

    def inject(self, board):
        board.monotonic = self.monotonic
        board.sleep = self.sleep


@pytest.mark.parametrize("case", ["normal", "contended_writer", "pending_event"])
def test_publish_read_retry_and_legacy_wire_parity(tmp_path, monkeypatch, case):
    root = make_store(tmp_path)
    monkeypatch.setattr(legacy, "now_utc", lambda: NOW)
    monkeypatch.setattr(legacy, "timestamp", lambda: "2026-11-16T12:00:00.000000Z")
    old = legacy.Board(tmp_path / "legacy")
    old.initialize()
    with old.lock():
        state = old.load()
        old.append(state, "channel", CHANNEL)
        old.append(state, "grant", GRANT)
    with core.Board(root, **OPTIONS) as board:
        if case == "contended_writer":
            lock, old_lock = (path / ".write.lock" for path in (root, old.path))
            lock.touch()
            old_lock.touch()
            timer = WaitClock(lock.unlink)
            timer.inject(board)
            monkeypatch.setattr(legacy, "time", WaitClock(old_lock.unlink))
        elif case == "pending_event":
            for path in (root, old.path):
                (path / "events" / (".pending-" + "a0" * 16)).write_bytes(b"unfinished event")
            assert board.verify() == old.verify() == {"ok": True, "events": 3, "posts": 0}
        for request in (post(), post("two", kind="blocker"), post("reply", thread="post-00000005")):
            assert board.publish("a/lane/one", request) == old.publish("a/lane/one", request)
        before = snapshot(root)
        assert board.publish("a/lane/one", post())["replayed"] is True
        assert snapshot(root) == before
        assert board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line) == old.read_channel(
            "a/lane/one", {"channel": "alpha"}, legacy.cli_line)
        assert board.verify() == old.verify()
        assert core.digest_text(board, board.load(), "alpha", NOW) == legacy.digest_text(old, old.load(), "alpha", NOW)
    core_files = snapshot(root)
    legacy_files = snapshot(old.path)
    if case == "pending_event":
        # Legacy skips an exact staging name. A core write removes it before the census.
        stale = "events/.pending-" + "a0" * 16
        assert stale not in core_files
        assert legacy_files.pop(stale) == b"unfinished event"
    assert core_files == legacy_files


@pytest.mark.parametrize("changes,reason", [
    ({"body": "x" * 4097}, "too_large"), ({"body": "\ud800"}, "invalid_record"),
    ({"body": "\x1bP" + "AKIA" + "IOSFODNN7EXAMPLE"}, "invalid_record"),
    ({"channel": []}, "invalid_record"), ({"thread": []}, "invalid_record"),
    ({"references": [{}] * 9}, "too_large"), ({"expires_at": []}, "invalid_record"),
    ({"unexpected": 1}, "invalid_record"), ({"kind": []}, "invalid_record"),
    ({"body": ""}, "invalid_record"), ({"key": []}, "invalid_record"),
])
def test_invalid_publish_has_no_effect_and_retry_works(tmp_path, changes, reason):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        before = snapshot(root)
        with refused(reason) as caught:
            board.publish("a/lane/one", post(**changes))
        assert caught.value.as_dict()["next_action"]
        assert snapshot(root) == before
        assert board.publish("a/lane/one", post())["replayed"] is False


def test_busy_is_typed_then_retry_succeeds(tmp_path):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board, storage.Store(root) as peer:
        timer = WaitClock()
        timer.inject(board)
        before = snapshot(root)
        with peer.lock(root):
            with pytest.raises(BusyError) as caught:
                board.publish("a/lane/one", post())
            assert caught.value.reason == "busy"
            assert timer.elapsed == 5.0
        assert snapshot(root) == before
        assert board.publish("a/lane/one", post())["replayed"] is False


def test_release_during_final_poll_is_acquired(tmp_path):
    """A holder that releases as the last poll lands on the deadline is still inside the budget."""
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board, storage.Store(root) as peer:
        held = peer.lock(root)
        held.__enter__()
        released = []

        def release_at_deadline():
            if timer.elapsed >= core.LOCK_WAIT_SECONDS and not released:
                held.__exit__(None, None, None)
                released.append(timer.elapsed)

        timer = WaitClock(release_at_deadline)
        timer.inject(board)
        try:
            result = board.publish("a/lane/one", post())
        finally:
            if not released:
                held.__exit__(None, None, None)
        assert released == [core.LOCK_WAIT_SECONDS]
        assert timer.elapsed == core.LOCK_WAIT_SECONDS
        assert result["seq"] == 4
        assert result["replayed"] is False


def test_busy_at_deadline_raises_without_another_sleep(tmp_path):
    root = make_store(tmp_path)
    samples = iter((0.0, core.LOCK_WAIT_SECONDS))

    def monotonic():
        return next(samples)

    def sleep(seconds):
        raise AssertionError("slept %r after the deadline" % (seconds,))

    with core.Board(root, **OPTIONS) as board, storage.Store(root) as peer:
        board.monotonic = monotonic
        board.sleep = sleep
        before = snapshot(root)
        with peer.lock(root):
            with pytest.raises(BusyError) as caught:
                board.publish("a/lane/one", post())
            assert caught.value.reason == "busy"
        assert snapshot(root) == before


def test_concurrent_same_key_has_one_publication(tmp_path):
    root = make_store(tmp_path)
    entered, release = Event(), Event()

    def write():
        with core.Board(root, **OPTIONS) as board:
            board.writer_guard = guard
            return board.publish("a/lane/one", post())

    @contextmanager
    def guard():
        entered.set()
        assert release.wait(5)
        yield

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(write)
        try:
            assert entered.wait(5)
            with core.Board(root, **OPTIONS) as board, pytest.raises(BusyError):
                WaitClock().inject(board)
                board.publish("a/lane/one", post())
        finally:
            release.set()
        assert future.result(timeout=5)["replayed"] is False
    with core.Board(root, **OPTIONS) as board:
        assert board.publish("a/lane/one", post())["replayed"] is True
        assert board.verify()["posts"] == 1


def test_concurrent_writers_wait_then_publish_in_order(tmp_path):
    root = make_store(tmp_path)
    entered, release = Event(), Event()

    @contextmanager
    def guard():
        entered.set()
        assert release.wait(5)
        yield

    def write():
        with core.Board(root, **OPTIONS) as board:
            board.writer_guard = guard
            return board.publish("a/lane/one", post())

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(write)

        def let_writer_finish():
            release.set()
            first.result(timeout=5)

        timer = WaitClock(let_writer_finish)
        try:
            assert entered.wait(5)
            with core.Board(root, **OPTIONS) as board:
                timer.inject(board)
                second = board.publish("a/lane/one", post("two"))
                assert board.verify() == {"ok": True, "events": 5, "posts": 2}
        finally:
            release.set()
        assert 0 < timer.elapsed < 5.0
        assert second["seq"] == first.result(timeout=5)["seq"] + 1


def test_busy_after_acquisition_is_not_retried(tmp_path):
    root = make_store(tmp_path)

    def blocked_guard():
        raise BusyError()

    with core.Board(root, **OPTIONS) as board:
        timer = WaitClock()
        timer.inject(board)
        before = snapshot(root)
        board.writer_guard = blocked_guard
        with pytest.raises(BusyError):
            board.publish("a/lane/one", post())
        assert timer.elapsed == 0
        assert snapshot(root) == before
    with core.Board(root, **OPTIONS) as board:
        assert board.publish("a/lane/one", post())["replayed"] is False


@pytest.mark.parametrize("name", [".pending-x", ".pending-" + "A" * 32, ".pending-" + "1" * 33])
def test_malformed_pending_name_refuses_load_and_write(tmp_path, name):
    root = make_store(tmp_path)
    pending = root / "events" / name
    pending.write_bytes(b"unfinished event")
    before = snapshot(root)
    with core.Board(root, **OPTIONS) as board:
        with refused("invalid_record"):
            board.verify()
        with refused("invalid_record"):
            board.publish("a/lane/one", post())
        assert snapshot(root) == before
        pending.unlink()
        assert board.publish("a/lane/one", post())["seq"] == 4


def test_stale_staging_file_does_not_consume_event_cap(tmp_path):
    """9,999 committed events plus one nlink-1 staging name still accept event 10,000."""
    assert core.MAX_RECORDS == 10000
    root = make_store(tmp_path)
    assert plant_grant_history(root, core.MAX_RECORDS - 1) == core.MAX_RECORDS - 1
    pending = root / "events" / (".pending-" + "ab" * 16)
    pending.write_bytes(b"killed before link")
    assert pending.is_file() and pending.stat().st_nlink == 1
    with core.Board(root, **OPTIONS) as board:
        assert board.verify() == {"ok": True, "events": core.MAX_RECORDS - 1, "posts": 0}
        assert pending.is_file()
        sent = board.publish("a/lane/one", post())
        assert sent["seq"] == core.MAX_RECORDS
        assert sent["replayed"] is False
        assert not pending.exists()
        assert (root / "events" / ("%08d.json" % core.MAX_RECORDS)).is_file()
        assert not list((root / "events").glob(".pending-*"))
        with refused("too_large"):
            board.publish("a/lane/one", post("past"))
        assert board.verify() == {"ok": True, "events": core.MAX_RECORDS, "posts": 1}
        assert not (root / "events" / ("%08d.json" % (core.MAX_RECORDS + 1))).exists()


def test_every_exact_stale_staging_name_is_reaped_on_write(tmp_path):
    root = make_store(tmp_path)
    events = root / "events"
    pending = []
    for token in ("ab", "cd"):
        path = events / (".pending-" + token * 16)
        path.write_bytes(b"killed before link")
        pending.append(path)
    with core.Board(root, **OPTIONS) as board:
        assert board.verify() == {"ok": True, "events": 3, "posts": 0}
        assert all(path.is_file() for path in pending)
        assert board.publish("a/lane/one", post())["seq"] == 4
        assert all(not path.exists() for path in pending)


def test_stale_staging_unlink_failure_is_typed(tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permissions required")
    root = make_store(tmp_path)
    events = root / "events"
    pending = events / (".pending-" + "ef" * 16)
    pending.write_bytes(b"killed before link")
    events.chmod(0o500)
    try:
        with core.Board(root, **OPTIONS) as board:
            before = snapshot(root)
            with refused("io") as caught:
                board.publish("a/lane/one", post())
            assert pending.name not in str(caught.value)
            assert snapshot(root) == before
    finally:
        events.chmod(0o700)
    assert pending.is_file()


def test_disposition_cursor_tombstone_and_authority(tmp_path):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", post(kind="blocker"))
        identifier = sent["post_id"]
        assert board.disposition("a/orchestrator", {"post_id": identifier, "state": "resolved"})["open"] is False
        assert board.disposition("a/lane/one", {"post_id": identifier, "state": "reopened"})["open"] is True
        page, moved = board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line)
        assert page["posts"][0]["post_id"] == identifier
        assert board.position("a/lane/one", "alpha") == 0
        board.move_position("a/lane/one", *moved)
        board.move_position("a/lane/one", *moved)
        assert board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line)[0]["posts"] == []
        board.tombstone({"post_id": identifier, "reason": "remove", "source": "owner"})
        assert not (root / "content" / (identifier + ".json")).exists()
        assert board.verify()["posts"] == 1
    with core.Board(root, **{**OPTIONS, "caller_role": "child"}) as board:
        before = snapshot(root)
        with refused("unauthorized"):
            board.configure("revoke", {"channel": "alpha", "endpoint": "a/lane/one", "source": "child"})
        assert snapshot(root) == before


@pytest.mark.parametrize("target", ["events", "content", "positions"])
def test_symlink_component_is_refused_without_touching_target(tmp_path, target):
    root = make_store(tmp_path)
    outside = tmp_path / "outside"
    with core.Board(root, **OPTIONS) as board:
        board.publish("a/lane/one", post())
        (root / target).rename(outside)
        symlink_or_skip(outside, root / target, target_is_directory=True)
        before = snapshot(outside)
        with refused("unsafe_path"):
            if target == "positions":
                board.position("a/lane/one", "alpha")
            else:
                board.verify()
        assert snapshot(outside) == before


def test_root_rename_cannot_redirect_existing_board(tmp_path):
    root = make_store(tmp_path)
    replacement = make_store(tmp_path, "replacement")
    with core.Board(root, **OPTIONS) as board:
        moved = tmp_path / "moved"
        root.rename(moved)
        replacement.rename(root)
        before = snapshot(root)
        board.publish("a/lane/one", post())
        assert snapshot(root) == before
        assert len(list((moved / "content").iterdir())) == 1


@pytest.mark.parametrize("spelling", ["native", "windows"])
def test_unsupported_platform_is_typed_and_has_no_effect(tmp_path, monkeypatch, spelling):
    root = tmp_path / "board" if spelling == "native" else "C:\\board"
    monkeypatch.setattr(storage, "descriptor_supported", lambda: False)
    with refused("unsupported_platform"):
        core.initialize(root, **OPTIONS)
    with refused("unsupported_platform"):
        core.Board(root, **OPTIONS)
    assert not (tmp_path / "board").exists()


@pytest.mark.parametrize("damage", ["unknown", "malformed", "oversized", "sequence", "content", "disposition"])
def test_damaged_history_is_refused_before_write(tmp_path, damage):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", post())
    path = sorted((root / "events").iterdir())[-1]
    event = json.loads(path.read_bytes())
    reason = "invalid_record"
    if damage == "unknown":
        event["kind"] = "unknown"
    elif damage == "sequence":
        event["seq"] = True
    elif damage == "disposition":
        event["kind"] = "disposition"
        event["data"] = {"post_id": sent["post_id"], "state": [], "from": "a/lane/one"}
    elif damage == "content":
        (root / "content" / (sent["post_id"] + ".json")).write_bytes(b'{}')
    elif damage == "oversized":
        path.write_bytes(b" " * (core.MAX_BYTES + 1))
        reason = "too_large"
    elif damage == "malformed":
        path.write_bytes(b'{"kind":')
    if damage in {"unknown", "sequence", "disposition"}:
        event["digest"] = core.event_digest(event)
        path.write_bytes(core.encoded(event) + b"\n")
    before = snapshot(root)
    with core.Board(root, **OPTIONS) as board, refused(reason):
        board.publish("a/lane/one", post("two"))
    assert snapshot(root) == before


def test_publication_failure_rolls_back_content_and_allows_retry(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        publish = storage.Store.publish

        def fail_event(store, path, raw, **kwargs):
            if path.parent.name == "events":
                raise OSError("private storage diagnostic")
            return publish(store, path, raw, **kwargs)

        before = snapshot(root)
        monkeypatch.setattr(storage.Store, "publish", fail_event)
        with refused("io"):
            board.publish("a/lane/one", post())
        monkeypatch.setattr(storage.Store, "publish", publish)
        assert snapshot(root) == before
        assert board.publish("a/lane/one", post())["replayed"] is False


def test_bounded_pages_match_legacy_and_references_are_validated(tmp_path):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        for number in range(12):
            board.publish("a/lane/one", post("p%d" % number, body="x" * 4096,
                          references=[{"kind": "file", "value": "src/a.py"}]))
        page, _ = board.read_channel("a/lane/one", {"channel": "alpha", "limit": 50}, legacy.cli_line)
        assert len(legacy.cli_line(page)) <= core.MAX_PAGE_BYTES
        assert 0 < len(page["posts"]) < 12
        assert page["remaining"] == 12 - len(page["posts"])


def test_retained_legacy_initialization_needs_no_new_core_dependency(tmp_path):
    repository = Path(__file__).resolve().parents[3]
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("hierarchy_board.py", "hierarchy_mailbox.py"):
        (tools / name).write_bytes((repository / "tools" / name).read_bytes())
    root = tmp_path / "legacy"
    result = subprocess.run([sys.executable, "-I", "-S", str(tools / "hierarchy_board.py"),
                             "--board", str(root), "init"], capture_output=True, text=True, timeout=15)
    assert result.stderr == ""
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"board": str(root)}


def test_legacy_fdopen_failure_closes_descriptor(tmp_path, monkeypatch):
    board = legacy.Board(tmp_path / "legacy")
    board.initialize()
    opened = []

    def fail_wrap(fd, *args, **kwargs):
        opened.append(fd)
        raise OSError("wrapper unavailable")

    proxy = SimpleNamespace(**{**vars(os), "fdopen": fail_wrap})
    monkeypatch.setattr(legacy, "os", proxy)
    with pytest.raises(OSError, match="^wrapper unavailable$"):
        with board.lock():
            pytest.fail("failed wrapper was admitted")
    assert len(opened) == 1
    with pytest.raises(OSError) as caught:
        os.fstat(opened[0])
    assert caught.value.errno == errno.EBADF
    assert not (board.path / ".write.lock").exists()
    monkeypatch.setattr(legacy, "os", os)
    with board.lock():
        assert (board.path / ".write.lock").exists()
    assert not (board.path / ".write.lock").exists()


def test_response_failure_rolls_back_event_and_content(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        before = snapshot(root)
        view = core.Board.view

        def fail_view(*args, **kwargs):
            raise OSError("private response failure")

        monkeypatch.setattr(core.Board, "view", fail_view)
        with refused("io"):
            board.publish("a/lane/one", post())
        monkeypatch.setattr(core.Board, "view", view)
        assert snapshot(root) == before
        board.publish("a/lane/one", post())


def test_one_operation_uses_one_injected_clock_observation(tmp_path):
    root = make_store(tmp_path)
    moments = []

    def clock():
        moments.append(NOW)
        return NOW

    with core.Board(root, **{**OPTIONS, "clock": clock}) as board:
        board.publish("a/lane/one", post())
    assert moments == [NOW]


def test_tombstone_failure_is_atomic_and_retry_succeeds(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", post())
        request = {"post_id": sent["post_id"], "reason": "remove", "source": "owner"}
        before = snapshot(root)

        def fail_unlink(*args, **kwargs):
            raise OSError("private deletion failure")

        proxy = SimpleNamespace(**{**vars(os), "unlink": fail_unlink})
        monkeypatch.setattr(core, "os", proxy)
        with refused("io"):
            board.tombstone(request)
        monkeypatch.setattr(core, "os", os)
        assert snapshot(root) == before
        assert board.tombstone(request) == board.tombstone(request)


@pytest.mark.parametrize("operation", ["position", "move_position", "read_thread", "call"])
def test_malformed_public_arguments_are_typed(tmp_path, operation):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        before = snapshot(root)
        with refused("invalid_record"):
            if operation == "position":
                board.position([], "alpha")
            elif operation == "move_position":
                board.move_position([], "alpha", 0)
            elif operation == "read_thread":
                board.read_thread("a/lane/one", {"post_id": []}, legacy.cli_line)
            else:
                board.call("a/lane/one", [], {}, legacy.cli_line)
        assert snapshot(root) == before


def test_initialization_failure_closes_descriptors_and_retry_succeeds(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / "new-board"
    opened = set()

    def tracking_open(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.add(fd)
        return fd

    def tracking_dup(fd):
        copied = os.dup(fd)
        opened.add(copied)
        return copied

    def tracking_close(fd):
        os.close(fd)
        opened.discard(fd)

    def fail_write(*args, **kwargs):
        raise OSError("private write failure")

    proxy = SimpleNamespace(**{**vars(os), "open": tracking_open, "dup": tracking_dup,
                               "close": tracking_close, "write": fail_write})
    monkeypatch.setattr(storage, "os", proxy)
    with refused("io"):
        core.initialize(root, **OPTIONS)
    monkeypatch.setattr(storage, "os", os)
    assert not opened
    assert not root.exists()
    core.initialize(root, **OPTIONS)
    with core.Board(root, **OPTIONS) as board:
        assert board.verify() == {"ok": True, "events": 1, "posts": 0}
    before = snapshot(root)
    with refused("exists"):
        core.initialize(root, **OPTIONS)
    assert snapshot(root) == before


def test_component_rename_during_publication_uses_held_descriptors(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        publish = storage.Store.publish
        detached = tmp_path / "detached"

        def rename_then_publish(store, path, raw, **kwargs):
            if path.parent == board.content:
                board.content.rename(detached)
                board.content.mkdir(mode=0o700)
                (board.content / path.name).write_bytes(b"untouched")
            return publish(store, path, raw, **kwargs)

        monkeypatch.setattr(storage.Store, "publish", rename_then_publish)
        result = board.publish("a/lane/one", post())
        assert result["body"] == "hello"
        assert (board.content / (result["post_id"] + ".json")).read_bytes() == b"untouched"
        assert json.loads((detached / (result["post_id"] + ".json")).read_bytes())["body"] == "hello"


def test_thread_disposition_revoke_and_clock_rate_window(tmp_path):
    root = make_store(tmp_path)
    moment = [NOW]
    with core.Board(root, **{**OPTIONS, "clock": lambda: moment[0]}) as board:
        first = board.publish("a/lane/one", post(kind="blocker"))
        reply = board.publish("a/lane/one", post("reply", thread=first["post_id"]))
        page, moved = board.call("a/lane/one", "board_read_thread", {"post_id": reply["post_id"]}, legacy.cli_line)
        assert [p["post_id"] for p in page["posts"]] == [first["post_id"], reply["post_id"]]
        assert moved is None
        for number in range(core.RATE_LIMIT_ACTIONS - 2):
            board.publish("a/lane/one", post("rate%d" % number))
        before = snapshot(root)
        with refused("invalid_record"):
            board.publish("a/lane/one", post("next"))
        assert snapshot(root) == before
        from datetime import timedelta
        moment[0] += timedelta(seconds=core.RATE_WINDOW_SECONDS + 1)
        board.publish("a/lane/one", post("next"))
        board.configure("revoke", {"channel": "alpha", "endpoint": "a/lane/one", "source": "owner"})
        before = snapshot(root)
        with refused("invalid_record"):
            board.read_thread("a/lane/one", {"post_id": reply["post_id"]}, legacy.cli_line)
        assert snapshot(root) == before


@pytest.mark.parametrize("damage,reason", [("missing", "missing"), ("mode", "unsafe_path"),
                                          ("hardlink", "unsafe_path"), ("cursor", "invalid_record")])
def test_storage_damage_is_typed_and_has_no_effect(tmp_path, damage, reason):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", post())
        content = root / "content" / (sent["post_id"] + ".json")
        if damage == "missing":
            content.unlink()
        elif damage == "mode":
            if os.name != "posix":
                pytest.skip("POSIX permissions required")
            (root / "content").chmod(0o777)
        elif damage == "hardlink":
            os.link(content, tmp_path / "alias")
        else:
            board.move_position("a/lane/one", "alpha", sent["seq"])
            board.position_path("a/lane/one", "alpha").write_bytes(b'{"seq":true,"at":"2026-11-16T12:00:00Z"}')
        before = snapshot(root)
        with refused(reason):
            board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line)
        assert snapshot(root) == before


def test_history_limit_refuses_before_content_publication(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    monkeypatch.setattr(core, "MAX_RECORDS", 3)
    with core.Board(root, **OPTIONS) as board:
        before = snapshot(root)
        with refused("too_large"):
            board.publish("a/lane/one", post())
        assert snapshot(root) == before


def test_cursor_replacement_failure_and_success_cleanup(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", post())
        before = snapshot(root)

        def fail_replace(*args, **kwargs):
            raise OSError("private replacement failure")

        proxy = SimpleNamespace(**{**vars(os), "replace": fail_replace})
        monkeypatch.setattr(core, "os", proxy)
        with refused("io"):
            board.move_position("a/lane/one", "alpha", sent["seq"])
        assert snapshot(root) == before

        def fail_unlink(*args, **kwargs):
            raise OSError("a consumed temporary must not be unlinked")

        proxy = SimpleNamespace(**{**vars(os), "unlink": fail_unlink})
        monkeypatch.setattr(core, "os", proxy)
        board.move_position("a/lane/one", "alpha", sent["seq"])
        monkeypatch.setattr(core, "os", os)
        assert board.position("a/lane/one", "alpha") == sent["seq"]


def secret_value(shape):
    token = "AKIA" + "IOSFODNN7EXAMPLE"
    if shape in ("prefix81", "prefix100"):
        return "x" * int(shape[6:]) + " " + token
    if shape == "pem_begin_newline":
        return "-----BEGIN\nPRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    if shape == "pem_header_run":
        return "memo -----BEGIN \t\nPRIVATE \t\nKEY-----\nabc\n-----END PRIVATE KEY-----"
    header = {"pem_begin_tab": "-----BEGIN\tPRIVATE KEY-----",
              "pem_key_tab": "-----BEGIN PRIVATE\tKEY-----"}[shape]
    return "memo " + header + "\nQUJDRA=="


def poison_record(root, site, value):
    path = sorted((root / "events").iterdir())[-1]
    event = json.loads(path.read_bytes())
    changed = {path: path.read_bytes()}
    if site in ("stored_body", "stored_reference", "stored_description"):
        content = root / "content" / (event["data"]["post_id"] + ".json")
        changed[content] = content.read_bytes()
        payload = json.loads(content.read_bytes())
        if site == "stored_body":
            payload["body"] = value
        else:
            reference = {"kind": "file", "value": value if site == "stored_reference" else "file.py"}
            if site == "stored_description":
                reference["description"] = value
            payload["references"] = [reference]
        raw = core.encoded(payload)
        content.write_bytes(raw)
        event["data"]["content_sha256"] = hashlib.sha256(raw).hexdigest()
    else:
        event["data"]["note" if site == "stored_note" else "reason"] = value
    event["digest"] = core.event_digest(event)
    path.write_bytes(core.encoded(event) + b"\n")
    return changed


@pytest.mark.parametrize("shape", ["prefix81", "prefix100", "pem_begin_tab", "pem_key_tab",
                                  "pem_begin_newline", "pem_header_run"])
@pytest.mark.parametrize("site", ["body", "reference", "description", "note", "reason",
                                  "stored_body", "stored_reference", "stored_description", "stored_note", "stored_reason"])
def test_complete_secret_scan_at_every_public_validation_site(tmp_path, site, shape):
    root = make_store(tmp_path)
    value = secret_value(shape)
    with core.Board(root, **OPTIONS) as board:
        blocker = board.publish("a/lane/one", post(kind="blocker"))
        identifier = blocker["post_id"]
        if site == "stored_note":
            board.disposition("a/lane/one", {"post_id": identifier, "state": "resolved", "note": "done"})
        elif site == "stored_reason":
            board.tombstone({"post_id": identifier, "reason": "remove", "source": "owner"})
        changed = poison_record(root, site, value) if site.startswith("stored_") else {}
        before = snapshot(root)
        for attempt in range(2):
            with refused("invalid_record") as caught:
                if changed:
                    board.verify()
                elif site == "body":
                    board.publish("a/lane/one", post("secret", body=value))
                elif site in ("reference", "description"):
                    reference = {"kind": "file", "value": value if site == "reference" else "file.py"}
                    if site == "description":
                        reference["description"] = value
                    board.publish("a/lane/one", post("secret", references=[reference]))
                elif site == "note":
                    board.disposition("a/lane/one", {"post_id": identifier, "state": "resolved", "note": value})
                else:
                    board.tombstone({"post_id": identifier, "reason": value, "source": "owner"})
            assert caught.value.code == 1
            assert value not in str(caught.value.as_dict())
            assert snapshot(root) == before
        for path, raw in changed.items():
            path.write_bytes(raw)
        assert board.verify()["ok"] is True
        board.publish("a/lane/one", post("safe-retry"))


@pytest.mark.parametrize("body", ["memo ab 12 cd 34", "memo ab\t12\ncd 34",
                                 "token budget: 1000", "secret scan: fixed",
                                 "memo " + "ab 12 " * 680])
def test_benign_prose_preserves_the_original_wire_text(tmp_path, body):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        request = post(body=body, kind="blocker", references=[{"kind": "file", "value": "memo ab 12",
                                                              "description": "memo cd 34"}])
        sent = board.publish("a/lane/one", request)
        assert sent["body"] == body
        assert board.publish("a/lane/one", request)["replayed"] is True
        page, _ = board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line)
        assert page["posts"][0]["body"] == body
        board.disposition("a/lane/one", {"post_id": sent["post_id"], "state": "resolved", "note": "memo ab\t12 cd\n34"})
        removal = {"post_id": sent["post_id"], "reason": "memo ab\t12 cd\n34", "source": "owner"}
        assert board.tombstone(removal) == board.tombstone(removal)
        assert board.verify()["ok"] is True


@pytest.mark.parametrize("size", [core.MAX_BODY_BYTES // 2, core.MAX_BODY_BYTES])
def test_dense_punctuation_has_bounded_secret_scans_on_publish_retry_and_replay(tmp_path, monkeypatch, size):
    root = make_store(tmp_path)
    patterns = core.SECRET_REPLACEMENTS
    work = {"scans": 0, "characters": 0}

    def observed(pattern):
        def search(value):
            work["scans"] += 1
            work["characters"] += len(value)
            return pattern.search(value)
        return SimpleNamespace(search=search)

    monkeypatch.setattr(core, "SECRET_REPLACEMENTS", [(observed(pattern), replacement)
                                                     for pattern, replacement in patterns])
    request = post(body="." * size)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", request)
        assert sent["body"] == request["body"]
        assert 0 < work["scans"] <= 4 * len(patterns)
        assert work["characters"] <= 4 * len(patterns) * size
        work.update(scans=0, characters=0)
        assert board.publish("a/lane/one", request)["replayed"] is True
        assert 0 < work["scans"] <= 6 * len(patterns)
        assert work["characters"] <= 6 * len(patterns) * size
        work.update(scans=0, characters=0)
        assert board.verify()["ok"] is True
        assert 0 < work["scans"] <= 2 * len(patterns)
        assert work["characters"] <= 2 * len(patterns) * size


def test_oversized_body_refuses_before_secret_scans(tmp_path, monkeypatch):
    root = make_store(tmp_path)

    def unexpected_scan(value):
        pytest.fail("oversized body reached secret scanning")

    monkeypatch.setattr(core, "SECRET_REPLACEMENTS", [(SimpleNamespace(search=unexpected_scan), "unused")])
    with core.Board(root, **OPTIONS) as board:
        before = snapshot(root)
        with refused("too_large") as caught:
            board.publish("a/lane/one", post(body="." * (core.MAX_BODY_BYTES + 1)))
        assert caught.value.code == 1
        assert snapshot(root) == before


@pytest.mark.parametrize("endpoint,channel", [
    ("a/lane/x--y", "z"), ("a/lane/x", "y--z"),
    ("a" * 80 + "/lane/" + "b" * 80, "c" * 80),
])
@pytest.mark.parametrize("operation", ["position", "move_position", "read_channel", "call"])
def test_ambiguous_or_long_cursor_pair_refuses_before_storage(tmp_path, monkeypatch, endpoint, channel, operation):
    root = make_store(tmp_path)
    reads = []
    with core.Board(root, **OPTIONS) as board:
        read = storage.Store.read
        directory = storage.Store.directory

        def observe_read(store, *args, **kwargs):
            reads.append("read")
            return read(store, *args, **kwargs)

        def observe_directory(store, *args, **kwargs):
            reads.append("directory")
            return directory(store, *args, **kwargs)

        monkeypatch.setattr(storage.Store, "read", observe_read)
        monkeypatch.setattr(storage.Store, "directory", observe_directory)
        before = snapshot(root)
        with refused("unsafe_path"):
            if operation == "position":
                board.position(endpoint, channel)
            elif operation == "move_position":
                board.move_position(endpoint, channel, 0)
            elif operation == "read_channel":
                board.read_channel(endpoint, {"channel": channel}, legacy.cli_line)
            else:
                board.call(endpoint, "board_read_channel", {"channel": channel}, legacy.cli_line)
        assert reads == []
        assert snapshot(root) == before
        monkeypatch.setattr(storage.Store, "read", read)
        monkeypatch.setattr(storage.Store, "directory", directory)
        assert board.position("a/lane/one", "alpha") == 0


@pytest.mark.parametrize("lock_name", [".write.lock", "team-mailbox-evidence.lock"])
@pytest.mark.parametrize("operation", ["publish", "configure", "disposition", "move_position", "tombstone"])
def test_committed_operations_report_release_warnings(tmp_path, monkeypatch, owner_plane, lock_name, operation):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        WaitClock().inject(board)
        sent = board.publish("a/lane/one", post(kind="blocker"))

        def fail_release(name, *args, **kwargs):
            if name == lock_name:
                raise OSError("private release failure")
            return os.unlink(name, *args, **kwargs)

        proxy = SimpleNamespace(**{**vars(os), "unlink": fail_release})
        monkeypatch.setattr(storage, "os", proxy)
        if operation == "publish":
            result = board.publish("a/lane/one", post("committed"))
        elif operation == "configure":
            result = board.configure("grant", {**GRANT, "access": "read"})
        elif operation == "disposition":
            result = board.disposition("a/lane/one", {"post_id": sent["post_id"], "state": "resolved"})
        elif operation == "move_position":
            result = board.move_position("a/lane/one", "alpha", sent["seq"])
        else:
            result = board.tombstone({"post_id": sent["post_id"], "reason": "remove", "source": "owner"})
        monkeypatch.setattr(storage, "os", os)
        assert isinstance(result, dict)
        warnings = result["warnings"]
        assert len(warnings) == 1
        assert warnings[0]["reason"] == "lock_release" and warnings[0]["code"] == 0
        assert warnings[0]["lock_path"].endswith("/" + lock_name)
        assert warnings[0]["lock_path"] in warnings[0]["next_action"]
        with pytest.raises(BusyError):
            board.publish("a/orchestrator", post("after"))
        (root / lock_name if lock_name == ".write.lock" else owner_plane / lock_name).unlink()
        assert board.verify()["ok"] is True
        retry = board.publish("a/orchestrator", post("after"))
        assert "warnings" not in retry


def test_initialize_reports_owner_release_warning(tmp_path, monkeypatch, owner_plane):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / "new"

    def fail_release(name, *args, **kwargs):
        if name == "team-mailbox-evidence.lock":
            raise OSError("private release failure")
        return os.unlink(name, *args, **kwargs)

    proxy = SimpleNamespace(**{**vars(os), "unlink": fail_release})
    monkeypatch.setattr(storage, "os", proxy)
    result = core.initialize(root, **OPTIONS)
    monkeypatch.setattr(storage, "os", os)
    assert len(result["warnings"]) == 1
    assert result["warnings"][0]["lock_path"].endswith("/team-mailbox-evidence.lock")
    assert result["warnings"][0]["lock_path"] in result["warnings"][0]["next_action"]
    (owner_plane / "team-mailbox-evidence.lock").unlink()
    with core.Board(root, **OPTIONS) as board:
        assert board.verify()["ok"] is True


def test_initialize_allows_foreign_grandparent(tmp_path, monkeypatch):
    make_store(tmp_path)
    parent = tmp_path / "selected-parent"
    parent.mkdir(mode=0o700)
    grandparent = tmp_path.stat()

    def foreign_grandparent(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (grandparent.st_dev, grandparent.st_ino):
            return os.stat_result((*info[:4], os.geteuid() + 1, *info[5:]))
        return info

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "fstat": foreign_grandparent}))
    root = parent / "board"
    assert set(core.initialize(root, **OPTIONS)) == {"board"}
    with core.Board(root, **OPTIONS) as board:
        assert board.verify() == {"ok": True, "events": 1, "posts": 0}


@pytest.mark.parametrize("damage", ["foreign", "group_writable", "world_writable", "replaced"])
def test_initialize_refuses_unsafe_parent_and_retries(tmp_path, monkeypatch, damage):
    make_store(tmp_path)
    parent = tmp_path / "selected-parent"
    parent.mkdir(mode=0o700)
    identity = parent.stat()
    replaced = []

    def parent_info(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            if damage == "foreign":
                return os.stat_result((*info[:4], os.geteuid() + 1, *info[5:]))
            if damage == "replaced" and not replaced:
                replaced.append(True)
                parent.rename(tmp_path / "saved-parent")
                parent.mkdir(mode=0o700)
        return info

    if damage.endswith("writable"):
        parent.chmod(0o720 if damage == "group_writable" else 0o702)
    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "fstat": parent_info}))
    with refused("unsafe_path"):
        core.initialize(parent / "board", **OPTIONS)
    monkeypatch.setattr(storage, "os", os)
    assert list(parent.iterdir()) == []
    if replaced:
        assert list((tmp_path / "saved-parent").iterdir()) == []
    parent.chmod(0o700)
    core.initialize(parent / "board", **OPTIONS)
    with core.Board(parent / "board", **OPTIONS) as board:
        assert board.verify()["events"] == 1


@pytest.mark.parametrize("failure", ["mkdir", "open", "link"])
def test_parent_initialization_failure_closes_and_rolls_back(tmp_path, monkeypatch, failure):
    make_store(tmp_path)
    root = tmp_path / "candidate"
    opened = set()

    def tracking_open(path, *args, **kwargs):
        if failure == "open" and path == root.name:
            raise OSError(errno.EIO, "private open failure")
        fd = os.open(path, *args, **kwargs)
        opened.add(fd)
        return fd

    def tracking_dup(fd):
        result = os.dup(fd)
        opened.add(result)
        return result

    def tracking_close(fd):
        os.close(fd)
        opened.remove(fd)

    def mkdir(path, *args, **kwargs):
        if failure == "mkdir" and path == root.name:
            raise OSError(errno.EIO, "private mkdir failure")
        return os.mkdir(path, *args, **kwargs)

    def link(*args, **kwargs):
        if failure == "link":
            raise OSError(errno.EIO, "private publication failure")
        return os.link(*args, **kwargs)

    proxy = SimpleNamespace(**{**vars(os), "open": tracking_open, "dup": tracking_dup,
                               "close": tracking_close, "mkdir": mkdir, "link": link})
    monkeypatch.setattr(storage, "os", proxy)
    with refused("io"):
        core.initialize(root, **OPTIONS)
    monkeypatch.setattr(storage, "os", os)
    assert opened == set()
    assert not root.exists()
    core.initialize(root, **OPTIONS)
    with core.Board(root, **OPTIONS) as board:
        assert board.verify()["events"] == 1


@pytest.mark.parametrize("same_root", [True, False])
def test_concurrent_initialization_refuses_then_retries(tmp_path, monkeypatch, same_root):
    make_store(tmp_path)
    root = tmp_path / "candidate"
    contender = root if same_root else tmp_path / "peer"
    entered, release = Event(), Event()

    def mkdir(path, *args, **kwargs):
        if path == root.name:
            entered.set()
            assert release.wait(5)
        return os.mkdir(path, *args, **kwargs)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "mkdir": mkdir}))
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(core.initialize, root, **OPTIONS)
        try:
            assert entered.wait(5)
            with pytest.raises(BusyError) as caught:
                core.initialize(contender, **OPTIONS)
            assert caught.value.reason == "busy"
        finally:
            release.set()
        assert set(future.result(timeout=5)) == {"board"}
    if same_root:
        with refused("exists"):
            core.initialize(contender, **OPTIONS)
    else:
        assert set(core.initialize(contender, **OPTIONS)) == {"board"}
    with core.Board(contender, **OPTIONS) as board:
        assert board.verify()["events"] == 1


@pytest.mark.parametrize("operation", ["read", "acknowledge", "position"])
def test_cursor_operations_replay_history_once(tmp_path, monkeypatch, operation):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", post())
        count = []
        read = storage.Store.read

        def count_events(store, path, **kwargs):
            if path.parent == root / "events":
                count.append(path.name)
            return read(store, path, **kwargs)

        monkeypatch.setattr(storage.Store, "read", count_events)
        if operation == "read":
            board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line)
        elif operation == "acknowledge":
            board.move_position("a/lane/one", "alpha", sent["seq"])
        else:
            board.position("a/lane/one", "alpha")
        assert count == sorted(path.name for path in (root / "events").iterdir())


def test_cursor_format_still_interoperates_with_legacy(tmp_path):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board:
        sent = board.publish("a/lane/one", post())
        board.move_position("a/lane/one", "alpha", sent["seq"])
        old = legacy.Board(root)
        assert board.position_path("a/lane/one", "alpha") == old.position_path("a/lane/one", "alpha")
        assert old.position("a/lane/one", "alpha") == sent["seq"]
        second = board.publish("a/lane/one", post("second"))
        old.move_position("a/lane/one", "alpha", second["seq"])
        assert board.position("a/lane/one", "alpha") == second["seq"]


def test_cursor_ambiguity_precedes_a_contended_writer_lock(tmp_path):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board, storage.Store(root) as peer:
        with peer.lock(root):
            before = snapshot(root)
            with refused("unsafe_path"):
                board.move_position("a/lane/x--y", "z", 0)
            assert snapshot(root) == before
        assert board.position("a/lane/one", "alpha") == 0


@pytest.mark.parametrize("shape", ["prefix100", "pem_begin_tab", "pem_key_tab", "pem_begin_newline"])
def test_secret_retry_after_competing_writer_release(tmp_path, shape):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board, storage.Store(root) as peer:
        WaitClock().inject(board)
        with peer.lock(root):
            before = snapshot(root)
            with pytest.raises(BusyError):
                board.publish("a/lane/one", post(body=secret_value(shape)))
            assert snapshot(root) == before
        before = snapshot(root)
        with refused("invalid_record"):
            board.publish("a/lane/one", post(body=secret_value(shape)))
        assert snapshot(root) == before
        board.publish("a/lane/one", post())


def test_read_snapshot_replays_once_while_another_writer_appends(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with core.Board(root, **OPTIONS) as board, core.Board(root, **OPTIONS) as peer:
        sent = board.publish("a/lane/one", post())
        history = sorted(path.name for path in (root / "events").iterdir())
        read = storage.Store.read
        observed = []
        injected = []

        def append_during_read(store, path, **kwargs):
            if store is board.store and path.parent == root / "events":
                observed.append(path.name)
                if not injected:
                    injected.append(True)
                    peer.publish("a/lane/one", post("concurrent"))
            return read(store, path, **kwargs)

        monkeypatch.setattr(storage.Store, "read", append_during_read)
        page, _ = board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line)
        assert observed == history
        assert [p["post_id"] for p in page["posts"]] == [sent["post_id"]]
        monkeypatch.setattr(storage.Store, "read", read)
        assert len(board.read_channel("a/lane/one", {"channel": "alpha"}, legacy.cli_line)[0]["posts"]) == 2
