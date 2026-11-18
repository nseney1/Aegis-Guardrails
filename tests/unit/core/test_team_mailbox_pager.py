"""Pure pager parity, post-flush state and bounded untrusted inputs."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from types import SimpleNamespace

import pytest

from aegis_core import team_mailbox_pager as core
from aegis_core.team_mailbox_primitives import MailboxRefusal, encoded
from tools import hierarchy_mailbox_pager as legacy
from tests.unit.core.test_team_mailbox import (  # noqa: F401
    populated, request, owner_plane,
)


def state(p):
    return deepcopy((p.session, p.briefs_session, p.offered, p.pending,
                     p.cutoffs, p.cursors, p.retained_cursor_pairs))


NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
SNAPSHOT = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "session",
            "generation": 1, "checkpoint_sha256": None, "created_at": "2026-11-16T12:00:00.000000Z",
            "checkpoint": None}


def records(count=5):
    return [{"path": "/mail/" + str(i) + ".md", "message": {
        "message_id": "m" + str(i), "to": "alpha/orchestrator", "from": "alpha/front-door",
        "created_at": SNAPSHOT["created_at"], "type": "info", "body": "hello"}} for i in range(count)]


def pager(module=core):
    return module.InboxPager(clock=lambda: NOW, brief_dedupe_max_bytes=10000,
                            since_clock_skew_seconds=30, capacity_error="capacity")


def page(p, arguments=None, rows=None, after=None):
    return p.page(p.prepare(arguments or {}), snapshot=SNAPSHOT, ready=True,
                  records=records() if rows is None else rows, limit=2, after=after,
                  read_brief=lambda ref: b"brief", brief_status=lambda ref: ref, slimming=True)


@pytest.mark.parametrize("options", [{}, {"order": "newest"}, {"since": "current_generation"},
    {"order": "newest", "since": "current_generation"}, {"include_briefs": True}])
def test_page_flush_retry_and_drain_parity(options):
    left, right = pager(), pager(legacy)
    cursor = None
    for _ in range(3):
        a, b = page(left, options, after=cursor), page(right, options, after=cursor)
        assert a == b
        for p, value in ((left, a), (right, b)):
            p.stage(value, len(encoded(value)), max_cursor_pairs=4)
            assert p.pending is not None
            p.commit()
            p.commit()
        assert left.cursors == right.cursors
        assert left.retained_cursor_pairs == right.retained_cursor_pairs
        cursor = a["next_after"]
    assert left.retained_cursor_pairs == 0


@pytest.mark.parametrize("arguments", [{"include_briefs": 1}, {"order": []}, {"since": "other"},
    {"briefs": "bad"}, {"unknown": True}, {"limit": 0}, {"limit": True}])
def test_bad_request_is_typed_and_leaves_state(arguments):
    p = pager()
    before = state(p)
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$") as caught:
        p.prepare(arguments)
    assert caught.value.code == 1 and caught.value.next_action
    assert state(p) == before
    assert page(p)["messages"]


def test_cap_precedes_iteration_and_sort():
    class TooMany(list):
        def __iter__(self):
            pytest.fail("iterated oversized history")
    p = pager()
    rows = TooMany([None] * 10001)
    with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
        page(p, rows=rows)
    assert p.offered is None


@pytest.mark.parametrize("rows", [[{}], [{"message": {"to": []}}]])
def test_malformed_history_refuses(rows):
    p = pager()
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        page(p, rows=rows)
    assert p.offered is None


def test_abandon_capacity_failure_and_recovery():
    p = pager()
    value = page(p, {"order": "newest"})
    p.stage(value, 1, max_cursor_pairs=1)
    p.begin_response()
    assert p.retained_cursor_pairs == 0
    p.stage(page(p, {"order": "newest"}), 1, max_cursor_pairs=1)
    p.commit()
    before = deepcopy(p.cursors)
    with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
        p.stage(page(p, {"since": "current_generation"}), 1, max_cursor_pairs=1)
    assert p.cursors == before and p.pending is None
    p.stage(page(p, {"order": "newest"}), 1, max_cursor_pairs=1)
    p.commit()
    assert p.cursors == before


def test_bounding_matches_linear_oracle_and_metadata_refusal():
    value = page(pager())
    expected = legacy.bounded_inbox(value, encoded, max_response_bytes=len(encoded(value)) - 1)
    assert core.bounded_inbox(value, encoded, max_response_bytes=len(encoded(value)) - 1) == expected
    with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
        core.bounded_inbox(value, encoded, max_response_bytes=1)


def test_preview_sorts_once_and_does_not_commit_live_state(monkeypatch):
    p = pager()
    calls = []
    ordered = core.ordered_history
    monkeypatch.setattr(core, "ordered_history", lambda *args: calls.append(1) or ordered(*args))
    rows = records(10000)
    box = SimpleNamespace(ready=lambda snapshot: True, brief=lambda ref: b"brief")
    before = state(p)
    found = p.preview({"limit": 100}, rows, "m9999", checked_binding=lambda: (box, SNAPSHOT),
                      slimming=True, render=encoded, bound=core.bounded_inbox, max_cursor_pairs=10000)
    assert found and b'm9999' in found[0]
    assert calls == [1]
    assert state(p) == before


@pytest.mark.parametrize("value", [None, [], "x" * 10000, "2026-99-01T00:00:00Z"],
                         ids=["missing", "wrong-type", "oversized", "invalid-date"])
def test_timestamp_refuses_without_echo(value):
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        core.parse_inbox_time(value)


@pytest.mark.parametrize("change", ["future", "drift", "ambiguous"])
def test_since_refuses_ambiguous_cutoff_without_committing(change):
    p = pager()
    snapshot = deepcopy(SNAPSHOT)
    if change == "future":
        snapshot["created_at"] = "2027-01-01T00:00:00Z"
    elif change == "drift":
        p.stage(page(p), 100, max_cursor_pairs=10)
        p.commit()
        snapshot["created_at"] = "2026-11-16T12:00:00Z"
    else:
        snapshot["created_at"] = "2026-11-16T12:00:00Z"
    p.begin_response()
    before = state(p)
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        p.page(p.prepare({"since": "current_generation"}), snapshot=snapshot, ready=True,
               records=records(), limit=2, after=None, read_brief=None, brief_status=None, slimming=True)
    assert state(p) == before


@pytest.mark.parametrize("failure", ["oversized", "timeout", "encoding"])
def test_brief_failure_leaves_records_and_state_unchanged(failure):
    p = pager()
    rows = records()
    rows[0]["message"]["brief"] = {"path": "/brief.md", "sha256": "a" * 64}
    before = deepcopy(rows)
    def read(reference):
        if failure == "timeout":
            raise TimeoutError("untrusted input")
        return b"x" * 262145 if failure == "oversized" else b"\xff"
    reason = {"oversized": "too_large", "timeout": "io", "encoding": "invalid_record"}[failure]
    with pytest.raises(MailboxRefusal, match="^mailbox refused: " + reason + "$"):
        p.page(p.prepare({"include_briefs": True}), snapshot=SNAPSHOT, ready=True,
               records=rows, limit=2, after=None, read_brief=read, brief_status=None, slimming=True)
    assert rows == before and p.offered is None and p.pending is None
    assert page(p)["messages"]


def test_preview_concurrency_has_no_shared_delivery_state():
    from concurrent.futures import ThreadPoolExecutor
    p = pager()
    box = SimpleNamespace(ready=lambda snapshot: True, brief=lambda ref: b"brief")
    def preview(_):
        return p.preview({"limit": 2}, records(), "m4", checked_binding=lambda: (box, SNAPSHOT),
                         slimming=True, render=encoded, bound=core.bounded_inbox, max_cursor_pairs=10)
    before = state(p)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(preview, range(2)))
    assert results[0] == results[1]
    assert state(p) == before


def test_stage_refuses_forged_drain_and_allows_real_retry():
    p = pager()
    first = page(p)
    forged = {**first, "next_after": None}
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        p.stage(forged, 100, max_cursor_pairs=10)
    assert p.pending is None and p.retained_cursor_pairs == 0
    p.stage(first, 100, max_cursor_pairs=10)
    p.commit()
    assert p.retained_cursor_pairs == 1


def test_stage_accepts_the_existing_adapter_pair_capacity():
    p = pager()
    p.stage(page(p), 100, max_cursor_pairs=40000)
    p.commit()
    assert p.retained_cursor_pairs == 1


def test_checkpoint_cap_precedes_brief_reader():
    p = pager()
    snapshot = {**SNAPSHOT, "checkpoint": {"briefs": [{}] * 257}}
    with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
        p.page(p.prepare({"include_briefs": True}), snapshot=snapshot, ready=True,
               records=records(), limit=2, after=None,
               read_brief=lambda ref: pytest.fail("read oversized checkpoint"),
               brief_status=None, slimming=True)
    assert p.offered is None


def test_preview_checkpoint_briefs_use_injected_status():
    p = pager()
    reference = {"path": "/brief.md", "sha256": "a" * 64}
    snapshot = {**SNAPSHOT, "checkpoint": {"briefs": [reference]}}
    box = SimpleNamespace(ready=lambda snapshot: True, brief=lambda ref: b"brief")
    result = p.preview({"limit": 2, "include_briefs": True}, records(), "m4",
        checked_binding=lambda: (box, snapshot), slimming=True, render=encoded,
        bound=core.bounded_inbox, max_cursor_pairs=10, brief_status=lambda ref: {**ref, "ok": True})
    assert result and b'"ok":true' in result[0]
    assert p.retained_cursor_pairs == 0


def test_missing_checkpoint_status_port_is_typed():
    p = pager()
    snapshot = {**SNAPSHOT, "checkpoint": {"briefs": [{"path": "/brief.md", "sha256": "a" * 64}]}}
    def read():
        return p.page(p.prepare({"include_briefs": True}), snapshot=snapshot, ready=True,
            records=records(), limit=2, after=None, read_brief=lambda ref: b"brief",
            brief_status=None, slimming=True)
    p.stage(read(), 100, max_cursor_pairs=10)
    p.commit()
    p.begin_response()
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        read()
    assert p.offered is None


@pytest.mark.parametrize("failure", ["timeout", "wrong-render-type", "malformed-record"])
def test_transport_bound_failures_are_typed_before_staging(failure):
    value = page(pager())
    def render(result):
        if failure == "timeout":
            raise TimeoutError("untrusted detail")
        return None if failure == "wrong-render-type" else encoded(result)
    if failure == "malformed-record":
        value["messages"] = [1]
    reason = "io" if failure == "timeout" else "invalid_record"
    with pytest.raises(MailboxRefusal, match="^mailbox refused: " + reason + "$"):
        core.bounded_inbox(value, render)


def render_transport(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@pytest.mark.parametrize("kind", ["unicode", "brief"])
@pytest.mark.parametrize("endpoint", ["alpha/orchestrator", "alpha/front-door"],
                         ids=["recipient", "unrelated"])
@pytest.mark.parametrize("surface", ["inbox", "preview"])
def test_published_records_survive_pager_budgets(tmp_path, kind, endpoint, surface):
    root, box = populated(tmp_path)
    with box:
        message = request("large")
        if kind == "unicode":
            message["body"] = "\u00e9" * 65536
        else:
            path = tmp_path / "maximum-brief.md"
            raw = b"b" * 262144
            path.write_bytes(raw)
            message["brief"] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
        sent = box.publish(message)
        assert len(box.store.read(sent["path"])) <= 262144
        snapshot = box.current_binding(endpoint)
        options = {"include_briefs": True, "limit": 100}
        left, right = pager(), pager(legacy)
        before = state(left)
        if surface == "preview":
            rows = list(box.messages().values())
            arguments = dict(checked_binding=lambda: (box, snapshot), slimming=False,
                             render=render_transport, max_cursor_pairs=40000)
            expected = right.preview(options, rows, "large", bound=legacy.bounded_inbox, **arguments)
            result = left.preview(options, rows, "large", bound=core.bounded_inbox, **arguments)
            assert result == expected
            assert state(left) == before
            assert (result is not None) == (endpoint == "alpha/orchestrator")
        else:
            arguments = dict(checked_binding=lambda: (box, snapshot), slim_metadata=lambda: False,
                             brief_status=lambda mailbox, brief: brief)
            expected = legacy.bounded_inbox(right.inbox(options, **arguments), render_transport)
            value = left.inbox(options, **arguments)
            result = core.assemble_inbox(value, render_transport, bound=core.bounded_inbox,
                note_returned=lambda page, size: left.stage(page, size, max_cursor_pairs=40000))
            left.commit()
            assert result == expected
            assert len(result["messages"]) == (1 if endpoint == "alpha/orchestrator" else 0)
            left.begin_response()
            assert core.bounded_inbox(left.inbox(options, **arguments), render_transport) == expected


@pytest.mark.parametrize("endpoint", ["alpha/orchestrator", "alpha/front-door"],
                         ids=["recipient", "unrelated"])
@pytest.mark.parametrize("response_bytes", [4194304, 65536], ids=["full", "paged"])
def test_candidate_page_uses_per_record_structure(endpoint, response_bytes):
    rows = records(100)
    for row in rows:
        row["checks"] = [{"name": "check", "ok": True} for _ in range(400)]
    snapshot = {**SNAPSHOT, "endpoint": endpoint}
    options = dict(snapshot=snapshot, ready=True, records=rows, limit=100, after=None,
                   read_brief=None, brief_status=None, slimming=False)
    left, right = pager(), pager(legacy)
    expected = legacy.bounded_inbox(right.page(right.prepare({}), **options), render_transport,
                                    max_response_bytes=response_bytes)
    candidate = left.page(left.prepare({}), **options)
    result = core.bounded_inbox(candidate, render_transport, max_response_bytes=response_bytes)
    assert result == expected
    assert len(render_transport(result)) <= response_bytes
    left.stage(result, len(render_transport(result)), max_cursor_pairs=40000)
    left.commit()
    left.begin_response()
    assert core.bounded_inbox(left.page(left.prepare({}), **options), render_transport,
                              max_response_bytes=response_bytes) == expected


def test_foreign_expanded_fields_do_not_enter_response_preflight():
    rows = records(1)
    rows[0]["brief_text"] = "b" * (2 * 262144 + 32768 + 1)
    snapshot = {**SNAPSHOT, "endpoint": "alpha/front-door"}
    options = dict(snapshot=snapshot, ready=True, records=rows, limit=100, after=None,
                   read_brief=None, brief_status=None, slimming=False)
    left, right = pager(), pager(legacy)
    expected = legacy.bounded_inbox(right.page(right.prepare({}), **options), render_transport)
    candidate = left.page(left.prepare({}), **options)
    assert core.bounded_inbox(candidate, render_transport) == expected
    assert candidate["messages"] == []
    with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
        left.page(left.prepare({}), **{**options, "snapshot": SNAPSHOT})


@pytest.mark.parametrize("kind,reason", [("cycle", "invalid_record"), ("nodes", "too_large"),
    ("nonfinite", "invalid_record"), ("object", "invalid_record"),
    ("integer", "invalid_record"), ("surrogate", "invalid_record")])
def test_response_structure_refuses_before_copy_and_recovers(kind, reason):
    p = pager()
    rows = records(1)
    if kind == "cycle":
        value = []
        value.append(value)
    else:
        value = {"nodes": [[0] * 10000 for _ in range(4)], "nonfinite": float("nan"),
                 "object": object(), "integer": 1 << 128, "surrogate": "\ud800"}[kind]
    rows[0]["checks"] = value
    before = state(p)
    with pytest.raises(MailboxRefusal, match="^mailbox refused: " + reason + "$") as caught:
        page(p, rows=rows)
    assert caught.value.code == 1 and caught.value.next_action
    assert state(p) == before
    assert page(p)["messages"]


def test_large_preview_concurrency_and_legacy_parity():
    from concurrent.futures import ThreadPoolExecutor
    p = pager()
    rows = records(1)
    rows[0]["message"]["body"] = "\u00e9" * 65536
    raw = b"b" * 262144
    rows[0]["message"]["brief"] = {"path": "/maximum.md", "sha256": hashlib.sha256(raw).hexdigest()}
    box = SimpleNamespace(ready=lambda snapshot: True, brief=lambda ref: raw)
    arguments = dict(checked_binding=lambda: (box, SNAPSHOT), slimming=False,
                     render=render_transport, max_cursor_pairs=40000)
    expected = pager(legacy).preview({"limit": 1, "include_briefs": True}, deepcopy(rows), "m0",
                                     bound=legacy.bounded_inbox, **arguments)
    def preview(_):
        return p.preview({"limit": 1, "include_briefs": True}, rows, "m0",
                         bound=core.bounded_inbox, **arguments)
    before = state(p)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(preview, range(2)))
    assert results == [expected, expected]
    assert state(p) == before
