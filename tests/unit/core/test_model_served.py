"""Served receipts through public selection, observation and replay surfaces."""
import copy
import errno
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import model_select as selection
from aegis_core import model_served as core
from aegis_core.storage import confined_descriptor_supported


@pytest.fixture
def scenario():
    bindings = {"schema": "aegis.model-bindings/v1", "roles": [
        {"kind": role, "model_class": "coding",
         "band": {"floor": "deep", "default": "deep", "ceiling": "extended"}}
        for role in ("orchestrator", "decider", "implementer", "integrator", "reviewer")],
        "hosts": [{"host": host, "class": "coding", "model": model,
                   "levels": {"deep": "high", "extended": "max"},
                   "admission": {"deep": "admitted", "extended": "admitted"}}
                  for host, model in (("host-a", "model-a"), ("host-b", "model-b"))]}
    policy = {"team_id": "example-team", "manager_family": "beta", "team_family": "alpha",
              "target_shares": {"alpha": 0.7, "beta": 0.3}, "family_order": ["alpha", "beta"],
              "family_hosts": {"alpha": ["host-a"], "beta": ["host-b"]},
              "flexible_tasks": ["T9"],
              "review_families": {"T4": {"primary": "beta"}, "T5": {"primary": "alpha"},
                                  "T6": {"primary": "alpha", "whole": "beta"},
                                  "T8": {"primary": "opposite", "second": "author"}}}
    return bindings, policy


def choose(scenario, rows=(), **changes):
    bindings, policy = scenario
    return selection.select_model(bindings, policy, "T9", "implementer", rows,
                                  host_kinds=("host-a", "host-b"), subject="example",
                                  author_family="alpha", **changes)[1]


@pytest.fixture
def original(scenario):
    return choose(scenario)


def chosen(record):
    return {**{key: record["choice"][key] for key in ("host", "model", "level", "family")},
            "fallback_reason": None}


def fallback():
    return {"host": "host-b", "model": "model-b", "level": "high", "family": "beta",
            "fallback_reason": "configured_host_unavailable"}


def observation(record, served):
    return {**record, "outcome": {"served": served}}


def make_store(tmp_path, original):
    if os.name != "posix" or not confined_descriptor_supported():
        pytest.skip("descriptor-relative no-follow decision logs required")
    path = tmp_path / "receipts.jsonl"
    selection.append_decision(path, original)
    return path


def malformed_blocks():
    return [None, [], "beta", {}, {**fallback(), "extra": True},
            {**fallback(), "cross_family": True}, {**fallback(), "family": []},
            {**fallback(), "host": "x" * 129}, {**fallback(), "model": "x" * 129},
            {**fallback(), "level": "high\nforged"}, {**fallback(), "family": "beta\x00"},
            {**fallback(), "fallback_reason": "unavailable\rforged"},
            {**fallback(), "fallback_reason": "x" * 129},
            {**fallback(), "fallback_reason": ""},
            {**fallback(), "host": "é"}, {**fallback(), "model": "\ud800"}]


@pytest.mark.parametrize("served", malformed_blocks())
def test_malformed_receipt_refuses_before_io_and_reads_as_absent(tmp_path, original, served):
    path = tmp_path / "never-created"
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError) as refused:
            core.observe_served(path, original["decision_id"], served)
        assert str(refused.value) == "invalid_served"
    assert list(tmp_path.iterdir()) == []
    rows = [original, observation(original, served)]
    assert core.served_of(rows, original["decision_id"]) is None


@pytest.mark.parametrize("identity", [None, [], {}, 1, "", "x" * 64, "a" * 65, "a\n" * 32])
def test_invalid_decision_id_refuses_without_echo_or_io(tmp_path, identity):
    with pytest.raises(selection.ModelSelectionError) as refused:
        core.observe_served(tmp_path / "never-created", identity, fallback())
    assert str(refused.value) == "invalid_decision_id"
    with pytest.raises(selection.ModelSelectionError, match="^invalid_decision_id$"):
        core.served_of([], identity)
    assert list(tmp_path.iterdir()) == []


def test_absent_malformed_rows_and_unknown_decision_never_infer_chosen(original):
    identity = original["decision_id"]
    assert core.served_of([original], identity) is None
    assert core.served_of([original, observation(original, fallback())], "f" * 64) is None
    rows = [None, [], {}, {"decision_id": identity, "outcome": []}]
    assert core.served_of(rows, identity) is None


@pytest.mark.parametrize("rows", [None, 3, {}])
def test_unreadable_history_is_a_refusal_not_absence(original, rows):
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.served_of(rows, original["decision_id"])


def test_reader_refuses_sequence_protocol_history_before_reading(original):
    class History:
        def __getitem__(self, index):
            pytest.fail("unsupported history was read")

    history = History()
    identity = original["decision_id"]

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.served_of(history, identity)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)


def test_reader_refuses_a_broken_iter_without_echo(original):
    class History:
        def __iter__(self):
            pytest.fail("unsupported __iter__ was called")

    history = History()
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.served_of(history, original["decision_id"])


@pytest.mark.parametrize("failure", [TypeError("row read failed"),
                                    selection.ModelSelectionError("unsafe_decision_path")])
def test_reader_propagates_row_read_failure_after_valid_receipt(original, failure):
    def history():
        yield original
        yield observation(original, fallback())
        raise failure

    with pytest.raises(type(failure)) as caught:
        core.served_of(history(), original["decision_id"])
    assert caught.value is failure


def test_reader_consumes_iterator_without_calling_its_broken_iter(original):
    served = fallback()

    class History:
        def __init__(self):
            self.records = iter((original, observation(original, served)))

        def __iter__(self):
            return None

        def __next__(self):
            return next(self.records)

    for _ in range(2):
        assert core.served_of(History(), original["decision_id"]) == {**served, "cross_family": True}


@pytest.mark.parametrize("container", [list, tuple])
def test_reader_walks_list_and_tuple_storage_directly(original, container):
    class History(container):
        def __iter__(self):
            pytest.fail("container override was called")

    served = fallback()
    records = (original, observation(original, served))
    for history in (container(records), History(records)):
        assert core.served_of(history, original["decision_id"]) == {**served, "cross_family": True}


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("has_observation", [False, True])
@pytest.mark.parametrize("known_id", [False, True])
def test_reader_limit_distinguishes_complete_history_from_absence(original, extra, has_observation, known_id):
    rows = [original]
    if has_observation:
        rows.append(observation(original, fallback()))
    rows.extend({} for _ in range(selection.MAX_HISTORY_RECORDS - len(rows) + extra))
    identity = original["decision_id"] if known_id else "f" * 64
    assert len(rows) == selection.MAX_HISTORY_RECORDS + extra
    for _ in range(2):
        if extra:
            with pytest.raises(selection.ModelSelectionError) as refused:
                core.served_of(rows, identity)
            assert str(refused.value) == "history_limit_exceeded: archive_or_rotate_decision_log"
        else:
            expected = {**fallback(), "cross_family": True} if has_observation and known_id else None
            assert core.served_of(rows, identity) == expected


@pytest.mark.parametrize("has_observation", [False, True])
def test_over_limit_generator_reads_only_one_extra_row_on_concurrent_retry(original, has_observation):
    def refuse(_):
        consumed = SimpleNamespace(count=0)

        def rows():
            for index in range(selection.MAX_HISTORY_RECORDS + 2):
                consumed.count += 1
                if index == 0:
                    yield original
                elif index == 1 and has_observation:
                    yield observation(original, fallback())
                else:
                    yield {}

        with pytest.raises(selection.ModelSelectionError) as refused:
            core.served_of(rows(), original["decision_id"])
        assert str(refused.value) == "history_limit_exceeded: archive_or_rotate_decision_log"
        assert consumed.count == selection.MAX_HISTORY_RECORDS + 1

    refuse(None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))


def test_unknown_decision_refuses_without_publication(tmp_path, original):
    path = make_store(tmp_path, original)
    before = path.read_bytes()
    def refuse(_):
        with pytest.raises(selection.ModelSelectionError) as refused:
            core.observe_served(path, "f" * 64, fallback())
        assert str(refused.value) == "unknown_decision_id"

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == before
    missing = tmp_path / "missing.jsonl"
    with pytest.raises(selection.ModelSelectionError, match="^unknown_decision_id$"):
        core.observe_served(missing, "f" * 64, fallback())
    assert not missing.exists()
    assert not missing.with_name(missing.name + ".lock").exists()


@pytest.mark.parametrize("field", ["host", "model", "level", "family"])
def test_any_changed_identity_requires_a_reason(original, field):
    served = chosen(original)
    served[field] = "different"
    assert core.served_of([original, observation(original, served)], original["decision_id"]) is None
    served["fallback_reason"] = "runtime_fallback"
    assert core.served_of([original, observation(original, served)], original["decision_id"]) == {
        **served, "cross_family": field == "family"}


def test_chosen_receipt_requires_null_reason(original):
    served = {**chosen(original), "fallback_reason": "invented_fallback"}
    assert core.served_of([original, observation(original, served)], original["decision_id"]) is None


@pytest.mark.parametrize("receipt", ["unchanged_with_reason", "fallback_without_reason"])
def test_inconsistent_fallback_reason_refuses_on_retry_without_mutation(tmp_path, original, receipt):
    path = make_store(tmp_path, original)
    served = ({**chosen(original), "fallback_reason": "invented_fallback"}
              if receipt == "unchanged_with_reason" else {**fallback(), "fallback_reason": None})
    before = path.read_bytes()
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_served$"):
            core.observe_served(path, original["decision_id"], served)
    assert path.read_bytes() == before
    assert core.served_of([original, observation(original, served)], original["decision_id"]) is None


@pytest.mark.parametrize("receipt", ["chosen", "fallback"])
@pytest.mark.parametrize("status", [None, "not_launched"])
def test_observation_preserves_launch_state_and_split_counts(tmp_path, original, scenario, receipt, status):
    path = make_store(tmp_path, original)
    if status:
        selection.append_decision(path, {**original, "outcome": {"launch_status": status}})
    before_rows = list(selection.read_decisions(path))
    before_counts = choose(scenario, before_rows)["counts_before"]
    served = chosen(original) if receipt == "chosen" else fallback()
    for _ in range(2):
        result = core.observe_served(path, original["decision_id"], served)
        assert result == observation(original, served)
    rows = list(selection.read_decisions(path))
    assert rows == before_rows + [observation(original, served)] * 2
    assert core.served_of(rows, original["decision_id"]) == {**served, "cross_family": receipt == "fallback"}
    assert choose(scenario, rows)["counts_before"] == before_counts
    assert sum(before_counts.values()) == (0 if status else 1)


def test_newest_valid_receipt_wins_and_invalid_later_receipts_do_not_hide_it(original):
    identity = original["decision_id"]
    rows = [original, observation(original, chosen(original)), observation(original, fallback())]
    for bad in malformed_blocks():
        rows.append(observation(original, bad))
    before = copy.deepcopy(rows)
    result = core.served_of(iter(rows), identity)
    assert result == {**fallback(), "cross_family": True}
    result["family"] = "mutated"
    assert rows == before
    rows.append(observation(original, chosen(original)))
    assert core.served_of(rows, identity) == {**chosen(original), "cross_family": False}


def test_coverage_uses_author_and_missing_author_cannot_claim_coverage(original):
    other_author = {**original, "author_family": "beta"}
    assert core.served_of([other_author, observation(other_author, fallback())], original["decision_id"]) == {
        **fallback(), "cross_family": False}
    no_author = {**original, "author_family": None}
    assert core.served_of([no_author, observation(no_author, fallback())], original["decision_id"]) == {
        **fallback(), "cross_family": False}


@pytest.mark.parametrize("status", [None, "not_launched"])
def test_concurrent_appenders_preserve_both_receipts_and_launch_state(tmp_path, original, scenario, status):
    path = make_store(tmp_path, original)
    if status:
        selection.append_decision(path, {**original, "outcome": {"launch_status": status}})
    before_rows = list(selection.read_decisions(path))
    counts = choose(scenario, before_rows)["counts_before"]
    receipts = [chosen(original), fallback()]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda served: core.observe_served(path, original["decision_id"], served), receipts))
    rows = list(selection.read_decisions(path))
    assert len(rows) == len(before_rows) + 2
    assert all(result in rows[len(before_rows):] for result in results)
    last = rows[-1]["outcome"]["served"]
    assert core.served_of(rows, original["decision_id"]) == {**last, "cross_family": last["family"] != "alpha"}
    assert choose(scenario, rows)["counts_before"] == counts


def test_concurrent_malformed_receipts_leave_history_unchanged_then_valid_retry_works(tmp_path, original):
    path = make_store(tmp_path, original)
    before = path.read_bytes()

    def refuse(served):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_served$"):
            core.observe_served(path, original["decision_id"], served)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, malformed_blocks()))
    assert path.read_bytes() == before
    core.observe_served(path, original["decision_id"], fallback())
    assert core.served_of(selection.read_decisions(path), original["decision_id"]) == {
        **fallback(), "cross_family": True}


@pytest.mark.parametrize("limit", ["records", "bytes"])
def test_history_limit_refuses_concurrent_retries_without_changes(tmp_path, original, limit):
    path = make_store(tmp_path, original)
    encode = lambda row: (json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    line = encode(original)
    if limit == "records":
        payload = line * selection.MAX_HISTORY_RECORDS
        assert len(payload) <= selection.MAX_HISTORY_BYTES
    else:
        padded = encode({**original, "outcome": {"padding": "x" * 2000}})
        count, remainder = divmod(selection.MAX_HISTORY_BYTES - len(line), len(padded))
        tail = encode({**original, "outcome": {"padding": ""}})
        if remainder < len(tail):
            count -= 1
            remainder += len(padded)
        tail = encode({**original, "outcome": {"padding": "x" * (remainder - len(tail))}})
        payload = line + padded * count + tail
        assert len(payload) == selection.MAX_HISTORY_BYTES
        assert count + 2 < selection.MAX_HISTORY_RECORDS
        assert len(tail) <= selection.MAX_LINE_BYTES
    path.write_bytes(payload)

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError) as refused:
            core.observe_served(path, original["decision_id"], fallback())
        assert str(refused.value) == "history_limit_exceeded: archive_or_rotate_decision_log"

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == payload
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name, path.name + ".lock"]


def test_malformed_block_on_disk_reads_as_absent(tmp_path, original):
    path = make_store(tmp_path, original)
    selection.append_decision(path, observation(original, {**fallback(), "extra": True}))
    assert core.served_of(selection.read_decisions(path), original["decision_id"]) is None
    core.observe_served(path, original["decision_id"], fallback())
    selection.append_decision(path, observation(original, {**fallback(), "family": "beta\n"}))
    assert core.served_of(selection.read_decisions(path), original["decision_id"]) == {
        **fallback(), "cross_family": True}


def test_symlink_component_refuses_without_touching_target(tmp_path, original):
    directory = tmp_path / "real"
    directory.mkdir()
    path = make_store(directory, original)
    link = tmp_path / "alias"
    symlink_or_skip(directory, link, target_is_directory=True)
    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^unsafe_decision_path$"):
        core.observe_served(link / path.name, original["decision_id"], fallback())
    assert path.read_bytes() == before


def test_unsupported_platform_refusal_is_preserved_with_probe_disabled(tmp_path, original, monkeypatch):
    monkeypatch.setattr(core, "os", SimpleNamespace(name="nt", supports_dir_fd=set()))
    with pytest.raises(selection.ModelSelectionError, match="^anchored_io_unavailable$"):
        core.observe_served(tmp_path / "receipts.jsonl", original["decision_id"], fallback())
    assert list(tmp_path.iterdir()) == []


def test_rotation_cannot_republish_a_suppressed_first_launch(tmp_path, original, scenario, monkeypatch):
    """A receipt must name a decision in the generation that receives it.

    Wiping the log after lookup is the cooperating rotation. An empty generation
    would otherwise admit this not_launched first row as a fresh launch.
    """
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    preserved = path.read_bytes()
    real_append = selection.append_decision
    state = {"rotate": True}

    def rotate_then_append(log_path, record=None, **kwargs):
        if state["rotate"]:
            log_path.write_bytes(b"")
            log_path.chmod(0o600)
        return real_append(log_path, record, **kwargs)

    monkeypatch.setattr(selection, "append_decision", rotate_then_append)
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^unknown_decision_id$"):
            core.observe_served(path, original["decision_id"], fallback())
    assert path.read_bytes() == b""
    assert not list(tmp_path.glob(".model-select-*"))
    state["rotate"] = False
    path.write_bytes(preserved)
    path.chmod(0o600)
    result = core.observe_served(path, original["decision_id"], fallback())
    rows = list(selection.read_decisions(path))
    assert result == observation(original, fallback())
    assert rows[-1] == result
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0


def test_changed_generation_refuses_receipt_before_rename(tmp_path, original, monkeypatch):
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    state = {"swapped": False}

    def swap_on_sync(descriptor):
        # The file fsync runs after the snapshot is taken and before the generation check.
        os.fsync(descriptor)
        if state["swapped"]:
            return
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"")
        replacement.chmod(0o600)
        replacement.replace(path)
        state["swapped"] = True

    monkeypatch.setattr(selection, "os", SimpleNamespace(**{**vars(os), "fsync": swap_on_sync}))
    with pytest.raises(selection.ModelSelectionError, match="^stale_decision$"):
        core.observe_served(path, original["decision_id"], fallback())
    monkeypatch.setattr(selection, "os", os)
    assert state["swapped"]
    assert path.read_bytes() == b""
    assert not list(tmp_path.glob(".model-select-*"))
    assert not (tmp_path / "replacement").exists()

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^unknown_decision_id$"):
            core.observe_served(path, original["decision_id"], fallback())

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == b""


def test_directory_flush_failure_leaves_visible_receipt_and_closed_descriptors(
        tmp_path, original, scenario, monkeypatch):
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    opened = []

    def fail_directory_fsync(descriptor):
        os.fsync(descriptor)
        opened.append(descriptor)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.EIO, "directory flush failed")

    monkeypatch.setattr(selection, "os", SimpleNamespace(**{**vars(os), "fsync": fail_directory_fsync}))
    with pytest.raises(OSError, match="directory flush failed") as raised:
        core.observe_served(path, original["decision_id"], fallback())
    monkeypatch.setattr(selection, "os", os)
    assert raised.value.errno == errno.EIO
    assert opened
    for descriptor in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    assert not list(tmp_path.glob(".model-select-*"))
    rows = list(selection.read_decisions(path))
    assert rows[-1] == observation(original, fallback())
    again = core.observe_served(path, original["decision_id"], fallback())
    rows = list(selection.read_decisions(path))
    assert again == rows[-1] == observation(original, fallback())
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0


def test_receipt_fdopen_failure_closes_descriptor_and_retries(tmp_path, original, scenario, monkeypatch):
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    before = path.read_bytes()
    fdopen, fsync, synced, failed = os.fdopen, os.fsync, [], []

    def track_sync(descriptor):
        fsync(descriptor)
        synced.append(descriptor)

    def fail_probe(descriptor, *args, **kwargs):
        if synced:
            failed.append(descriptor)
            raise OSError(errno.EIO, "probe stream unavailable")
        return fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(selection, "os", SimpleNamespace(
        **{**vars(os), "fdopen": fail_probe, "fsync": track_sync}))
    with pytest.raises(OSError, match="probe stream unavailable") as raised:
        core.observe_served(path, original["decision_id"], fallback())
    monkeypatch.setattr(selection, "os", os)
    assert raised.value.errno == errno.EIO
    assert len(failed) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(failed[0])
    assert closed.value.errno == errno.EBADF
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".model-select-*"))
    result = core.observe_served(path, original["decision_id"], fallback())
    rows = list(selection.read_decisions(path))
    assert result == rows[-1] == observation(original, fallback())
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0


def test_corrupt_snapshot_refuses_receipt_without_publication(tmp_path, original):
    path = make_store(tmp_path, original)
    raw = path.read_bytes() + b"{broken}\n"
    path.write_bytes(raw)

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.observe_served(path, original["decision_id"], fallback())

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == raw
    assert not list(tmp_path.glob(".model-select-*"))
