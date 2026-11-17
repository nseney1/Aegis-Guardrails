"""Core index public parity, retry and descriptor confinement."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_mailbox_index as core
from aegis_core import team_mailbox_index_scan as scan
from aegis_core import team_mailbox_store as store_module
from tests.unit.core.test_team_mailbox import (  # noqa: F401
    populated, request, snapshot, refusal, mailbox, owner_plane,
)
from tools import hierarchy_mailbox as legacy
from tools.hierarchy_mailbox_index import MailboxIndex


def seed(tmp_path):
    root, box = populated(tmp_path)
    for identifier in ("one", "two", "three"):
        box.publish(request(identifier))
    return root, box


def test_index_parity_retry_and_copy_isolation(tmp_path):
    root, box = seed(tmp_path)
    with box:
        index = core.Index(box)
        oracle = MailboxIndex(legacy.Mailbox(root), mode="shadow")
        assert index.messages() == oracle.messages() == box.messages()
        assert index.get("one") == oracle.get("one")
        assert index.inbox("alpha/orchestrator", limit=1) == oracle.inbox("alpha/orchestrator", limit=1)
        changed = index.messages()
        changed["one"]["message"]["body"] = "tampered"
        assert index.messages()["one"]["message"]["body"] == "hello"
        assert index.verify() == []
        with refusal("invalid_record"):
            index.get("missing")
        assert index.get("one")["message"]["body"] == "hello"


def test_hash_memo_still_validates_live_records(tmp_path, monkeypatch):
    _, box = seed(tmp_path)
    with box:
        index = core.Index(box, mode="indexed")
        expected = index.messages()
        calls = []
        parse = scan.parse_message
        monkeypatch.setattr(scan, "parse_message", lambda raw: calls.append(raw) or parse(raw))
        assert index.messages() == expected
        assert calls == []
        box.publish(request("four"))
        assert len(index.messages()) == 4
        assert len(calls) == 1


@pytest.mark.parametrize("raw,reason", [(b"{", "invalid_record"), (b"\xff", "invalid_record"),
    (b"x" * 262145, "too_large"), (b'---\n[]\n---\n\nbody', "invalid_record")],
    ids=["malformed", "non-utf8", "oversized", "wrong-shape"])
def test_bad_history_refuses_without_effect_and_recovers(tmp_path, raw, reason):
    root, box = seed(tmp_path)
    with box:
        index = core.Index(box, mode="indexed")
        record = index.get("one")
        path = Path(record["path"])
        original = path.read_bytes()
        path.write_bytes(raw)
        before = snapshot(root)
        with refusal(reason) as caught:
            index.messages()
        assert caught.value.as_dict()["code"] == 1
        assert caught.value.next_action
        assert snapshot(root) == before
        path.write_bytes(original)
        assert index.get("one") == record


def test_history_budget_precedes_parse(tmp_path, monkeypatch):
    _, box = seed(tmp_path)
    with box:
        monkeypatch.setattr(scan, "MAX_HISTORY_BYTES", 1)
        monkeypatch.setattr(scan, "parse_message", lambda raw: pytest.fail("parsed over budget"))
        with refusal("too_large"):
            core.Index(box, mode="indexed").messages()


def test_unsupported_platform_is_typed(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    with refusal("unsupported_platform"):
        mailbox(tmp_path / "mail")


def test_symlink_component_and_root_rename_stay_confined(tmp_path):
    root, box = seed(tmp_path)
    with box:
        index = core.Index(box, mode="indexed")
        expected = index.messages()
        held = root.with_name("held")
        root.rename(held)
        root.mkdir()
        assert index.messages() == expected
        folder = held / "alpha" / "orchestrator"
        folder.rename(held / "alpha" / "original")
        symlink_or_skip(held / "alpha" / "original", folder, target_is_directory=True)
        with refusal("unsafe_path"):
            index.messages()
        folder.unlink()
        (held / "alpha" / "original").rename(folder)
        assert index.messages() == expected


def test_concurrent_readers_and_typed_io_retry(tmp_path, monkeypatch):
    _, box = seed(tmp_path)
    with box:
        index = core.Index(box, mode="indexed")
        with ThreadPoolExecutor(max_workers=3) as pool:
            values = list(pool.map(lambda _: index.messages(), range(9)))
        assert all(value == values[0] for value in values)
        read = store_module.Store.read
        def timeout(*args, **kwargs):
            raise TimeoutError("secret untrusted detail")
        monkeypatch.setattr(store_module.Store, "read", timeout)
        with refusal("io"):
            index.messages()
        monkeypatch.setattr(store_module.Store, "read", read)
        assert index.messages() == values[0]


def test_content_change_verification_and_bounded_retention(tmp_path, monkeypatch):
    root, box = seed(tmp_path)
    with box:
        monkeypatch.setattr(scan, "MAX_EVIDENCE_ENTRIES", 1)
        index = core.Index(box, mode="indexed")
        index.messages()
        path = Path(index.get("one")["path"])
        path.write_bytes(path.read_bytes().replace(b"hello", b"other"))
        changes = index.verify()
        assert any(row["kind"] == "content_changed" for row in changes)
        stats = index.evidence_stats()
        assert stats["entries"] <= 1
        assert stats["summary_paths"] <= stats["max_summary_paths"]
        assert index.get("one")["message"]["body"] == "other"


def test_mode_is_explicit_and_read_only(tmp_path):
    _, box = seed(tmp_path)
    with box:
        index = core.Index(box)
        assert index.mode == "shadow"
        with pytest.raises(AttributeError):
            index.mode = "indexed"
        with refusal("invalid_record"):
            core.Index(box, mode=[])


def test_component_swap_during_read_uses_held_directory(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    with box:
        box.publish(request("one"))
        index = core.Index(box, mode="indexed")
        record = index.get("one")
        folder = Path(record["path"]).parent
        outside = tmp_path / "outside"
        outside.mkdir()
        # Capability check happens before starting a cooperating thread.
        probe = tmp_path / "link-probe"
        symlink_or_skip(outside, probe, target_is_directory=True)
        probe.unlink()
        opened, swapped = Event(), Event()
        def opening(path, flags, *args, **kwargs):
            if path == Path(record["path"]).name:
                opened.set()
                assert swapped.wait(5), "swap did not complete"
            return os.open(path, flags, *args, **kwargs)
        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "open": opening}))
        def swap():
            assert opened.wait(5), "reader did not reach held parent"
            folder.rename(folder.with_name("original"))
            folder.symlink_to(outside, target_is_directory=True)
            swapped.set()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(swap)
            assert index.get("one") == record
            future.result(timeout=5)
        folder.unlink()
        folder.with_name("original").rename(folder)
        assert core.compare(box, index) == []


def test_evidence_canonicalizes_then_redacts_before_truncating():
    evidence = scan.Evidence()
    example = "AKIAIOSFODNN7EXAMPLE"
    path = "/trusted/\x1bP" + example + "/" + "tail" * 400
    evidence.admit(path, "a" * 64)
    evidence.observe(path, "b" * 64)
    shown = evidence.changes()[0]
    assert example not in shown["path"]
    assert "\x1b" not in shown["path"]
    assert len(shown["path"]) <= 1024
    assert shown["path_sha256"]


def test_compare_preserves_shadow_race_diagnostics(tmp_path, monkeypatch):
    _, box = seed(tmp_path)
    with box:
        index = core.Index(box)
        target = Path(index.get("one")["path"])
        read, changed = store_module.Store.read, []
        def changing(self, path, **kwargs):
            raw = read(self, path, **kwargs)
            if path == target and not changed:
                target.write_bytes(raw.replace(b"hello", b"other"))
                changed.append(True)
            return raw
        monkeypatch.setattr(store_module.Store, "read", changing)
        differences = core.compare(box, index)
        assert any(row["kind"] == "mailbox_index_divergence" for row in differences)
        assert index.get("one")["message"]["body"] == "other"


def assert_coverage_gap(result):
    markers = [row for row in result if row["kind"] == "verification_unavailable"]
    assert len(markers) == 1
    assert markers[0]["reason"] == "baseline_unavailable"


@pytest.mark.parametrize("surface", ["messages", "inbox"])
@pytest.mark.parametrize("followup", ["direct", "matching", "failed_verify"])
def test_publication_gap_survives_until_verification(tmp_path, monkeypatch, surface, followup):
    root, box = seed(tmp_path)
    with box:
        index = core.Index(box)
        target = Path(index.get("one")["path"])
        read, published, failing = store_module.Store.read, [], [False]
        def writer():
            with mailbox(root) as publisher:
                publisher.publish(request("four"))
        def changing(self, path, **kwargs):
            if failing[0]:
                raise TimeoutError("untrusted storage detail")
            raw = read(self, path, **kwargs)
            if path == target and not published:
                published.append(True)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(writer).result(timeout=5)
            return raw
        monkeypatch.setattr(store_module.Store, "read", changing)
        result = index.messages() if surface == "messages" else index.inbox("alpha/orchestrator")
        assert len(result if surface == "messages" else result["messages"]) == 4
        if followup == "matching":
            assert len(index.messages()) == 4
        if followup == "failed_verify":
            failing[0] = True
            with refusal("io"):
                index.verify()
            failing[0] = False
        assert_coverage_gap(index.verify())
        assert index.verify() == []


@pytest.mark.parametrize("matching_read", [False, True], ids=["direct", "matching"])
def test_restore_a_cannot_erase_returned_b_coverage_gap(tmp_path, monkeypatch, matching_read):
    _, box = seed(tmp_path)
    with box:
        index = core.Index(box)
        record = index.get("one")
        target = Path(record["path"])
        original = target.read_bytes()
        read, changed = store_module.Store.read, []
        def changing(self, path, **kwargs):
            raw = read(self, path, **kwargs)
            if path == target and not changed:
                changed.append(True)
                target.write_bytes(raw.replace(b"hello", b"other"))
            return raw
        monkeypatch.setattr(store_module.Store, "read", changing)
        assert index.get("one")["message"]["body"] == "other"
        target.write_bytes(original)
        if matching_read:
            assert index.get("one") == record
        assert_coverage_gap(index.verify())
        assert index.verify() == []
