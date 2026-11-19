"""Public mailbox behaviour, bounded refusals and legacy parity."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import hashlib
import os
import select
import stat
import subprocess
import sys
import traceback
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_mailbox as mail
from aegis_core import team_mailbox_delivery as delivery_module
from aegis_core import team_mailbox_store as store_module
from aegis_core import team_mailbox_primitives as primitives
from aegis_core.team_mailbox_primitives import BusyError, MailboxRefusal, RoleTables
from aegis_core.workspace.layout import UserLayout
from tools import hierarchy_mailbox as legacy


NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
MANIFEST = {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {
    "alpha/front-door": {}, "alpha/orchestrator": {}, "alpha/root": {},
    "alpha/lane/review": {"kind": "reviewer"}}, "counterparts": [], "writer_limit": 2}
ROLES = RoleTables(writes={"owner": frozenset({"bind", "publish", "acknowledge_handoff",
    "record_read", "write_delivery_receipt", "initialize"}), "reader": frozenset()})
HOSTS = {"test-host": SimpleNamespace()}


@pytest.fixture(autouse=True)
def owner_plane(tmp_path_factory, monkeypatch):
    layout = UserLayout(tmp_path_factory.mktemp("mailbox-owner"))
    layout.aegis_dir.mkdir(mode=0o700)

    class IsolatedLayout(UserLayout):
        def __init__(self, home):
            assert Path(home) == layout.home, "test attempted to reach a real account home"
            super().__init__(home)

        @classmethod
        def current(cls):
            return layout

    monkeypatch.setattr(store_module, "UserLayout", IsolatedLayout)
    monkeypatch.setattr(store_module, "pwd", SimpleNamespace(
        getpwuid=lambda uid: SimpleNamespace(pw_dir=str(layout.home))))
    return layout.aegis_dir


def make_store(tmp_path, name="mail"):
    if not store_module.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / name
    mail.initialize(root, MANIFEST, roles=ROLES, caller_role="owner")
    return root


def mailbox(root, **overrides):
    options = dict(clock=lambda: NOW, roles=ROLES, hosts=HOSTS, caller_role="owner",
                   delivery_roots=(root.parent / "delivery",))
    options.update(overrides)
    return mail.Mailbox(root, **options)


def bind(box, endpoint):
    return box.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                     "expected_generation": 0})


def request(identifier="message"):
    return {"message_id": identifier, "from": "alpha/front-door", "to": "alpha/orchestrator",
            "host": "test-host", "session": "alpha/front-door", "binding_generation": 1,
            "type": "info", "body": "hello"}


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def populated(tmp_path):
    root = make_store(tmp_path)
    box = mailbox(root)
    bind(box, "alpha/front-door")
    bind(box, "alpha/orchestrator")
    return root, box


def refusal(reason):
    return pytest.raises(MailboxRefusal, match="^mailbox refused: " + reason + "$")


MANIFEST_REPAIR_ACTIONS = {
    "manifest": "Restore a bounded manifest with schema, writer_limit, endpoints and counterparts before retrying.",
    "schema": "Repair the manifest schema field to use aegis.hierarchy-pilot/v1 before retrying.",
    "writer_limit": "Repair the manifest writer_limit field to use an integer within the owner writer ceiling before retrying.",
    "endpoints": "Repair the manifest endpoints field: check endpoint names, lane kinds and required hierarchy roles before retrying.",
    "counterparts": "Repair the manifest counterparts field: check endpoint pairs, cross-hierarchy roles and unique membership before retrying.",
}


@pytest.mark.parametrize("field,patch,reason", [
    ("manifest", None, "invalid_record"),
    ("manifest", {"extra": "PRIVATE\nmanifest"}, "invalid_record"),
    ("manifest", {"schema": "x" * 262145}, "too_large"),
    ("schema", {"schema": "PRIVATE\nschema"}, "invalid_record"),
    ("writer_limit", {"writer_limit": "PRIVATE\nwriter"}, "invalid_record"),
    ("writer_limit", {"writer_limit": True}, "invalid_record"),
    ("writer_limit", {"writer_limit": 6}, "invalid_record"),
    ("endpoints", {"endpoints": []}, "invalid_record"),
    ("endpoints", {"endpoints": {}}, "invalid_record"),
    ("endpoints", {"endpoints": {"alpha/lane/worker" + str(i): {"kind": "reviewer"}
                                for i in range(257)}}, "invalid_record"),
    ("endpoints", {"endpoints": {"PRIVATE\nendpoint": {}}}, "invalid_record"),
    ("endpoints", {"endpoints": {"alpha/front-door": {"PRIVATE": "definition"}}}, "invalid_record"),
    ("endpoints", {"endpoints": {"alpha/lane/work": {"kind": "PRIVATE\nkind"}}}, "invalid_record"),
    ("endpoints", {"endpoints": {"alpha/root": {}}}, "invalid_record"),
    ("counterparts", {"counterparts": "PRIVATE\npairs"}, "invalid_record"),
    ("counterparts", {"counterparts": [[]] * 257}, "invalid_record"),
    ("counterparts", {"counterparts": [["PRIVATE\npair", "alpha/front-door"]]}, "invalid_record"),
    ("counterparts", {"counterparts": [["alpha/root", "alpha/front-door"]]}, "invalid_record"),
    ("counterparts", {"counterparts": [["alpha/front-door", "alpha/orchestrator"]]}, "invalid_record"),
], ids=["shape", "extra", "budget", "schema", "writer-type", "writer-bool", "writer-ceiling",
        "endpoints-type", "endpoints-empty", "endpoints-limit", "endpoint-name", "endpoint-definition", "lane-kind",
        "hierarchy-roles", "counterparts-type", "counterparts-limit", "counterpart-name", "counterpart-root", "counterpart-role"])
def test_initialize_manifest_repair_context_is_fixed_before_storage(tmp_path, monkeypatch, field, patch, reason):
    def unexpected_storage(*args, **kwargs):
        pytest.fail("invalid manifest reached storage")

    monkeypatch.setattr(mail, "initialize_store", unexpected_storage)
    candidate = None if patch is None else {**MANIFEST, **patch}
    root = tmp_path / "candidate"
    for _ in range(2):
        with refusal(reason) as caught:
            mail.initialize(root, candidate, roles=ROLES, caller_role="owner")
        assert caught.value.as_dict() == {"status": "refused", "reason": reason, "code": 1,
                                          "next_action": MANIFEST_REPAIR_ACTIONS[field]}
        assert "PRIVATE" not in str(caught.value) + json.dumps(caught.value.as_dict())
        assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("field", ["schema", "writer_limit", "endpoints", "counterparts"])
def test_initialize_manifest_repair_then_retry_preserves_existing_store(tmp_path, field):
    existing = make_store(tmp_path)
    before = snapshot(existing)
    root = tmp_path / "candidate"
    with refusal("invalid_record") as caught:
        mail.initialize(root, {**MANIFEST, field: None}, roles=ROLES, caller_role="owner")
    assert caught.value.next_action == MANIFEST_REPAIR_ACTIONS[field]
    assert snapshot(existing) == before and not root.exists()
    mail.initialize(root, MANIFEST, roles=ROLES, caller_role="owner")
    with mailbox(root) as box:
        assert box.manifest == MANIFEST
    assert snapshot(existing) == before


def test_initialize_manifest_repair_context_is_local_to_concurrent_calls(tmp_path):
    fields = ["schema", "writer_limit", "endpoints", "counterparts"] * 8

    def rejected(field):
        with refusal("invalid_record") as caught:
            mail.initialize(tmp_path / "candidate", {**MANIFEST, field: None}, roles=ROLES, caller_role="owner")
        return caught.value.as_dict()

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(rejected, fields))
    assert [result["next_action"] for result in results] == [MANIFEST_REPAIR_ACTIONS[field] for field in fields]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("pairs", [
    [["alpha/front-door", "beta/orchestrator"]],
    [["alpha/router", "beta/router"]],
    [["alpha/front-door", "beta/front-door"]] * 2,
], ids=["different-roles", "unsupported-role", "duplicate-membership"])
def test_initialize_manifest_counterpart_constraints_have_fixed_repair(tmp_path, pairs):
    endpoints = {**MANIFEST["endpoints"], "alpha/router": {}, "beta/router": {},
                 "beta/front-door": {}, "beta/orchestrator": {}}
    candidate = {**MANIFEST, "endpoints": endpoints, "counterparts": pairs}
    with refusal("invalid_record") as caught:
        mail.initialize(tmp_path / "candidate", candidate, roles=ROLES, caller_role="owner")
    assert caught.value.next_action == MANIFEST_REPAIR_ACTIONS["counterparts"]
    assert list(tmp_path.iterdir()) == []


def test_initialize_storage_refusal_keeps_platform_repair_advice(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    with refusal("unsupported_platform") as caught:
        mail.initialize(tmp_path / "candidate", MANIFEST, roles=ROLES, caller_role="owner")
    assert caught.value.as_dict() == MailboxRefusal("unsupported_platform").as_dict()
    assert list(tmp_path.iterdir()) == []


def test_publish_inbox_and_retry(tmp_path):
    root, box = populated(tmp_path)
    with box:
        sent = box.publish(request())
        assert sent["message"]["created_at"] == "2026-11-16T12:00:00.000000Z"
        assert box.inbox("alpha/orchestrator")["messages"][0]["message"] == sent["message"]
        assert box.messages()["message"]["message"] == sent["message"]
        before = snapshot(root)
        with refusal("invalid_record"):
            box.publish(request())
        assert snapshot(root) == before
        box.publish(request("second"))
        assert box.status()["messages"] == 2


@pytest.mark.parametrize("raw,reason", [(b"{", "invalid_record"),
    (b'{"schema":1,"schema":2}', "invalid_record"), (b" " * 262145, "too_large"),
    (b"[" * 1000, "invalid_record"), (b'"\\ud800"', "invalid_record")],
    ids=["malformed", "duplicate", "oversized", "depth", "surrogate"])
def test_bad_manifest_refuses_without_mutation_then_retry(tmp_path, raw, reason):
    root = make_store(tmp_path)
    path = root / "manifest.json"
    original = path.read_bytes()
    path.write_bytes(raw)
    before = snapshot(root)
    with refusal(reason) as caught:
        mailbox(root)
    assert caught.value.reason == reason
    assert caught.value.next_action
    assert caught.value.code == 1
    assert snapshot(root) == before
    path.write_bytes(original)
    with mailbox(root) as box:
        assert box.status()["messages"] == 0


def test_unauthorized_and_unknown_host_have_no_writes(tmp_path):
    root, owner = populated(tmp_path)
    owner.close()
    before = snapshot(root)
    with mailbox(root, caller_role="reader") as reader:
        with refusal("unauthorized"):
            reader.publish(request())
    with mailbox(root) as writer:
        with refusal("unknown_host"):
            writer.bind({"endpoint": "alpha/root", "host": "unknown", "session": "s", "expected_generation": 0})
    assert snapshot(root) == before


def test_two_writers_busy_then_retry(tmp_path):
    root, box = populated(tmp_path)
    entered, release = Event(), Event()

    def held_clock():
        entered.set()
        assert release.wait(5)
        return NOW

    def first():
        with mailbox(root, clock=held_clock) as writer:
            return writer.publish(request("one"))

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(first)
            assert entered.wait(5)
            try:
                with pytest.raises(BusyError) as caught:
                    box.publish(request("two"))
                assert caught.value.reason == "busy"
            finally:
                release.set()
            assert future.result(timeout=5)["message"]["message_id"] == "one"
        box.publish(request("two"))
        assert len(box.messages()) == 2
        assert not (root / ".write.lock").exists()
    finally:
        release.set()
        box.close()


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_linked_lock_is_unsafe_not_busy(tmp_path, kind):
    root, box = populated(tmp_path)
    target = tmp_path / "target"
    target.write_bytes(b"external")
    lock = root / ".write.lock"
    try:
        if kind == "symlink":
            symlink_or_skip(target, lock)
        else:
            if os.name != "posix":
                pytest.skip("POSIX hardlink policy")
            os.link(target, lock)
        with refusal("unsafe_path"):
            box.publish(request())
        assert target.read_bytes() == b"external"
        lock.unlink()
        box.publish(request())
    finally:
        box.close()


def test_concurrent_component_swap_cannot_redirect_descriptor_read(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    with box:
        sent = box.publish(request())
    path = Path(sent["path"])
    expected = path.read_bytes()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "orchestrator").mkdir()
    evil = outside / "orchestrator" / path.name
    evil.write_bytes(b"outside")
    # Establish symlink capability before installing the deterministic OS seam.
    probe = tmp_path / "probe"
    symlink_or_skip(outside, probe, target_is_directory=True)
    probe.unlink()
    moved = root / "old-alpha"
    swapped = []

    def open_and_swap(name, flags, *args, **kwargs):
        fd = os.open(name, flags, *args, **kwargs)
        if name == "alpha" and not swapped:
            swapped.append(True)
            (root / "alpha").rename(moved)
            symlink_or_skip(outside, root / "alpha", target_is_directory=True)
        return fd

    with store_module.Store(root) as bound:
        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "open": open_and_swap}))
        try:
            assert bound.read(path) == expected
            with refusal("unsafe_path"):
                bound.read(path)
            assert evil.read_bytes() == b"outside"
        finally:
            monkeypatch.setattr(store_module, "os", os)
            (root / "alpha").unlink()
            moved.rename(root / "alpha")
        assert bound.read(path) == expected


def test_injected_route_policy_and_history_count_refuse_without_writes(tmp_path, monkeypatch):
    from dataclasses import replace

    root, box = populated(tmp_path)
    box.publish(request("first"))
    box.publish(request("second"))
    box.close()
    policy = replace(ROLES, vertical_routes=())
    with mailbox(root, roles=policy) as restricted:
        before = snapshot(root)
        with refusal("invalid_record"):
            restricted.publish(request("third"))
        assert snapshot(root) == before
    with mailbox(root) as normal:
        monkeypatch.setattr(store_module, "MAX_RECORDS", 1)
        with refusal("too_large"):
            normal.messages()
        monkeypatch.setattr(store_module, "MAX_RECORDS", 10000)
        assert len(normal.messages()) == 2


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_linked_record_refused_then_retry(tmp_path, kind):
    root = make_store(tmp_path)
    manifest = root / "manifest.json"
    saved = tmp_path / "saved.json"
    saved.write_bytes(manifest.read_bytes())
    manifest.unlink()
    if kind == "symlink":
        symlink_or_skip(saved, manifest)
    else:
        if os.name != "posix":
            pytest.skip("POSIX hardlink policy")
        os.link(saved, manifest)
    with refusal("unsafe_path"):
        mailbox(root)
    manifest.unlink()
    manifest.write_bytes(saved.read_bytes())
    with mailbox(root) as box:
        assert box.messages() == {}


def test_unsupported_platform_has_typed_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    monkeypatch.setattr(store_module, "pwd", None)
    with refusal("unsupported_platform"):
        mailbox(tmp_path / "mail")
    assert list(tmp_path.iterdir()) == []


def test_renamed_root_stays_bound_to_open_descriptor(tmp_path):
    root, box = populated(tmp_path)
    moved = tmp_path / "moved"
    root.rename(moved)
    root.mkdir()
    (root / "manifest.json").write_text("hostile replacement", encoding="utf-8")
    try:
        box.publish(request())
        assert len(list((moved / "alpha" / "orchestrator").glob("*.md"))) == 1
        assert list(root.iterdir()) == [root / "manifest.json"]
    finally:
        box.close()


def test_parity_through_legacy_public_api(tmp_path, monkeypatch):
    root, core = populated(tmp_path)
    monkeypatch.setattr(legacy, "timestamp", lambda: "2026-11-16T12:00:00.000000Z")
    old_root = tmp_path / "legacy"
    legacy.initialize(old_root, MANIFEST)
    old = legacy.Mailbox(old_root)
    for endpoint in ("alpha/front-door", "alpha/orchestrator"):
        bind(old, endpoint)
    try:
        for identifier in ("first", "second"):
            assert core.publish(request(identifier))["message"] == old.publish(request(identifier))["message"]
        assert core.status() == old.status()
        new_inbox, old_inbox = core.inbox("alpha/orchestrator"), old.inbox("alpha/orchestrator")
        for result in (new_inbox, old_inbox):
            for record in result["messages"]:
                record.pop("path")
        assert new_inbox == old_inbox
    finally:
        core.close()


def test_changed_manifest_refuses_existing_handle_before_write(tmp_path):
    root, box = populated(tmp_path)
    path = root / "manifest.json"
    original = path.read_bytes()
    path.write_bytes(b"{")
    before = snapshot(root)
    with box:
        with refusal("invalid_record"):
            box.publish(request())
        assert snapshot(root) == before
        path.write_bytes(original)
        assert box.publish(request())["message"]["message_id"] == "message"


def test_corrupt_delivery_history_refuses_before_receipt_write(tmp_path):
    root, box = populated(tmp_path)
    with box:
        box.publish(request())
        directory = tmp_path / "delivery"
        folder = directory / "reads" / "alpha" / "orchestrator"
        folder.mkdir(parents=True)
        bad = folder / "broken.json"
        bad.write_bytes(b"{")
        before = snapshot(tmp_path)
        receipt = {"endpoint": "alpha/orchestrator", "host": "test-host",
                   "session": "alpha/orchestrator", "generation": 1, "message_ids": ["message"]}
        with refusal("invalid_record"):
            box.write_delivery_receipt(directory, "reads", receipt)
        assert snapshot(tmp_path) == before
        bad.unlink()
        box.write_delivery_receipt(directory, "reads", receipt)
        assert box.delivery(directory, message_id="message")["message"]["state"] == "read"


@pytest.mark.parametrize("area", ["binding", "message", "delivery"])
def test_unexpected_hidden_entries_are_ambiguous(tmp_path, area):
    root, box = populated(tmp_path)
    with box:
        if area == "binding":
            folder = root / "bindings" / "alpha" / "front-door"
            call = lambda: box.bindings("alpha/front-door")
        elif area == "message":
            folder = root / "alpha" / "front-door"
            call = box.messages
        else:
            directory = tmp_path / "delivery"
            folder = directory / "reads" / "alpha" / "orchestrator"
            folder.mkdir(parents=True)
            call = lambda: box.delivery(directory)
        bad = folder / ".pending-hostile"
        bad.write_bytes(b"garbage")
        with refusal("invalid_record"):
            call()
        bad.unlink()
        call()


def test_sizes_refused_before_open_or_parse_and_then_retry(tmp_path, monkeypatch):
    root, box = populated(tmp_path)

    def no_read(*args):
        pytest.fail("oversized file must refuse before read allocation")

    path = root / "manifest.json"
    original = path.read_bytes()
    path.write_bytes(b" " * (store_module.MAX_BYTES + 1))
    try:
        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "read": no_read}))
        with refusal("too_large"):
            box.status()
        monkeypatch.setattr(store_module, "os", os)
        path.write_bytes(original)
        with refusal("too_large"):
            box.publish({**request(), "body": "x" * 262145})
        assert box.publish(request())["message"]["message_id"] == "message"
    finally:
        monkeypatch.setattr(store_module, "os", os)
        box.close()


def test_missing_host_port_and_timeout_have_fixed_refusal(tmp_path):
    root = make_store(tmp_path)

    def timeout(*args):
        raise TimeoutError("untrusted diagnostic")

    for hosts in (HOSTS, {"test-host": SimpleNamespace(git=timeout)}):
        with mailbox(root, hosts=hosts) as box:
            with refusal("host_unavailable") as caught:
                box.git(tmp_path, "rev-parse", "HEAD")
            assert "untrusted" not in str(caught.value)


def test_dispatch_reviewer_and_handoff_parity(tmp_path, monkeypatch):
    root, core = populated(tmp_path)
    monkeypatch.setattr(legacy, "timestamp", lambda: "2026-11-16T12:00:00.000000Z")
    old_root = tmp_path / "old"
    legacy.initialize(old_root, MANIFEST)
    old = legacy.Mailbox(old_root)
    for endpoint in ("alpha/front-door", "alpha/orchestrator"):
        bind(old, endpoint)
    brief_path = tmp_path / "brief.md"
    brief_path.write_text("bounded brief", encoding="utf-8")
    brief = {"path": str(brief_path), "sha256": hashlib.sha256(brief_path.read_bytes()).hexdigest()}
    try:
        for box in (core, old):
            bind(box, "alpha/lane/review")
            box.publish({**request("dispatch"), "from": "alpha/orchestrator", "to": "alpha/lane/review",
                         "session": "alpha/orchestrator", "type": "dispatch", "brief": brief})
            box.publish({**request("accepted"), "from": "alpha/lane/review", "to": "alpha/orchestrator",
                         "session": "alpha/lane/review", "type": "ack", "acknowledgment": "accepted",
                         "in_reply_to": "dispatch"})
            box.publish({**request("reviewed"), "from": "alpha/lane/review", "to": "alpha/orchestrator",
                         "session": "alpha/lane/review", "type": "review", "in_reply_to": "dispatch",
                         "result": {"source_revision": "a" * 40, "source_tree": "b" * 40,
                                    "checks": [{"check": "review", "outcome": "pass", "reference": "record"}]}})
            draft = box.draft_handoff({"endpoint": "alpha/lane/review", "host": "test-host",
                                      "session": "replacement", "outgoing_stopped": True})
            bound = box.bind(draft)
            assert bound["generation"] == 2 and not bound["ready"]
            ack = {key: bound[key] for key in ("endpoint", "generation", "session", "checkpoint_sha256")}
            assert box.acknowledge_handoff(ack)["ready"]
        assert core.status() == old.status()
        assert [r["message"] for r in core.messages().values()] == [r["message"] for r in old.messages().values()]
    finally:
        core.close()


def test_unicode_body_keeps_legacy_wire_parity(tmp_path):
    root, box = populated(tmp_path)
    with box:
        body = "\U0001f600" * 40000
        result = box.publish({**request(), "body": body})
        assert box.inbox("alpha/orchestrator")["messages"][0]["message"]["body"] == body
        assert Path(result["path"]).stat().st_size < 262144


@pytest.mark.parametrize("name,args", [("reply", ({}, {})),
    ("dispatch_history", ({"broken": {}},)), ("open_job_requests", ({"broken": {}},))])
def test_public_record_helpers_never_leak_raw_errors(name, args):
    with refusal("invalid_record"):
        getattr(mail.Mailbox, name)(*args)


def test_new_binding_refuses_corrupt_mail_then_retry(tmp_path):
    root = make_store(tmp_path)
    bad = root / "alpha" / "front-door" / "bad.md"
    bad.write_bytes(b"invalid")
    with mailbox(root) as box:
        before = snapshot(root)
        with refusal("invalid_record"):
            bind(box, "alpha/front-door")
        assert snapshot(root) == before
        bad.unlink()
        assert bind(box, "alpha/front-door")["ready"]


def test_write_failure_closes_descriptors_and_removes_partial_directories(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    box.publish(request())

    class FailedWrite:
        def __init__(self):
            self.opened = set()

        def open(self, *args, **kwargs):
            fd = os.open(*args, **kwargs)
            self.opened.add(fd)
            return fd

        def dup(self, fd):
            copied = os.dup(fd)
            self.opened.add(copied)
            return copied

        def close(self, fd):
            os.close(fd)
            self.opened.discard(fd)

        def write(self, *args):
            raise OSError("private diagnostic")

    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["message"]}
    failure = FailedWrite()
    try:
        proxy = SimpleNamespace(**{**vars(os), "open": failure.open, "dup": failure.dup,
                                   "close": failure.close, "write": failure.write})
        monkeypatch.setattr(store_module, "os", proxy)
        with refusal("io"):
            box.write_delivery_receipt(tmp_path / "delivery", "reads", receipt)
        assert not failure.opened
        with refusal("io"):
            mail.initialize(tmp_path / "failed", MANIFEST, roles=ROLES, caller_role="owner")
        assert not failure.opened
        monkeypatch.setattr(store_module, "os", os)
        assert not (tmp_path / "delivery").exists()
        assert not (tmp_path / "failed").exists()
        box.write_delivery_receipt(tmp_path / "delivery", "reads", receipt)
        mail.initialize(tmp_path / "failed", MANIFEST, roles=ROLES, caller_role="owner")
    finally:
        monkeypatch.setattr(store_module, "os", os)
        box.close()


def test_aggregate_history_budget_refuses_before_next_record_allocation(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    with box:
        box.publish(request("one"))
        box.publish(request("two"))
        sizes = [Path(record["path"]).stat().st_size for record in box.messages().values()]
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", max(sizes))
        with refusal("too_large"):
            box.messages()
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", 67108864)
        assert len(box.messages()) == 2


def test_status_evidence_and_transport_helpers(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    raw = b"R  old\x00new\x00 M changed\x00"
    assert primitives.status_entries(raw) == 2
    sha = hashlib.sha256(raw).hexdigest()
    with store_module.Store(root) as bound:
        path = bound.publish_status_evidence(tmp_path / "evidence", raw, sha)
        assert bound.read(path) == raw
        assert bound.publish_status_evidence(tmp_path / "evidence", raw, sha) == path
        Path(path).write_bytes(b"changed")
        with refusal("invalid_record"):
            bound.publish_status_evidence(tmp_path / "evidence", raw, sha)
    result = {"messages": [{"message": {"message_id": "one"}}, {"message": {"message_id": "two"}}],
              "remaining": 0, "next_after": None}
    render = lambda row: json.dumps(row).encode("utf-8")
    single = {**result, "messages": result["messages"][:1], "remaining": 1, "next_after": "one"}
    monkeypatch.setattr(primitives, "MAX_INBOX_RESPONSE_BYTES", len(render(single)))
    assert primitives.bounded_inbox(result, render) == single


def test_receipt_clock_metadata_cannot_be_supplied_by_caller(tmp_path):
    root, box = populated(tmp_path)
    with box:
        box.publish(request())
        receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
                   "generation": 1, "message_ids": ["message"], "at": "2020-01-01T00:00:00Z"}
        with refusal("invalid_record"):
            box.write_delivery_receipt(tmp_path / "delivery", "reads", receipt)
        assert not (tmp_path / "delivery").exists()


def test_handoff_request_list_limit_precedes_expansion(tmp_path):
    root, box = populated(tmp_path)
    with box:
        before = snapshot(root)
        brief = {"path": str(tmp_path / "missing.md"), "sha256": "a" * 64}
        with refusal("too_large"):
            box.draft_handoff({"endpoint": "alpha/front-door", "host": "test-host", "session": "next",
                               "outgoing_stopped": True, "briefs": [brief] * 257})
        assert snapshot(root) == before


def test_brief_refusal_traceback_never_echoes_rejected_path(tmp_path):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        outside = tmp_path.parent / "untrusted-diagnostic-marker.md"
        brief = {"path": str(outside), "sha256": "a" * 64}
        with refusal("invalid_record") as caught:
            box.brief(brief)
        shown = "".join(traceback.format_exception(type(caught.value), caught.value, caught.tb))
        assert "untrusted-diagnostic-marker" not in shown


@pytest.mark.parametrize("value", [None, 7, [], {}, bytearray(b"{}")],
                         ids=["none", "integer", "array", "object", "bytearray"])
def test_strict_json_wrong_type_is_explicit_typed_refusal(value):
    with refusal("invalid_record") as caught:
        primitives.strict_json(value)
    assert caught.value.as_dict() == MailboxRefusal("invalid_record").as_dict()


@pytest.mark.parametrize("sender", [[], "sender", 7], ids=["array", "text", "integer"])
def test_operation_wrong_sender_type_refuses_without_write_then_retries(tmp_path, sender):
    root, box = populated(tmp_path)
    with box:
        box.publish(request())
        before = snapshot(tmp_path)
        with refusal("invalid_record") as caught:
            box.record_read(tmp_path / "delivery", sender, ["message"])
        assert caught.value.code == 1 and caught.value.next_action
        assert snapshot(tmp_path) == before
        valid = {"from": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
                 "binding_generation": 1}
        box.record_read(tmp_path / "delivery", valid, ["message"])
        assert box.delivery(tmp_path / "delivery", message_id="message")["message"]["state"] == "read"


@pytest.mark.parametrize("header", [[], 7, "header", None], ids=["array", "integer", "text", "null"])
def test_messages_wrong_header_type_refuses_without_write_then_retries(tmp_path, header):
    root, box = populated(tmp_path)
    with box:
        sent = box.publish(request())
        path = Path(sent["path"])
        original = path.read_bytes()
        path.write_bytes(b"---\n" + json.dumps(header).encode("utf-8") + b"\n---\n\nbody")
        before = snapshot(root)
        with refusal("invalid_record") as caught:
            box.messages()
        assert caught.value.code == 1 and caught.value.next_action
        assert snapshot(root) == before
        path.write_bytes(original)
        assert box.messages()["message"]["message"] == sent["message"]


@pytest.mark.parametrize("state", [[], {}, 7, None], ids=["array", "object", "integer", "null"])
def test_delivery_wrong_wake_state_type_refuses_without_write_then_retries(tmp_path, state):
    root, box = populated(tmp_path)
    directory = tmp_path / "delivery"
    with box:
        box.publish(request())
        folder = directory / "wakes" / "alpha" / "orchestrator"
        folder.mkdir(parents=True)
        path = folder / "wake.json"
        receipt = {"schema": primitives.DELIVERY_RECEIPT, "endpoint": "alpha/orchestrator",
                   "host": "test-host", "session": "alpha/orchestrator", "generation": 1,
                   "at": "2026-11-16T12:00:00.000000Z", "message_ids": ["message"],
                   "wake_id": "wake", "state": state}
        path.write_text(json.dumps(receipt), encoding="utf-8")
        before = snapshot(tmp_path)
        with refusal("invalid_record") as caught:
            box.delivery(directory, message_id="message")
        assert caught.value.code == 1 and caught.value.next_action
        assert snapshot(tmp_path) == before
        path.write_text(json.dumps({**receipt, "state": "started"}), encoding="utf-8")
        assert box.delivery(directory, message_id="message")["message"]["state"] == "woken"


@pytest.mark.parametrize("name,args", [
    ("reply", ({"in_reply_to": []}, {})),
    ("reply", ([], {})),
    ("dispatch_history", ({"message": {"message": {"type": []}}},)),
    ("dispatch_history", ({"message": {"message": {"type": "result", "in_reply_to": []}}},)),
    ("open_job_requests", ({"message": {"message": {"type": "job_receipt", "receipt": {"state": []}}}},)),
], ids=["reply-list-id", "reply-array", "history-list-type", "history-list-id", "jobs-list-state"])
def test_validation_helpers_wrong_field_types_have_typed_refusal(name, args):
    with refusal("invalid_record") as caught:
        getattr(mail.Mailbox, name)(*args)
    assert caught.value.as_dict() == MailboxRefusal("invalid_record").as_dict()


@pytest.mark.parametrize("rendered", [None, 7], ids=["none", "integer"])
def test_validation_inbox_render_type_has_typed_refusal(rendered):
    result = {"messages": [], "remaining": 0, "next_after": None}
    with refusal("invalid_record"):
        primitives.bounded_inbox(result, lambda row: rendered)


@pytest.mark.parametrize("result", [[], {"messages": None, "remaining": 0},
    {"messages": [], "remaining": []}, {"messages": [[]], "remaining": 0}],
    ids=["array", "messages", "remaining", "row"])
def test_validation_inbox_shape_has_typed_refusal(result):
    with refusal("invalid_record"):
        primitives.bounded_inbox(result, lambda row: b"{}")


def test_operation_unhashable_host_selector_has_typed_refusal(tmp_path):
    root = make_store(tmp_path)
    with mailbox(root, host=[]) as box:
        with refusal("invalid_record"):
            box.git(tmp_path, "rev-parse", "HEAD")


def replacement_request(tmp_path, generation):
    brief = tmp_path / "replacement.md"
    brief.write_bytes(b"replacement brief")
    checkpoint = {"outgoing_stopped": True, "briefs": [{"path": str(brief),
        "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}], "sources": [], "lease_refs": [],
        "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
    return {"endpoint": "alpha/front-door", "host": "test-host", "session": "replacement-" + str(generation),
            "expected_generation": generation, "checkpoint": checkpoint}


def handoff_ack(binding):
    return {key: binding[key] for key in ("endpoint", "generation", "session", "checkpoint_sha256")}


@pytest.mark.parametrize("ascii_strings", [False, True])
@pytest.mark.parametrize("value", ["", "plain ASCII " * 1024, ''.join(chr(i) for i in range(128)),
    "quote\"\\\b\f\n\r\t\x00\x1f\x7f", 'printable "quotes" and \\slashes',
    "é中😀", ["a\n", {"quoted\"": "é😀"}]],
    ids=["empty", "ordinary", "all-ascii", "escapes", "printable-escapes", "unicode", "nested"])
def test_bounded_tree_string_wire_boundaries_and_retry(value, ascii_strings):
    def utf8_budget(item):
        if type(item) is str:
            return len(item.encode("utf-8")) + 2
        if type(item) is dict:
            return 2 + max(0, len(item) - 1) + len(item) + sum(
                utf8_budget(key) + utf8_budget(entry) for key, entry in item.items())
        return 2 + max(0, len(item) - 1) + sum(utf8_budget(entry) for entry in item)

    size = (len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))
            if ascii_strings else utf8_budget(value))
    for _ in range(2):
        with refusal("too_large") as caught:
            primitives.bounded_tree(value, limit=size - 1, ascii_strings=ascii_strings)
        assert caught.value.as_dict() == MailboxRefusal("too_large").as_dict()
        assert primitives.bounded_tree(value, limit=size, ascii_strings=ascii_strings) is None


@pytest.mark.parametrize("ascii_strings", [False, True])
@pytest.mark.parametrize("value,limit,reason", [("a\ud800", 1, "too_large"),
    ("\n\n\udfff", 3, "invalid_record"), ("a\ud800", 100, "invalid_record")])
def test_bounded_tree_surrogate_refusal_precedence(value, limit, reason, ascii_strings):
    # An escaped newline can exhaust the budget before the later surrogate.
    expected = "too_large" if ascii_strings and value.startswith("\n") else reason
    with refusal(expected) as caught:
        primitives.bounded_tree(value, limit=limit, ascii_strings=ascii_strings)
    assert caught.value.as_dict() == MailboxRefusal(expected).as_dict()


def read_binding_surface(box, surface):
    if surface == "status":
        return box.status()["bindings"]["alpha/front-door"]
    if surface == "inbox":
        return box.inbox("alpha/front-door")["binding"]
    if surface == "binding_view":
        return box.binding_view("alpha/front-door")["binding"]
    return box.fence(request())


@pytest.mark.parametrize("surface", ["status", "inbox", "binding_view", "fence"])
def test_binding_history_read_once_per_operation_then_fresh_retry(tmp_path, monkeypatch, surface):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        binding = box.bind(replacement_request(tmp_path, 1))
        reads = []
        original_read = store_module.Store.read

        def counted_read(self, path, **kwargs):
            if path.suffix == ".json" and path.parent.name == "front-door":
                reads.append(path.name)
            return original_read(self, path, **kwargs)

        monkeypatch.setattr(store_module.Store, "read", counted_read)
        sender = {**request(), "session": binding["session"], "binding_generation": 2}

        def observe():
            reads.clear()
            if surface == "fence":
                return box.fence(sender)
            return read_binding_surface(box, surface)

        before = snapshot(root)
        if surface == "fence":
            with refusal("invalid_record"):
                observe()
        else:
            assert observe()["ready"] is False
        assert reads == ["000001.json", "000002.json"]
        assert snapshot(root) == before
        box.acknowledge_handoff(handoff_ack(binding))
        result = observe()
        assert result == primitives.binding_record(binding) if surface == "fence" else result["ready"] is True
        assert reads == ["000001.json", "000002.json"]
        path = root / "bindings" / "alpha" / "front-door" / "000001.json"
        raw = path.read_bytes()
        path.write_bytes(b"{")
        before = snapshot(root)
        with refusal("invalid_record") as caught:
            observe()
        assert caught.value.as_dict() == MailboxRefusal("invalid_record").as_dict()
        assert snapshot(root) == before
        path.write_bytes(raw)
        observe()
        assert reads == ["000001.json", "000002.json"]


@pytest.mark.parametrize("kind", ["info", "dispatch"])
def test_publish_validates_sender_and_recipient_histories_once(tmp_path, monkeypatch, kind):
    root = make_store(tmp_path)
    brief_path = tmp_path / "dispatch.md"
    brief_path.write_bytes(b"dispatch brief")
    brief = {"path": str(brief_path), "sha256": hashlib.sha256(b"dispatch brief").hexdigest()}
    with mailbox(root) as box:
        bind(box, "alpha/orchestrator")
        bind(box, "alpha/lane/review")
        reads = []
        original_read = store_module.Store.read

        def counted_read(self, path, **kwargs):
            if path.suffix == ".json" and "bindings" in path.parts:
                reads.append(path.relative_to(root).as_posix())
            return original_read(self, path, **kwargs)

        monkeypatch.setattr(store_module.Store, "read", counted_read)
        result = box.publish({**request(), "from": "alpha/orchestrator", "session": "alpha/orchestrator",
                              "to": "alpha/lane/review", "type": kind, "brief": brief})
        assert result["message"]["type"] == kind
        assert reads == ["bindings/alpha/orchestrator/000001.json", "bindings/alpha/lane/review/000001.json"]


def test_binding_history_reuse_is_local_to_concurrent_operations(tmp_path):
    root, box = populated(tmp_path)
    with box:
        binding = box.bind(replacement_request(tmp_path, 1))

        def observe(endpoint):
            return box.inbox(endpoint)["binding"]

        endpoints = ["alpha/front-door", "alpha/orchestrator"] * 8
        before = snapshot(root)
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(observe, endpoints))
        assert snapshot(root) == before
        assert [(result["endpoint"], result["generation"], result["ready"]) for result in results] == [
            (endpoint, 2 if endpoint == "alpha/front-door" else 1, endpoint != "alpha/front-door")
            for endpoint in endpoints]
        box.acknowledge_handoff(handoff_ack(binding))
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert all(result["ready"] for result in pool.map(observe, endpoints))


@pytest.mark.parametrize("surface", ["status", "inbox", "binding_view", "fence", "ready"])
def test_binding_history_reuse_preserves_reads_during_owner_lock(tmp_path, surface):
    root, box = populated(tmp_path)
    entered, release = Event(), Event()
    with box, mailbox(root) as holder:
        binding = box.current_binding("alpha/front-door")

        def hold():
            with holder.store.evidence_transaction():
                entered.set()
                assert release.wait(5)

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(hold)
            try:
                assert entered.wait(5)
                before = snapshot(tmp_path)
                result = box.ready(binding) if surface == "ready" else read_binding_surface(box, surface)
                assert result is True if surface == "ready" else result["generation"] == 1
                assert snapshot(tmp_path) == before
            finally:
                release.set()
                future.result(timeout=5)
        result = box.ready(binding) if surface == "ready" else read_binding_surface(box, surface)
        assert result is True if surface == "ready" else result["generation"] == 1


def test_binding_append_byte_budget_refuses_without_publication_then_retries(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    control = tmp_path / "control"
    mail.initialize(control, MANIFEST, roles=ROLES, caller_role="owner")
    request_next = replacement_request(tmp_path, 1)
    with mailbox(control) as other:
        bind(other, "alpha/front-door")
        other.bind(request_next)
    folder = root / "bindings" / "alpha" / "front-door"
    candidate = (control / "bindings" / "alpha" / "front-door" / "000002.json").stat().st_size
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        retained = (folder / "000001.json").stat().st_size
        total = retained + candidate
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", total - 1)
        assert len(box.bindings("alpha/front-door")) == 1
        before = snapshot(root)
        with refusal("too_large"):
            box.bind(request_next)
        assert snapshot(root) == before
        assert len(box.bindings("alpha/front-door")) == 1
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", total)
        assert box.bind(request_next)["ready"] is False
        assert len(box.bindings("alpha/front-door")) == 2


def test_handoff_ack_byte_budget_includes_ack_bytes_then_retries(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        binding = box.bind(replacement_request(tmp_path, 1))
        ack = handoff_ack(binding)
        folder = root / "bindings" / "alpha" / "front-door"
        retained = sum(path.stat().st_size for path in folder.iterdir())
        candidate = len(primitives.encoded(ack) + b"\n")
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", retained + candidate - 1)
        before = snapshot(root)
        with refusal("too_large"):
            box.acknowledge_handoff(ack)
        assert snapshot(root) == before
        assert box.ready(binding) is False
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", retained + candidate)
        assert box.acknowledge_handoff(ack)["ready"]
        assert box.ready(binding)
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", retained + candidate - 1)
        with refusal("too_large"):
            box.bindings("alpha/front-door")


def test_message_append_byte_budget_refuses_without_publication_then_retries(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    with box:
        first = box.publish(request("one"))
        size = Path(first["path"]).stat().st_size
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", size * 2 - 1)
        before = snapshot(root)
        with refusal("too_large"):
            box.publish(request("two"))
        assert snapshot(root) == before
        assert len(box.messages()) == 1
        monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", size * 2)
        box.publish(request("two"))
        assert len(box.messages()) == 2


def test_receipt_append_byte_budget_refuses_without_publication_then_retries(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    directory = tmp_path / "delivery"
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["message"] * 4}
    with box:
        sent = box.publish(request())
        box.write_delivery_receipt(directory, "reads", receipt)
        folder = directory / "reads" / "alpha" / "orchestrator"
        size = next(folder.glob("*.json")).stat().st_size
        assert size * 2 - 1 >= Path(sent["path"]).stat().st_size
        monkeypatch.setattr(delivery_module, "MAX_HISTORY_BYTES", size * 2 - 1)
        before = snapshot(tmp_path)
        with refusal("too_large"):
            box.write_delivery_receipt(directory, "reads", receipt)
        assert snapshot(tmp_path) == before
        assert box.delivery(directory, message_id="message")["message"]["state"] == "read"
        monkeypatch.setattr(delivery_module, "MAX_HISTORY_BYTES", size * 2)
        box.write_delivery_receipt(directory, "reads", receipt)
        assert len(box.delivery_receipts(directory, "reads", "alpha/orchestrator", box.messages())) == 2


@pytest.mark.parametrize("limit", [5, 6], ids=["binding-full", "ack-full"])
def test_binding_and_ack_share_entry_census(tmp_path, monkeypatch, limit):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        monkeypatch.setattr(store_module, "MAX_RECORDS", limit)
        for generation in (1, 2):
            binding = box.bind(replacement_request(tmp_path, generation))
            box.acknowledge_handoff(handoff_ack(binding))
        if limit == 5:
            before = snapshot(root)
            with refusal("too_large"):
                box.bind(replacement_request(tmp_path, 3))
        else:
            binding = box.bind(replacement_request(tmp_path, 3))
            assert binding["ready"] is False
            before = snapshot(root)
            with refusal("too_large"):
                box.acknowledge_handoff(handoff_ack(binding))
        assert snapshot(root) == before
        folder = root / "bindings" / "alpha" / "front-door"
        assert len(list(folder.iterdir())) == limit
        assert len(box.bindings("alpha/front-door")) == (3 if limit == 5 else 4)


@pytest.mark.parametrize("area", ["binding", "message"])
def test_recognized_pending_entries_consume_admission_capacity(tmp_path, monkeypatch, area):
    root, box = populated(tmp_path)
    with box:
        if area == "binding":
            folder = root / "bindings" / "alpha" / "front-door"
            candidate = replacement_request(tmp_path, 1)
            action = lambda: box.bind(candidate)
        else:
            box.publish(request("one"))
            folder = root / "alpha" / "orchestrator"
            action = lambda: box.publish(request("two"))
        (folder / (".pending-" + "a" * 32)).write_bytes(b"pending")
        monkeypatch.setattr(store_module, "MAX_RECORDS", 2)
        before = snapshot(root)
        with refusal("too_large"):
            action()
        assert snapshot(root) == before
        monkeypatch.setattr(store_module, "MAX_RECORDS", 3)
        action()
        assert len(list(folder.iterdir())) == 3
        assert len(box.bindings("alpha/front-door") if area == "binding" else box.messages()) == 2


def test_receipt_pending_entries_and_owned_lock_share_census(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    directory = tmp_path / "delivery"
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["message"]}
    with box:
        box.publish(request())
        box.write_delivery_receipt(directory, "reads", receipt)
        folder = directory / "reads" / "alpha" / "orchestrator"
        (folder / (".pending-" + "b" * 32)).write_bytes(b"pending")
        monkeypatch.setattr(store_module, "MAX_RECORDS", 3)
        box.write_delivery_receipt(directory, "reads", receipt)
        before = snapshot(tmp_path)
        with refusal("too_large"):
            box.write_delivery_receipt(directory, "reads", receipt)
        assert snapshot(tmp_path) == before
        assert len(list(folder.iterdir())) == 3
        assert len(box.delivery_receipts(directory, "reads", "alpha/orchestrator", box.messages())) == 2


@pytest.mark.parametrize("replies", [4, 12], ids=["four", "twelve"])
def test_history_read_validation_work_is_linear_and_standalone_reply_validates(tmp_path, monkeypatch, replies):
    root, box = populated(tmp_path)
    with box:
        box.publish(request("original"))
        for index in range(replies):
            box.publish({**request("reply-" + str(index)), "from": "alpha/orchestrator",
                         "to": "alpha/front-door", "session": "alpha/orchestrator", "in_reply_to": "original"})
        counts = {"full": 0, "shape": 0}
        validate_message = mail.Mailbox.validate_message
        message_types = primitives.message_types

        def observed_message(self, *args, **kwargs):
            counts["full"] += 1
            return validate_message(self, *args, **kwargs)

        def observed_types(message):
            counts["shape"] += 1
            return message_types(message)

        monkeypatch.setattr(mail.Mailbox, "validate_message", observed_message)
        monkeypatch.setattr(primitives, "message_types", observed_types)
        records = box.messages()
        assert counts["full"] == replies + 1
        assert counts["shape"] <= 2 * (replies + 1)
        before = counts["shape"]
        assert mail.Mailbox.reply(records["reply-0"]["message"], records)["message_id"] == "original"
        assert counts["shape"] - before == replies + 1
        invalid = {**records, "broken": {"message": []}}
        with refusal("invalid_record"):
            mail.Mailbox.reply(records["reply-0"]["message"], invalid)


def test_two_writers_last_byte_budget_slot_then_retry_refuses(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    first = box.publish(request("one"))
    size = Path(first["path"]).stat().st_size
    monkeypatch.setattr(mail, "MAX_HISTORY_BYTES", size * 2)
    entered, release = Event(), Event()

    def held_clock():
        entered.set()
        assert release.wait(5)
        return NOW

    def writer():
        with mailbox(root, clock=held_clock) as other:
            return other.publish(request("two"))

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(writer)
            assert entered.wait(5)
            try:
                with pytest.raises(BusyError):
                    box.publish(request("tri"))
            finally:
                release.set()
            assert future.result(timeout=5)["message"]["message_id"] == "two"
        before = snapshot(root)
        with refusal("too_large"):
            box.publish(request("tri"))
        assert snapshot(root) == before
        assert len(box.messages()) == 2
    finally:
        release.set()
        box.close()


@pytest.mark.parametrize("field,value,reason", [
    ("exit_code", [], "invalid_record"), ("exit_code", {"value": 0}, "invalid_record"),
    ("exit_code", False, "invalid_record"), ("timed_out", [], "invalid_record"),
    ("timed_out", None, "invalid_record"), ("timed_out", 0, "invalid_record"),
    ("exit_code", [None] * 10001, "too_large"), ("timed_out", [None] * 10001, "too_large"),
], ids=["exit-array", "exit-object", "exit-bool", "timeout-array", "timeout-null", "timeout-int",
        "exit-container-limit", "timeout-container-limit"])
def test_wake_field_types_and_container_limits_refuse_without_poisoning(tmp_path, field, value, reason):
    root, box = populated(tmp_path)
    directory = tmp_path / "delivery"
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["message"], "wake_id": "wake", "state": "started"}
    with box:
        box.publish(request())
        before = snapshot(tmp_path)
        with refusal(reason):
            box.write_delivery_receipt(directory, "wakes", {**receipt, field: value})
        assert snapshot(tmp_path) == before
        assert box.delivery(directory, message_id="message")["message"]["state"] == "published"
        valid = {**receipt, "exit_code": None, "timed_out": False}
        box.write_delivery_receipt(directory, "wakes", valid)
        folder = directory / "wakes" / "alpha" / "orchestrator"
        path = next(folder.glob("*.json"))
        original = path.read_bytes()
        stored = json.loads(original)
        path.write_text(json.dumps({**stored, field: value}), encoding="utf-8")
        before = snapshot(tmp_path)
        with refusal("invalid_record"):
            box.delivery(directory, message_id="message")
        assert snapshot(tmp_path) == before
        path.write_bytes(original)
        assert box.delivery(directory, message_id="message")["message"]["state"] == "woken"


def test_serialized_container_limit_equals_reader_limit():
    accepted = [None] * 10000
    assert primitives.strict_json(primitives.encoded(accepted)) == accepted
    with refusal("too_large"):
        primitives.encoded([None] * 10001)


def test_serialized_depth_limit_equals_reader_limit():
    value = []
    for _ in range(31):
        value = [value]
    assert primitives.strict_json(primitives.encoded(value)) == value
    with refusal("invalid_record"):
        primitives.encoded([value])


def test_encoded_dictionary_checks_complete_size_before_serializing(monkeypatch):
    overhead = len(json.dumps({"a": "", "b": ""}, separators=(",", ":")).encode("utf-8"))
    oversized = {"a": "x" * (primitives.MAX_BYTES - overhead + 1), "b": ""}

    def cannot_encode(*args, **kwargs):
        pytest.fail("encoded size must refuse before serialization allocation")

    monkeypatch.setattr(primitives, "json", SimpleNamespace(**{**vars(json), "dumps": cannot_encode}))
    with refusal("too_large"):
        primitives.encoded(oversized)


def test_encoded_exact_byte_boundary_roundtrips():
    overhead = len(json.dumps({"a": "", "b": None}, separators=(",", ":")).encode("utf-8"))
    value = {"a": "x" * (primitives.MAX_BYTES - overhead), "b": None}
    raw = primitives.encoded(value)
    assert len(raw) == primitives.MAX_BYTES
    assert primitives.strict_json(raw) == value
    with refusal("too_large"):
        primitives.encoded({**value, "a": value["a"] + "x"})


def test_disappearing_pending_entry_never_hides_retained_binding(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        folder = root / "bindings" / "alpha" / "front-door"
        pending = folder / (".pending-" + "c" * 32)
        pending.write_bytes(b"pending")
        record = folder / "000001.json"
        retained = record.read_bytes()

        class DisappearingEntries:
            def __init__(self, fd):
                self.entries = os.scandir(fd)

            def __enter__(self):
                return self

            def __iter__(self):
                for entry in self.entries:
                    if entry.name == pending.name:
                        pending.unlink()
                    yield entry

            def __exit__(self, *error):
                self.entries.close()

        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "scandir": DisappearingEntries}))
        try:
            with refusal("missing"):
                box.bindings("alpha/front-door")
        finally:
            monkeypatch.setattr(store_module, "os", os)
        assert record.read_bytes() == retained
        assert len(box.bindings("alpha/front-door")) == 1


def test_trusted_parent_mode_checked_at_construction_and_each_use(tmp_path):
    root = make_store(tmp_path)
    brief = tmp_path / "brief.md"
    brief.write_bytes(b"brief")
    reference = {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}
    with mailbox(root) as box:
        original_mode = tmp_path.stat().st_mode & 0o777
        try:
            tmp_path.chmod(0o777)
            with refusal("unsafe_path"):
                mailbox(root)
            with refusal("unsafe_path"):
                box.brief(reference)
        finally:
            tmp_path.chmod(original_mode)
        assert box.brief(reference) == b"brief"


def test_initialization_refuses_writable_parent_before_creating_root(tmp_path):
    make_store(tmp_path)
    candidate = tmp_path / "new-mail"
    original_mode = tmp_path.stat().st_mode & 0o777
    try:
        tmp_path.chmod(0o777)
        with refusal("unsafe_path"):
            mail.initialize(candidate, MANIFEST, roles=ROLES, caller_role="owner")
        assert not candidate.exists()
    finally:
        tmp_path.chmod(original_mode)
    mail.initialize(candidate, MANIFEST, roles=ROLES, caller_role="owner")
    with mailbox(candidate) as box:
        assert box.messages() == {}


@pytest.mark.parametrize("readiness", [[], None, 1, "readiness"], ids=["array", "null", "integer", "text"])
def test_checkpoint_assignments_readiness_types_refuse_before_host_then_retry(tmp_path, readiness):
    root = make_store(tmp_path)
    checkpoint = replacement_request(tmp_path, 1)["checkpoint"]
    worktree = str(tmp_path / "worktree")
    checkpoint.update({"pending_message_ids": ["dispatch"], "lease_refs": ["lease"], "sources": [{
        "worktree": worktree, "source_revision": "a" * 40, "source_tree": "b" * 40, "dirty_state": "clean"}]})
    calls = []

    def git(path, *args):
        calls.append(args)
        return "branch" if args[0] == "branch" else "a" * 40 if args[-1] == "HEAD" else "b" * 40 if args[-1] == "HEAD^{tree}" else ""

    records = {"dispatch": {"message": {"message_id": "dispatch", "type": "dispatch", "from": "alpha/orchestrator",
        "to": "alpha/lane/review", "brief": checkpoint["briefs"][0]}},
        "accepted": {"message": {"type": "ack", "acknowledgment": "accepted", "in_reply_to": "dispatch",
                                  "readiness": readiness}}}
    with mailbox(root, hosts={"test-host": SimpleNamespace(git=git)}) as box:
        before = snapshot(tmp_path)
        with refusal("invalid_record"):
            box.checkpoint_assignments("alpha/orchestrator", checkpoint, records)
        assert not calls
        assert snapshot(tmp_path) == before
        records["accepted"]["message"]["readiness"] = {"worktree": worktree, "branch": "branch", "lease_ref": "lease"}
        assert box.checkpoint_assignments("alpha/orchestrator", checkpoint, records) == []


def active_handoff_store(tmp_path, name="mail"):
    root = make_store(tmp_path, name)
    manifest = json.loads((root / "manifest.json").read_bytes())
    manifest["endpoints"]["alpha/lane/work"] = {"kind": "implementer"}
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    brief = replacement_request(tmp_path, 1)["checkpoint"]["briefs"][0]
    worktree = str(tmp_path / "worktree")
    status = b" M owned.py\0"
    calls = []

    def git(path, *args):
        if args == ("rev-parse", "--show-toplevel"):
            return worktree
        return "branch" if args[0] == "branch" else "a" * 40 if args[-1] == "HEAD" else "b" * 40 if args[-1] == "HEAD^{tree}" else ""

    def witness(path, evidence_dir):
        calls.append(evidence_dir)
        result = {"worktree": str(path), "source_revision": "a" * 40, "source_tree": "b" * 40,
                  "dirty_state_sha256": hashlib.sha256(status).hexdigest(), "dirty_entries": 1}
        if evidence_dir is not None:
            with store_module.Store(root) as store:
                result["dirty_evidence"] = store.publish_status_evidence(evidence_dir, status, result["dirty_state_sha256"])
        return result

    hosts = {"test-host": SimpleNamespace(git=git, source_witness=witness, observe_readiness=lambda value: True)}
    with mailbox(root, hosts=hosts) as box:
        for endpoint in ("alpha/front-door", "alpha/orchestrator", "alpha/lane/work"):
            bind(box, endpoint)
        box.publish({**request("dispatch"), "from": "alpha/orchestrator", "to": "alpha/lane/work",
                     "session": "alpha/orchestrator", "type": "dispatch", "brief": brief})
        readiness = {"worktree": worktree, "branch": "branch", "base_revision": "a" * 40,
            "lease_ref": "refs/aegis/lanes/work", "lease_oid": "c" * 40,
            "lease_expires_at": "2099-01-01T00:00:00Z", "owned_paths": ["owned.py"],
            "scan_workspace": worktree, "scan_evidence": "scan", "enforcement_tier": "advisory", "hook_evidence": "hook"}
        box.publish({**request("accepted"), "from": "alpha/lane/work", "to": "alpha/orchestrator",
            "session": "alpha/lane/work", "type": "ack", "acknowledgment": "accepted",
            "in_reply_to": "dispatch", "readiness": readiness})
    roles = RoleTables(writes={**dict(ROLES.writes), "owner": ROLES.writes["owner"] | {"source_witness"}})
    return root, hosts, roles, calls, worktree


@pytest.mark.parametrize("role,bad_delivery", [("reader", True), ("owner", True), ("owner", False)],
                         ids=["reader-refused", "invalid-delivery", "authorized-evidence"])
def test_draft_evidence_authorized_and_deferred_until_validation(tmp_path, role, bad_delivery):
    root, hosts, roles, calls, _worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles, caller_role=role) as box:
        request_draft = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                         "outgoing_stopped": True, "evidence_dir": str(tmp_path / "evidence"),
                         "delivery_dir": str(root if bad_delivery else tmp_path / "delivery")}
        before = snapshot(tmp_path)
        if role == "reader" or bad_delivery:
            with refusal("unauthorized" if role == "reader" else "invalid_record"):
                box.draft_handoff(request_draft)
            assert not calls
            assert snapshot(tmp_path) == before
        else:
            draft = box.draft_handoff(request_draft)
            assert calls[0] is None and not Path(calls[-1]).exists()
            assert Path(draft["checkpoint"]["sources"][0]["dirty_evidence"]).read_bytes() == b" M owned.py\0"


@pytest.mark.parametrize("role", ["reader", "owner"])
def test_source_witness_evidence_requires_explicit_write_permission(tmp_path, role):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles, caller_role=role) as box:
        directory = str(tmp_path / "evidence")
        before = snapshot(tmp_path)
        if role == "reader":
            with refusal("unauthorized"):
                box.source_witness(worktree, directory)
            assert not calls and snapshot(tmp_path) == before
        else:
            assert Path(box.source_witness(worktree, directory)["dirty_evidence"]).is_file()
        assert box.source_witness(worktree)["dirty_entries"] == 1


def test_invalid_delivery_history_refuses_draft_before_evidence_write_then_retry(tmp_path):
    root, hosts, roles, calls, _worktree = active_handoff_store(tmp_path)
    directory = tmp_path / "delivery"
    folder = directory / "reads" / "alpha" / "orchestrator"
    folder.mkdir(parents=True)
    bad = folder / "bad.json"
    bad.write_bytes(b"{")
    with mailbox(root, hosts=hosts, roles=roles) as box:
        request_draft = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                         "outgoing_stopped": True, "evidence_dir": str(tmp_path / "evidence"),
                         "delivery_dir": str(directory)}
        before = snapshot(tmp_path)
        with refusal("invalid_record"):
            box.draft_handoff(request_draft)
        assert all(directory is None for directory in calls)
        assert snapshot(tmp_path) == before
        bad.unlink()
        assert box.draft_handoff(request_draft)["checkpoint"]["sources"][0]["dirty_evidence"]


@pytest.mark.parametrize("kind", ["reads", "wakes"])
@pytest.mark.parametrize("relation", ["equal", "above", "below"])
def test_evidence_and_delivery_trees_disjoint_before_any_witness(tmp_path, kind, relation):
    root, hosts, roles, calls, _worktree = active_handoff_store(tmp_path)
    delivery = tmp_path / "trees" / "delivery"
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["accepted"]}
    if kind == "wakes":
        receipt.update({"wake_id": "initial-wake", "state": "started", "exit_code": None, "timed_out": False})
    with mailbox(root, hosts=hosts, roles=roles, delivery_roots=(delivery,)) as box:
        box.write_delivery_receipt(delivery, kind, receipt)
        evidence = delivery if relation == "equal" else delivery.parent if relation == "above" else delivery / kind / "alpha" / "orchestrator" / "evidence"
        request_draft = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                         "outgoing_stopped": True, "evidence_dir": str(evidence), "delivery_dir": str(delivery)}
        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with refusal("invalid_record"):
            box.draft_handoff(request_draft)
        assert not calls
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
        expected_state = "read" if kind == "reads" else "woken"
        assert box.delivery(delivery, message_id="accepted")["message"]["state"] == expected_state
        box.write_delivery_receipt(delivery, kind, receipt)
        request_draft["evidence_dir"] = str(delivery.parent / "evidence")
        draft = box.draft_handoff(request_draft)
        assert Path(draft["checkpoint"]["sources"][0]["dirty_evidence"]).is_file()
        assert box.delivery(delivery, message_id="accepted")["message"]["state"] == expected_state


@pytest.mark.parametrize("aliased", ["delivery", "evidence"])
def test_delivery_evidence_alias_refuses_before_witness(tmp_path, aliased):
    root, hosts, roles, calls, _worktree = active_handoff_store(tmp_path)
    delivery = tmp_path / "delivery"
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["accepted"]}
    with mailbox(root, hosts=hosts, roles=roles) as box:
        box.write_delivery_receipt(delivery, "reads", receipt)
        alias = tmp_path / "alias"
        symlink_or_skip(delivery, alias, target_is_directory=True)
        request_draft = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True,
            "evidence_dir": str(alias / "reads" / "alpha" / "orchestrator") if aliased == "evidence" else str(tmp_path / "evidence"),
            "delivery_dir": str(alias if aliased == "delivery" else delivery)}
        before = snapshot(tmp_path)
        with refusal("unsafe_path"):
            box.draft_handoff(request_draft)
        assert not calls
        assert snapshot(tmp_path) == before
        assert box.delivery(delivery, message_id="accepted")["message"]["state"] == "read"


@pytest.mark.parametrize("kind", ["reads", "wakes"])
def test_standalone_witness_cannot_publish_into_delivery_tree(tmp_path, kind):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    delivery = tmp_path / "delivery"
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["accepted"]}
    if kind == "wakes":
        receipt.update({"wake_id": "wake", "state": "started"})
    with mailbox(root, hosts=hosts, roles=roles) as box:
        box.write_delivery_receipt(delivery, kind, receipt)
        before = snapshot(tmp_path)
        with refusal("invalid_record"):
            box.source_witness(worktree, str(delivery / kind / "alpha" / "orchestrator"))
        assert not calls
        assert snapshot(tmp_path) == before
        assert box.delivery(delivery, message_id="accepted")["message"]["state"] == ("read" if kind == "reads" else "woken")


def two_source_handoff_store(tmp_path, failure=None, name="mail"):
    root, hosts, roles, _calls, first = active_handoff_store(tmp_path, name)
    second = str(tmp_path / "worktree-two")
    manifest = json.loads((root / "manifest.json").read_bytes())
    manifest["endpoints"]["alpha/lane/second"] = {"kind": "implementer"}
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    calls = []
    faults = [failure]

    def git(path, *args):
        if args == ("rev-parse", "--show-toplevel"):
            return str(path)
        if args[0] == "branch":
            return "branch" if str(path) == first else "branch-two"
        return "a" * 40 if args[-1] == "HEAD" else "b" * 40 if args[-1] == "HEAD^{tree}" else ""

    def witness(path, directory):
        calls.append((str(path), directory))
        if directory is not None and str(path) == second and faults[0] is not None:
            try:
                raise OSError("private host diagnostic")
            except OSError:
                if faults[0] == "busy":
                    raise BusyError()
                if faults[0] == "timeout":
                    raise TimeoutError("private host diagnostic")
                raise MailboxRefusal("invalid_record")
        status = (" M " + Path(path).name + ".py\0").encode("utf-8")
        result = {"worktree": str(path), "source_revision": "a" * 40, "source_tree": "b" * 40,
                  "dirty_state_sha256": hashlib.sha256(status).hexdigest(), "dirty_entries": 1}
        if directory is not None:
            with store_module.Store(root) as store:
                result["dirty_evidence"] = store.publish_status_evidence(directory, status, result["dirty_state_sha256"])
        return result

    hosts["test-host"].git = git
    hosts["test-host"].source_witness = witness
    hosts["test-host"].witness_faults = faults
    brief = replacement_request(tmp_path, 1)["checkpoint"]["briefs"][0]
    with mailbox(root, hosts=hosts, roles=roles) as box:
        bind(box, "alpha/lane/second")
        box.publish({**request("second-dispatch"), "from": "alpha/orchestrator", "to": "alpha/lane/second",
                     "session": "alpha/orchestrator", "type": "dispatch", "brief": brief})
        ready = {"worktree": second, "branch": "branch-two", "base_revision": "a" * 40,
            "lease_ref": "refs/aegis/lanes/second", "lease_oid": "c" * 40, "lease_expires_at": "2099-01-01T00:00:00Z",
            "owned_paths": ["owned.py"], "scan_workspace": second, "scan_evidence": "scan",
            "enforcement_tier": "advisory", "hook_evidence": "hook"}
        box.publish({**request("second-accepted"), "from": "alpha/lane/second", "to": "alpha/orchestrator",
            "session": "alpha/lane/second", "type": "ack", "acknowledgment": "accepted",
            "in_reply_to": "second-dispatch", "readiness": ready})
    return root, hosts, roles, calls


@pytest.mark.parametrize("failure", ["refusal", "busy", "timeout"])
def test_second_witness_failure_leaves_no_evidence(tmp_path, failure):
    root, hosts, roles, calls = two_source_handoff_store(tmp_path, failure)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    (evidence / "keep.txt").write_bytes(b"preserve")
    with mailbox(root, hosts=hosts, roles=roles) as box:
        before = snapshot(tmp_path)
        names = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
        with pytest.raises(MailboxRefusal) as caught:
            box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                "outgoing_stopped": True, "evidence_dir": str(evidence), "delivery_dir": str(tmp_path / "delivery")})
        assert snapshot(tmp_path) == before
        assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == names
        assert caught.value.code == 1 and caught.value.next_action
        assert caught.value.reason == {"busy": "busy", "timeout": "host_unavailable", "refusal": "invalid_record"}[failure]
        diagnostic = "".join(traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__))
        assert "private host diagnostic" not in diagnostic
        if failure == "busy":
            assert isinstance(caught.value, BusyError)
        assert len([directory for _path, directory in calls if directory is not None]) == 2
        hosts["test-host"].witness_faults[0] = None
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True, "evidence_dir": str(evidence), "delivery_dir": str(tmp_path / "delivery")})
        assert len(draft["checkpoint"]["sources"]) == 2
        assert len(list(evidence.glob("*.status"))) == 2
        assert (evidence / "keep.txt").read_bytes() == b"preserve"


def test_evidence_batch_rolls_back_files_when_later_publication_fails(tmp_path, monkeypatch):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    (evidence / "keep.txt").write_bytes(b"preserve")
    publish = store_module.Store.publish
    committed = []

    def fail_late(self, path, raw, **kwargs):
        result = publish(self, path, raw, **kwargs)
        if Path(path).parent == evidence:
            committed.append(path)
            if len(committed) == 2:
                raise MailboxRefusal("io")
        return result

    monkeypatch.setattr(store_module.Store, "publish", fail_late)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        before = snapshot(tmp_path)
        names = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
        with pytest.raises(MailboxRefusal):
            box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                "outgoing_stopped": True, "evidence_dir": str(evidence), "delivery_dir": str(tmp_path / "delivery")})
        assert len(committed) == 2
        assert snapshot(tmp_path) == before
        assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == names
        monkeypatch.setattr(store_module.Store, "publish", publish)
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True, "evidence_dir": str(evidence), "delivery_dir": str(tmp_path / "delivery")})
        assert all(Path(row["dirty_evidence"]).is_file() for row in draft["checkpoint"]["sources"])


@pytest.mark.parametrize("draft", [False, True])
def test_evidence_requires_owner_delivery_context_before_observation(tmp_path, draft):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    before = snapshot(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles, delivery_roots=()) as box:
        with refusal("delivery_context_required"):
            if draft:
                box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(tmp_path / "evidence")})
            else:
                box.source_witness(worktree, tmp_path / "evidence")
        assert not calls
        assert snapshot(tmp_path) == before
        assert box.source_witness(worktree)["dirty_entries"] == 1


@pytest.mark.parametrize("fault", ["drift", "extra", "bad_digest", "wrong_path"])
def test_staged_witnesses_are_validated_before_any_final_publication(tmp_path, fault):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    (tmp_path / "new").mkdir(mode=0o700)
    original = hosts["test-host"].source_witness
    staged = []

    def witness(path, directory):
        result = original(path, directory)
        if directory is not None:
            staged.append(directory)
            if len(staged) == 2:
                if fault == "drift":
                    result["source_revision"] = "c" * 40
                elif fault == "extra":
                    extra = Path(directory) / "unexpected" / "nested"
                    extra.mkdir(parents=True, mode=0o700)
                    (extra / "unexpected.txt").write_bytes(b"untrusted")
                elif fault == "bad_digest":
                    Path(result["dirty_evidence"]).write_bytes(b"wrong")
                else:
                    result["dirty_evidence"] = str(tmp_path / "unrelated.status")
        return result

    hosts["test-host"].source_witness = witness
    with mailbox(root, hosts=hosts, roles=roles) as box:
        before = snapshot(tmp_path)
        names = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
        with refusal("unsafe_path" if fault == "extra" else "invalid_record"):
            box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                "outgoing_stopped": True, "evidence_dir": str(tmp_path / "new" / "evidence")})
        assert len(staged) == 2
        assert snapshot(tmp_path) == before
        assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == names
        hosts["test-host"].source_witness = original
        assert box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True, "evidence_dir": str(tmp_path / "new" / "evidence")})


def test_evidence_batch_holds_one_exclusion_across_both_witnesses(tmp_path, monkeypatch):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    original = hosts["test-host"].source_witness
    lock = store_module.Store.lock
    acquisitions, observations = [], []
    with mailbox(root, hosts=hosts, roles=roles) as box:
        @contextmanager
        def tracked(self, directory, **kwargs):
            if self is box.store and Path(directory) == root:
                acquisitions.append(directory)
            with lock(self, directory, **kwargs):
                yield

        def witness(path, directory):
            if directory is not None:
                observations.append(path)
                assert len(acquisitions) == 1
                with store_module.Store(root) as contender, refusal("busy"):
                    with contender.lock(root):
                        pytest.fail("batch exclusion was released")
            return original(path, directory)

        monkeypatch.setattr(store_module.Store, "lock", tracked)
        hosts["test-host"].source_witness = witness
        evidence = tmp_path / "evidence"
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True, "evidence_dir": str(evidence)})
        assert len(observations) == 2 and len(acquisitions) == 1
        before = snapshot(tmp_path)
        acquisitions.clear()
        observations.clear()
        assert box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True, "evidence_dir": str(evidence)}) == draft
        assert snapshot(tmp_path) == before


def test_partial_evidence_rollback_uses_held_directory_after_rename(tmp_path, monkeypatch):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    evidence, moved = tmp_path / "evidence", tmp_path / "moved-evidence"
    evidence.mkdir(mode=0o700)
    (evidence / "keep.txt").write_bytes(b"preserve")
    publish = store_module.Store.publish
    committed = []

    def fail_late(self, path, raw, **kwargs):
        result = publish(self, path, raw, **kwargs)
        if Path(path).parent == evidence:
            committed.append(path)
            if len(committed) == 1:
                evidence.rename(moved)
                evidence.mkdir(mode=0o700)
                (evidence / "sentinel.txt").write_bytes(b"untouched")
            else:
                raise MailboxRefusal("io")
        return result

    monkeypatch.setattr(store_module.Store, "publish", fail_late)
    with mailbox(root, hosts=hosts, roles=roles) as box, refusal("io"):
        box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True, "evidence_dir": str(evidence)})
    assert len(committed) == 2
    assert list(moved.iterdir()) == [moved / "keep.txt"]
    assert (moved / "keep.txt").read_bytes() == b"preserve"
    assert list(evidence.iterdir()) == [evidence / "sentinel.txt"]
    assert (evidence / "sentinel.txt").read_bytes() == b"untouched"
    assert not list(root.glob(".pending*")) and not (root / ".write.lock").exists()


def test_evidence_committed_mailbox_exit_failure_warns(tmp_path, monkeypatch):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    lock = store_module.Store.lock
    with mailbox(root, hosts=hosts, roles=roles) as box:
        @contextmanager
        def fail_exit(self, directory, **kwargs):
            with lock(self, directory, **kwargs):
                yield
            if self is box.store and Path(directory) == root:
                raise MailboxRefusal("io")

        monkeypatch.setattr(store_module.Store, "lock", fail_exit)
        result = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
            "outgoing_stopped": True, "evidence_dir": str(tmp_path / "evidence")})
        assert len(result["warnings"]) == 1
        assert result["warnings"][0]["reason"] == "lock_release"
        assert all(Path(source["dirty_evidence"]).is_file() for source in result["checkpoint"]["sources"])
        assert not list(tmp_path.rglob("*.lock"))


@pytest.mark.parametrize("peer", ["same", "sibling", "nested"])
@pytest.mark.parametrize("failure", ["publication", "rollback_release"])
def test_evidence_rollback_excludes_contender_until_cleanup(tmp_path, monkeypatch, peer, failure):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    peer_parent = tmp_path / "nested" if peer == "nested" else tmp_path
    peer_parent.mkdir(exist_ok=True)
    peer_root = root if peer == "same" else peer_parent / "peer-mail"
    if peer_root != root:
        mail.initialize(peer_root, MANIFEST, roles=roles, caller_role="owner")
    evidence = peer_parent / "evidence"
    evidence.mkdir(mode=0o700)
    identity = evidence.stat()
    rollback, release = Event(), Event()
    publish = store_module.Store.publish
    lock = store_module.Store.lock
    committed = []

    def fail_second(self, path, raw, **kwargs):
        if Path(path).parent == evidence:
            committed.append(path)
            if len(committed) == 2:
                raise MailboxRefusal("io")
        return publish(self, path, raw, **kwargs)

    @contextmanager
    def fail_release(self, directory, **kwargs):
        with lock(self, directory, **kwargs):
            yield
        if failure == "rollback_release" and self is first.store and Path(directory) == root:
            raise MailboxRefusal("io")

    def paused_unlink(name, **kwargs):
        info = os.fstat(kwargs["dir_fd"])
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino) and name.endswith(".status"):
            rollback.set()
            assert release.wait(5)
        return os.unlink(name, **kwargs)

    monkeypatch.setattr(store_module.Store, "publish", fail_second)
    monkeypatch.setattr(store_module.Store, "lock", fail_release)
    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": paused_unlink}))
    with mailbox(root, hosts=hosts, roles=roles) as first, mailbox(peer_root, hosts=hosts, roles=roles) as second:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(first.draft_handoff, {"endpoint": "alpha/orchestrator", "host": "test-host",
                "session": "next", "outgoing_stopped": True, "evidence_dir": str(evidence)})
            try:
                assert rollback.wait(5)
                assert Path(committed[0]).is_file()
                with pytest.raises(BusyError) as caught:
                    second.source_witness(tmp_path / "worktree", evidence)
                assert caught.value.code == 1 and caught.value.reason == "busy"
                assert caught.value.next_action
            finally:
                release.set()
                pending.exception(timeout=5)
            with refusal("io"):
                pending.result(timeout=5)
        assert not list(evidence.iterdir())
        result = second.source_witness(tmp_path / "worktree", evidence)
        assert Path(result["dirty_evidence"]).read_bytes() == b" M worktree.py\0"
        assert len(list(evidence.iterdir())) == 1
        assert not list(tmp_path.rglob("*.lock"))


@pytest.mark.parametrize("peer", ["same", "sibling", "nested"])
def test_new_evidence_destination_excludes_contender_before_mkdir(tmp_path, monkeypatch, peer):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    peer_parent = tmp_path / "nested" if peer == "nested" else tmp_path
    peer_parent.mkdir(exist_ok=True)
    peer_root = root if peer == "same" else peer_parent / "peer-mail"
    if peer_root != root:
        mail.initialize(peer_root, MANIFEST, roles=roles, caller_role="owner")
    evidence = peer_parent / "round5-evidence"
    created, release_create, peer_ready, peer_observing, release_peer = (Event() for _ in range(5))
    original = hosts["test-host"].source_witness

    def paused_mkdir(name, mode=0o777, **kwargs):
        result = os.mkdir(name, mode, **kwargs)
        if name == evidence.name:
            created.set()
            assert release_create.wait(5)
        return result

    def peer_witness(path, directory):
        peer_observing.set()
        peer_ready.set()
        assert release_peer.wait(5)
        return original(path, directory)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "mkdir": paused_mkdir}))
    with mailbox(root, hosts=hosts, roles=roles) as first, mailbox(peer_root,
            hosts={"test-host": SimpleNamespace(source_witness=peer_witness)}, roles=roles) as second:
        def contender():
            try:
                return second.source_witness(worktree, evidence)
            finally:
                peer_ready.set()

        with ThreadPoolExecutor(max_workers=2) as pool:
            winner = pool.submit(first.source_witness, worktree, evidence)
            loser = None
            try:
                assert created.wait(5)
                loser = pool.submit(contender)
                assert peer_ready.wait(5)
                assert not peer_observing.is_set(), "contender entered an uncommitted destination"
                with pytest.raises(BusyError) as caught:
                    loser.result(timeout=5)
                assert caught.value.reason == "busy" and caught.value.code == 1
                release_create.set()
                result = winner.result(timeout=5)
                assert Path(result["dirty_evidence"]).read_bytes() == b" M owned.py\0"
                assert evidence.is_dir() and len(list(evidence.iterdir())) == 1
            finally:
                release_create.set()
                release_peer.set()
                winner.exception(timeout=5)
                if loser is not None:
                    loser.exception(timeout=5)
        result = second.source_witness(worktree, evidence)
        assert Path(result["dirty_evidence"]).read_bytes() == b" M owned.py\0"
        assert not list(tmp_path.rglob("*.lock"))


def test_owner_lock_serializes_independent_evidence_destinations(tmp_path):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    peer_root = tmp_path / "peer-mail"
    mail.initialize(peer_root, MANIFEST, roles=roles, caller_role="owner")
    entered, release = Event(), Event()
    original = hosts["test-host"].source_witness

    def paused_witness(path, directory):
        entered.set()
        assert release.wait(5)
        return original(path, directory)

    with mailbox(root, hosts={"test-host": SimpleNamespace(source_witness=paused_witness)}, roles=roles) as first:
        with mailbox(peer_root, hosts=hosts, roles=roles) as second, ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(first.source_witness, worktree, tmp_path / "first-evidence")
            try:
                assert entered.wait(5)
                with pytest.raises(BusyError) as caught:
                    second.source_witness(worktree, tmp_path / "second-evidence")
                assert "team-mailbox-evidence.lock" in caught.value.next_action
                assert not (tmp_path / "second-evidence").exists()
            finally:
                release.set()
                pending.exception(timeout=5)
            assert Path(pending.result(timeout=5)["dirty_evidence"]).read_bytes() == b" M owned.py\0"
            result = second.source_witness(worktree, tmp_path / "second-evidence")
            assert Path(result["dirty_evidence"]).read_bytes() == b" M owned.py\0"
    assert not list(tmp_path.rglob("*.lock"))


def test_witness_lock_close_failure_is_typed_and_cleans_up(tmp_path, monkeypatch):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    (tmp_path / "new").mkdir(mode=0o700)
    failed = []

    def close_lock(fd):
        info = os.fstat(fd)
        os.close(fd)
        if stat.S_ISREG(info.st_mode) and info.st_size == 0 and not failed:
            failed.append(fd)
            raise OSError("private close diagnostic")

    with mailbox(root, hosts=hosts, roles=roles) as box:
        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "close": close_lock}))
        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with refusal("io") as caught:
            box.source_witness(worktree, tmp_path / "new" / "evidence")
        assert failed and not calls
        assert caught.value.code == 1 and caught.value.next_action
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
        result = box.source_witness(worktree, tmp_path / "new" / "evidence")
        assert Path(result["dirty_evidence"]).read_bytes() == b" M owned.py\0"


def test_witness_batch_rejects_retired_parent_descriptors(tmp_path, monkeypatch):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    retired = set()

    def record_close(fd):
        os.close(fd)
        retired.add(fd)

    with mailbox(root, hosts=hosts, roles=roles) as box:
        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "close": record_close}))
        result = box.source_witness(worktree, tmp_path / "evidence")
        assert Path(result["dirty_evidence"]).read_bytes() == b" M owned.py\0"
        for fd in sorted(retired):
            with refusal("invalid_record"):
                box.store.publish(tmp_path / "unexpected.status", b"unexpected", parent=fd)
        assert not (tmp_path / "unexpected.status").exists()


@pytest.mark.parametrize("draft", [False, True])
def test_evidence_missing_parent_refuses_before_observation(tmp_path, draft):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    evidence = tmp_path / "missing-parent" / "evidence"
    before = snapshot(tmp_path)
    names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    with mailbox(root, hosts=hosts, roles=roles) as box:
        with refusal("missing") as caught:
            if draft:
                box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(evidence)})
            else:
                box.source_witness(worktree, evidence)
        assert caught.value.code == 1 and caught.value.next_action
    assert not calls
    assert snapshot(tmp_path) == before
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names


def test_peer_initialized_after_new_ancestor_cannot_reuse_rollback(tmp_path, monkeypatch):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    ancestor, evidence = tmp_path / "new-parent", tmp_path / "new-parent" / "evidence"
    reached, published, release = Event(), Event(), Event()
    publish = store_module.Store.publish
    final_names = []

    def paused_publish(self, path, raw, **kwargs):
        if Path(path).parent == evidence and final_names:
            raise MailboxRefusal("io")
        result = publish(self, path, raw, **kwargs)
        if Path(path).parent == evidence:
            final_names.append(path)
            published.set()
            reached.set()
            assert release.wait(5)
        return result

    monkeypatch.setattr(store_module.Store, "publish", paused_publish)
    with mailbox(root, hosts=hosts, roles=roles) as first, ThreadPoolExecutor(max_workers=1) as pool:
        def run():
            try:
                return first.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(evidence)})
            finally:
                reached.set()

        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        pending = pool.submit(run)
        try:
            assert reached.wait(5)
            if not published.is_set():
                with refusal("missing"):
                    pending.result(timeout=5)
                assert snapshot(tmp_path) == before
                assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
                ancestor.mkdir(mode=0o700)
                reached.clear()
                pending = pool.submit(run)
                assert reached.wait(5) and published.is_set()
            peer_root = ancestor / "peer-mail"
            with pytest.raises(BusyError) as caught:
                mail.initialize(peer_root, MANIFEST, roles=roles, caller_role="owner")
            assert caught.value.reason == "busy" and caught.value.code == 1
            assert "team-mailbox-evidence.lock" in caught.value.next_action
            assert not peer_root.exists()
        finally:
            release.set()
            pending.exception(timeout=5)
        with refusal("io"):
            pending.result(timeout=5)
        assert not evidence.exists()
        mail.initialize(peer_root, MANIFEST, roles=roles, caller_role="owner")
        assert (peer_root / "manifest.json").is_file()
        assert not list(tmp_path.rglob("*.lock"))


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("lock_kind", ["owner", "mailbox", "destination"])
@pytest.mark.parametrize("phase", ["before", "after"])
def test_evidence_lock_release_commit_point(tmp_path, monkeypatch, owner_plane, draft, lock_kind, phase):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    evidence = tmp_path / "evidence"
    failed = []
    publish = store_module.Store.publish

    def fail_publication(self, path, raw, **kwargs):
        result = publish(self, path, raw, **kwargs)
        if phase == "before" and Path(path).parent == evidence:
            raise MailboxRefusal("invalid_record")
        return result

    def fail_release(name, **kwargs):
        matches = (name == "team-mailbox-evidence.lock" if lock_kind == "owner" else
                   name == ".write.lock" if lock_kind == "mailbox" else name.startswith(".witness-"))
        result = os.unlink(name, **kwargs)
        if matches and not failed:
            failed.append(name)
            raise OSError("private release diagnostic")
        return result

    monkeypatch.setattr(store_module.Store, "publish", fail_publication)
    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": fail_release}))
    with mailbox(root, hosts=hosts, roles=roles) as box:
        def run():
            if draft:
                return box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(evidence)})
            return box.source_witness(tmp_path / "worktree", evidence)

        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        if phase == "before":
            with refusal("io") as caught:
                run()
            assert caught.value.code == 1 and caught.value.next_action
            assert snapshot(tmp_path) == before
            assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
        else:
            result = run()
            sources = result["checkpoint"]["sources"] if draft else [result]
            assert all(Path(source["dirty_evidence"]).is_file() for source in sources)
            assert len(result["warnings"]) == 1
            warning = result["warnings"][0]
            assert warning["status"] == "warning" and warning["reason"] == "lock_release"
            assert warning["code"] == 0
            assert warning["lock_path"].endswith("/" + failed[0])
            assert warning["lock_path"] in warning["next_action"]
            assert "private release diagnostic" not in json.dumps(result)
        assert len(failed) == 1
        assert not list(tmp_path.rglob("*.lock"))
        monkeypatch.setattr(store_module.Store, "publish", publish)
        retry = run()
        if phase == "before":
            assert len(retry["warnings"]) == 1 and retry["warnings"][0]["reason"] == "lock_release"
        else:
            assert "warnings" not in retry


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("lock_kind", ["owner", "mailbox", "destination"])
def test_committed_evidence_retained_lock_warns_then_names_busy_path(tmp_path, monkeypatch, owner_plane, draft, lock_kind):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    peer_root = tmp_path / "peer-mail"
    mail.initialize(peer_root, MANIFEST, roles=roles, caller_role="owner")
    evidence = tmp_path / "evidence"
    failed = []

    def retain_lock(name, **kwargs):
        matches = (name == "team-mailbox-evidence.lock" if lock_kind == "owner" else
                   name == ".write.lock" if lock_kind == "mailbox" else name.startswith(".witness-"))
        if matches and not failed:
            failed.append(name)
            raise OSError("private retained-lock diagnostic")
        return os.unlink(name, **kwargs)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": retain_lock}))
    with mailbox(root, hosts=hosts, roles=roles) as box:
        if draft:
            result = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                "outgoing_stopped": True, "evidence_dir": str(evidence)})
        else:
            result = box.source_witness(worktree, evidence)
        warning = result["warnings"][0]
        lock = {"owner": owner_plane, "mailbox": root, "destination": evidence.parent}[lock_kind] / failed[0]
        assert lock.is_file()
        assert warning["lock_path"].endswith("/" + lock.name)
        committed = snapshot(evidence)
        with pytest.raises(BusyError) as caught:
            box.source_witness(worktree, evidence)
        assert caught.value.reason == "busy" and caught.value.code == 1
        assert warning["lock_path"] in caught.value.next_action
        assert snapshot(evidence) == committed
        assert "private retained-lock diagnostic" not in json.dumps(result)
        if lock_kind == "owner":
            with mailbox(peer_root, hosts=hosts, roles=roles) as peer, pytest.raises(BusyError) as busy:
                peer.source_witness(worktree, tmp_path / "another-evidence")
            assert warning["lock_path"] in busy.value.next_action
            assert not (tmp_path / "another-evidence").exists()
        lock.unlink()
        retry = box.source_witness(worktree, evidence)
        assert "warnings" not in retry and Path(retry["dirty_evidence"]).is_file()


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("lock_kind", ["owner", "mailbox", "destination"])
def test_refused_evidence_retained_lock_names_busy_path(tmp_path, monkeypatch, owner_plane, draft, lock_kind):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    evidence = tmp_path / "evidence"
    failed = []
    publish = store_module.Store.publish

    def fail_publication(self, path, raw, **kwargs):
        result = publish(self, path, raw, **kwargs)
        if Path(path).parent == evidence:
            raise MailboxRefusal("invalid_record")
        return result

    def retain_lock(name, **kwargs):
        matches = (name == "team-mailbox-evidence.lock" if lock_kind == "owner" else
                   name == ".write.lock" if lock_kind == "mailbox" else name.startswith(".witness-"))
        if matches and not failed:
            failed.append(name)
            raise OSError("private retained-lock diagnostic")
        return os.unlink(name, **kwargs)

    monkeypatch.setattr(store_module.Store, "publish", fail_publication)
    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": retain_lock}))
    with mailbox(root, hosts=hosts, roles=roles) as box:
        before = snapshot(tmp_path)
        with refusal("io") as caught:
            if draft:
                box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(evidence)})
            else:
                box.source_witness(worktree, evidence)
        assert caught.value.code == 1 and not evidence.exists()
        lock = {"owner": owner_plane, "mailbox": root, "destination": evidence.parent}[lock_kind] / failed[0]
        assert lock.is_file()
        after = snapshot(tmp_path)
        if lock_kind != "owner":
            after.pop(str(lock.relative_to(tmp_path)))
        assert after == before
        with pytest.raises(BusyError) as busy:
            box.source_witness(worktree, evidence)
        assert busy.value.code == 1 and busy.value.reason == "busy"
        assert lock.name in busy.value.next_action
        lock.unlink()


@pytest.mark.parametrize("prefix_count", [0, 4, 8])
def test_lock_diagnostics_canonicalize_redact_then_bound(tmp_path, prefix_count):
    make_store(tmp_path)
    secret = "ghp_" + "A" * 36
    parent = tmp_path / ("prefix-" + secret[:6] + "\x1b[31m" + secret[6:] + "\nend")
    for _index in range(prefix_count):
        parent /= "component-" + "z" * 150
    name = ".witness-" + "a" * 64 + ".lock"
    path = parent / name
    warning = primitives.LockReleaseWarning(path).as_dict()
    busy = BusyError(path).as_dict()
    rendered = json.dumps([warning, busy])
    assert secret not in rendered and "ghp_AA" not in rendered
    assert "\x1b" not in warning["lock_path"] and "\n" not in warning["lock_path"]
    assert len(warning["lock_path"]) <= 1024
    assert warning["lock_path"].endswith("/" + name)
    assert warning["lock_path"] in warning["next_action"]
    assert warning["lock_path"] in busy["next_action"]


def test_evidence_parent_rename_keeps_lock_creation_and_rollback_bound(tmp_path, monkeypatch):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    ancestor, moved = tmp_path / "parent", tmp_path / "moved-parent"
    ancestor.mkdir(mode=0o700)
    evidence = ancestor / "evidence"
    lock = store_module.Store.lock
    publish = store_module.Store.publish
    swapped, published = [], []

    @contextmanager
    def swap_parent(self, directory, **kwargs):
        if kwargs.get("destination") == evidence and not swapped:
            ancestor.rename(moved)
            ancestor.mkdir(mode=0o700)
            (ancestor / "sentinel").write_bytes(b"untouched")
            swapped.append(True)
        with lock(self, directory, **kwargs):
            yield

    def fail_publication(self, path, raw, **kwargs):
        result = publish(self, path, raw, **kwargs)
        if Path(path).parent == evidence:
            published.append(path)
            assert list((moved / "evidence").glob("*.status"))
            raise MailboxRefusal("io")
        return result

    monkeypatch.setattr(store_module.Store, "lock", swap_parent)
    monkeypatch.setattr(store_module.Store, "publish", fail_publication)
    with mailbox(root, hosts=hosts, roles=roles) as box, refusal("io"):
        box.source_witness(worktree, evidence)
    assert swapped and published
    assert not list(moved.iterdir())
    assert list(ancestor.iterdir()) == [ancestor / "sentinel"]
    assert (ancestor / "sentinel").read_bytes() == b"untouched"
    assert not list(tmp_path.rglob("*.lock"))


@pytest.mark.parametrize("surface", ["directory", "lock", "publish", "read", "entries", "exists"])
@pytest.mark.parametrize("invalid", [[], {}], ids=["list", "dict"])
def test_noninteger_borrowed_descriptors_refuse_before_io(tmp_path, surface, invalid):
    root = make_store(tmp_path)
    with store_module.Store(root) as store:
        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with refusal("invalid_record"):
            if surface == "publish":
                store.publish(tmp_path / "unexpected", b"unexpected", parent=invalid)
            elif surface == "directory":
                with store.directory(tmp_path / "unexpected", create=True, parent=invalid):
                    pytest.fail("invalid descriptor admitted")
            elif surface == "read":
                store.read(root / "manifest.json", parent=invalid)
            elif surface == "entries":
                store.entries(root / "manifest.json", parent=invalid)
            elif surface == "exists":
                store.exists(root / "manifest.json", parent=invalid)
            else:
                with store.lock(root, parent=invalid):
                    pytest.fail("invalid descriptor admitted")
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names


@pytest.mark.parametrize("parents_exist", [False, True])
def test_sibling_evidence_refusals_never_remove_shared_ancestors(tmp_path, parents_exist):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    peer_root = tmp_path / "peer-mail"
    mail.initialize(peer_root, MANIFEST, roles=roles, caller_role="owner")
    parent = tmp_path / "outer" / "new"
    if parents_exist:
        parent.mkdir(parents=True, mode=0o700)
    worktrees = [tmp_path / "worktree-a", tmp_path / "worktree-b"]
    evidence = [parent / "a", parent / "b"]
    ready, entered, release = ([Event(), Event()] for _ in range(3))
    start = [Event(), Event()]
    original = hosts["test-host"].source_witness

    def refused_observation(path, directory):
        index = worktrees.index(path)
        entered[index].set()
        assert release[index].wait(5)
        return {}

    hosts["test-host"].source_witness = refused_observation
    with mailbox(root, hosts=hosts, roles=roles) as first, mailbox(peer_root, hosts=hosts, roles=roles) as second:
        def run(box, index):
            ready[index].set()
            assert start[index].wait(5)
            return box.source_witness(worktrees[index], evidence[index])

        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = [pool.submit(run, box, index) for index, box in enumerate((first, second))]
            try:
                assert all(event.wait(5) for event in ready)
                start[0].set()
                if parents_exist:
                    assert entered[0].wait(5) and evidence[0].is_dir()
                    start[1].set()
                    with pytest.raises(BusyError):
                        pending[1].result(timeout=5)
                    assert not entered[1].is_set() and not evidence[1].exists()
                    release[1].set()
                    release[0].set()
                    with refusal("invalid_record"):
                        pending[0].result(timeout=5)
                    assert not evidence[0].exists()
                    with refusal("invalid_record"):
                        second.source_witness(worktrees[1], evidence[1])
                else:
                    for index, future in enumerate(pending):
                        start[index].set()
                        with refusal("missing"):
                            future.result(timeout=5)
                    assert not any(event.is_set() for event in entered)
            finally:
                for event in start:
                    event.set()
                for event in release:
                    event.set()
                for future in pending:
                    future.exception(timeout=5)
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
        hosts["test-host"].source_witness = original
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        result = first.source_witness(worktrees[0], evidence[0])
        assert Path(result["dirty_evidence"]).read_bytes() == b" M worktree-a.py\0"
        assert not list(tmp_path.rglob("*.lock"))


@pytest.mark.parametrize("first_draft", [False, True])
@pytest.mark.parametrize("second_draft", [False, True])
def test_nested_evidence_never_enters_an_uncommitted_parent(tmp_path, owner_plane, first_draft, second_draft):
    root, hosts, roles, _calls = two_source_handoff_store(tmp_path)
    peer_root, peer_hosts, peer_roles, _peer_calls = two_source_handoff_store(tmp_path, name="peer-mail")
    evidence = tmp_path / "evidence"
    first_entered, second_reached, second_entered = Event(), Event(), Event()
    release_first, release_second = Event(), Event()
    observe = hosts["test-host"].source_witness
    observations, peer_git_calls = [[], []], []
    peer_git = peer_hosts["test-host"].git

    def tracked_peer_git(*args):
        peer_git_calls.append(args)
        return peer_git(*args)

    peer_hosts["test-host"].git = tracked_peer_git

    def first_observation(path, directory):
        observations[0].append((directory, (owner_plane / "team-mailbox-evidence.lock").is_file()))
        if directory is None:
            return observe(path, directory)
        first_entered.set()
        assert release_first.wait(5)
        return {}

    def second_observation(path, directory):
        observations[1].append(directory)
        second_entered.set()
        second_reached.set()
        assert release_second.wait(5)
        return {}

    hosts["test-host"].source_witness = first_observation
    peer_hosts["test-host"].source_witness = second_observation
    with mailbox(root, hosts=hosts, roles=roles) as first, mailbox(peer_root, hosts=peer_hosts, roles=peer_roles) as second:
        def run(box, draft, directory):
            if draft:
                return box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(directory)})
            return box.source_witness(tmp_path / "worktree", directory)

        def contender():
            try:
                return run(second, second_draft, evidence / "child")
            finally:
                second_reached.set()

        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(run, first, first_draft, evidence)
            peer = None
            try:
                assert first_entered.wait(5) and evidence.is_dir()
                peer = pool.submit(contender)
                assert second_reached.wait(5)
            finally:
                release_first.set()
                pending.exception(timeout=5)
                release_second.set()
                if peer is not None:
                    peer.exception(timeout=5)
            with refusal("invalid_record"):
                pending.result(timeout=5)
            with pytest.raises(BusyError) as caught:
                peer.result(timeout=5)
            assert caught.value.code == 1 and caught.value.reason == "busy"
            assert "team-mailbox-evidence.lock" in caught.value.next_action
            assert not second_entered.is_set()
            assert observations[0] and all(held for _directory, held in observations[0])
            assert observations[1] == [] and peer_git_calls == []
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
        with refusal("missing"):
            run(second, second_draft, evidence / "child")


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("kind,reason", [("no-account", "missing"), ("missing", "missing"),
    ("symlink", "unsafe_path"), ("writable", "unsafe_path")])
def test_owner_plane_unavailable_refuses_without_creation(tmp_path, monkeypatch, owner_plane, draft, kind, reason):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    if kind == "no-account":
        def missing(uid):
            raise KeyError("missing account")
        monkeypatch.setattr(store_module, "pwd", SimpleNamespace(getpwuid=missing))
    elif kind == "missing":
        owner_plane.rmdir()
    elif kind == "symlink":
        saved = owner_plane.with_name("saved-state")
        owner_plane.rename(saved)
        symlink_or_skip(saved, owner_plane, target_is_directory=True)
    else:
        owner_plane.chmod(0o777)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with refusal(reason) as caught:
            if draft:
                box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(tmp_path / "evidence")})
            else:
                box.source_witness(worktree, tmp_path / "evidence")
        assert caught.value.code == 1 and caught.value.next_action
        assert calls == []
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names


def test_evidence_lock_order_is_owner_mailbox_destination(tmp_path, monkeypatch):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    lock = store_module.Store.lock
    acquired = []
    with mailbox(root, hosts=hosts, roles=roles) as box:
        @contextmanager
        def tracked(self, directory, **kwargs):
            with lock(self, directory, **kwargs):
                if self is box.store:
                    acquired.append("owner" if kwargs.get("owner") else
                                    "destination" if kwargs.get("destination") is not None else "mailbox")
                yield

        monkeypatch.setattr(store_module.Store, "lock", tracked)
        result = box.source_witness(worktree, tmp_path / "evidence")
        assert Path(result["dirty_evidence"]).is_file()
        assert acquired == ["owner", "mailbox", "destination"]


def evidence_identity_process():
    """A fresh interpreter, startup environment, real pipes, and a mocked OS account lookup."""
    config = json.loads(sys.argv[1])
    lookups = []
    port_calls = {"witness": 0, "git": 0}

    def account(uid):
        lookups.append(uid)
        return SimpleNamespace(pw_dir=config["account_home"])

    def send(event, **values):
        print(json.dumps({"event": event, "euid": os.geteuid(), "home": os.environ["HOME"],
                          "lookups": list(lookups), "port_calls": dict(port_calls), **values}), flush=True)

    def git(path, *args):
        port_calls["git"] += 1
        if args == ("rev-parse", "--show-toplevel"):
            return str(path)
        if args[0] == "branch":
            return "branch" if Path(path).name == "worktree" else "branch-two"
        return "a" * 40 if args[-1] == "HEAD" else "b" * 40 if args[-1] == "HEAD^{tree}" else ""

    def observe(path, directory):
        port_calls["witness"] += 1
        raw = (" M " + Path(path).name + ".py\0").encode("utf-8")
        if directory is None:
            return {"worktree": str(path), "source_revision": "a" * 40, "source_tree": "b" * 40,
                    "dirty_state_sha256": hashlib.sha256(raw).hexdigest(), "dirty_entries": 1}
        send("entered")
        readable, _write, _error = select.select([sys.stdin], [], [], 15)
        assert readable and sys.stdin.readline().strip() == "release", "publication latch timed out"
        return {}

    try:
        # This interpreter owns this module reference; the shared pwd module stays intact.
        # The RED predecessor has no pwd boundary and uses its startup HOME.
        if hasattr(store_module, "pwd"):
            store_module.pwd = SimpleNamespace(getpwuid=account)
        roles = RoleTables(writes={**dict(ROLES.writes), "owner": ROLES.writes["owner"] | {"source_witness"}})
        hosts = {"test-host": SimpleNamespace(git=git, source_witness=observe, observe_readiness=lambda value: True)}
        with mailbox(Path(config["root"]), roles=roles, hosts=hosts) as box:
            try:
                if config["draft"]:
                    box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                        "outgoing_stopped": True, "evidence_dir": config["evidence"]})
                else:
                    box.source_witness(Path(config["root"]).parent / "worktree", config["evidence"])
            except MailboxRefusal as error:
                send("refused", result=error.as_dict())
            else:
                send("unexpected-success")
    except BaseException as error:
        send("harness-error", error_type=type(error).__name__)


def process_event(child):
    assert child.stdout is not None
    readable, _write, _error = select.select([child.stdout], [], [], 15)
    assert readable, "evidence process did not report an event"
    line = child.stdout.readline()
    assert line, "evidence process ended without an event"
    return json.loads(line)


@pytest.mark.parametrize("first_draft", [False, True])
@pytest.mark.parametrize("second_draft", [False, True])
def test_account_identity_lock_ignores_different_process_homes(tmp_path, owner_plane, first_draft, second_draft):
    root, _hosts, _roles, _calls = two_source_handoff_store(tmp_path)
    peer_root, _peer_hosts, _peer_roles, _peer_calls = two_source_handoff_store(tmp_path, name="peer-mail")
    homes = [tmp_path / "environment-a", tmp_path / "environment-b"]
    for home in homes:
        UserLayout(home).aegis_dir.mkdir(parents=True, mode=0o700)
    evidence = tmp_path / "evidence"
    code = ("import sys; sys.path.insert(0, 'tests'); "
            "from tests.unit.core.test_team_mailbox import evidence_identity_process; evidence_identity_process()")
    children = []

    def start(root, directory, draft, home):
        config = {"root": str(root), "evidence": str(directory), "draft": draft,
                  "account_home": str(owner_plane.parent)}
        child = subprocess.Popen([sys.executable, "-u", "-c", code, json.dumps(config)],
            cwd=Path(__file__).resolve().parents[3], env={**os.environ, "HOME": str(home)},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(child)
        return child

    def release(child):
        assert child.stdin is not None
        child.stdin.write("release\n")
        child.stdin.flush()

    before = snapshot(tmp_path)
    names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    try:
        first = start(root, evidence, first_draft, homes[0])
        entry = process_event(first)
        assert entry["event"] == "entered" and evidence.is_dir()
        second = start(peer_root, evidence / "child", second_draft, homes[1])
        contender = process_event(second)
        release(first)
        first_result = process_event(first)
        if contender["event"] == "entered":
            release(second)
            contender = process_event(second)
        assert first_result["event"] == contender["event"] == "refused"
        assert first_result["result"]["reason"] == "invalid_record"
        assert contender["result"]["reason"] == "busy"
        assert first_result["result"]["code"] == contender["result"]["code"] == 1
        assert first_result["euid"] == contender["euid"] == os.geteuid()
        assert first_result["home"] == str(homes[0]) and contender["home"] == str(homes[1])
        assert first_result["lookups"] == contender["lookups"] == [os.geteuid()]
        assert first_result["port_calls"]["witness"] > 0
        assert contender["port_calls"] == {"witness": 0, "git": 0}
        assert "team-mailbox-evidence.lock" in contender["result"]["next_action"]
        for child in children:
            child.wait(timeout=5)
            assert child.returncode == 0
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
    assert snapshot(tmp_path) == before
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
    assert not list(owner_plane.iterdir())


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("kind", ["missing-entry", "empty", "relative", "invalid-type", "lookup-error", "no-module"])
def test_unavailable_account_home_refuses_without_fallback(tmp_path, monkeypatch, owner_plane, draft, kind):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)

    def unavailable(uid):
        if kind == "missing-entry":
            raise KeyError("private account diagnostic")
        if kind == "lookup-error":
            raise OSError("private account diagnostic")
        return SimpleNamespace(pw_dir={"empty": "", "relative": "relative/home", "invalid-type": None}[kind])

    if hasattr(store_module, "pwd"):
        monkeypatch.setattr(store_module, "pwd", None if kind == "no-module" else SimpleNamespace(getpwuid=unavailable))
    before = snapshot(tmp_path)
    names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    with mailbox(root, hosts=hosts, roles=roles) as box, refusal("missing") as caught:
        if draft:
            box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                "outgoing_stopped": True, "evidence_dir": str(tmp_path / "evidence")})
        else:
            box.source_witness(worktree, tmp_path / "evidence")
    assert caught.value.code == 1 and caught.value.next_action
    diagnostic = "".join(traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__))
    assert "private account diagnostic" not in diagnostic
    assert snapshot(tmp_path) == before
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
    assert not list(owner_plane.iterdir())


@pytest.mark.parametrize("mode", [0o750, 0o755])
def test_account_owner_state_requires_exact_private_mode(tmp_path, owner_plane, mode):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    owner_plane.chmod(mode)
    before = snapshot(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box, refusal("unsafe_path"):
        box.source_witness(worktree, tmp_path / "evidence")
    assert snapshot(tmp_path) == before
    assert not list(owner_plane.iterdir())


@pytest.mark.parametrize("draft", [False, True])
def test_account_owner_state_rejects_foreign_uid(tmp_path, monkeypatch, owner_plane, draft):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    identity = owner_plane.stat()

    def foreign_owner(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            values = list(info)
            values[4] = os.geteuid() + 1
            return os.stat_result(values)
        return info

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "fstat": foreign_owner}))
    before = snapshot(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box, refusal("unsafe_path") as caught:
        if draft:
            box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                "outgoing_stopped": True, "evidence_dir": str(tmp_path / "evidence")})
        else:
            box.source_witness(worktree, tmp_path / "evidence")
    assert caught.value.code == 1 and caught.value.next_action
    assert snapshot(tmp_path) == before
    assert not list(owner_plane.iterdir())


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("evidence", [False, True])
def test_unavailable_owner_precedes_all_host_ports(tmp_path, monkeypatch, owner_plane, draft, evidence):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    calls.clear()
    git_calls = []
    git = hosts["test-host"].git

    def tracked_git(*args):
        git_calls.append(args)
        return git(*args)

    hosts["test-host"].git = tracked_git
    owner_plane.rmdir()
    with mailbox(root, hosts=hosts, roles=roles) as box, refusal("missing"):
        directory = tmp_path / "evidence" if evidence else None
        if draft:
            request = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                       "outgoing_stopped": True}
            if evidence:
                request["evidence_dir"] = str(directory)
            box.draft_handoff(request)
        else:
            box.source_witness(worktree, directory)
    assert calls == []
    assert git_calls == []


@pytest.mark.parametrize("surface", ["status", "mkdir", "directory", "publish", "lock", "initialize"])
@pytest.mark.parametrize("draft", [False, True])
def test_every_evidence_mutator_contends_before_entering_uncommitted_leaf(tmp_path, surface, draft):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    evidence = tmp_path / "evidence"
    entered, release = Event(), Event()
    observe = hosts["test-host"].source_witness

    def blocked(path, directory):
        if directory is None:
            return observe(path, directory)
        entered.set()
        assert release.wait(5)
        return {}

    hosts["test-host"].source_witness = blocked
    with mailbox(root, hosts=hosts, roles=roles) as box, store_module.Store(root) as peer:
        def run():
            if draft:
                return box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                    "outgoing_stopped": True, "evidence_dir": str(evidence)})
            return box.source_witness(worktree, evidence)

        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(run)
            try:
                assert entered.wait(5) and evidence.is_dir()
                raw = b" M child.py\0"
                with pytest.raises(BusyError) as caught:
                    if surface == "status":
                        peer.publish_status_evidence(evidence / "child", raw, hashlib.sha256(raw).hexdigest())
                    elif surface == "mkdir":
                        peer.mkdir(evidence / "child")
                    elif surface == "directory":
                        with peer.directory(evidence / "child", create=True):
                            pytest.fail("contending directory admitted")
                    elif surface == "publish":
                        peer.publish(evidence / "child" / "artifact.status", raw)
                    elif surface == "lock":
                        with peer.lock(evidence / "child", create=True):
                            pytest.fail("contending lock admitted")
                    else:
                        mail.initialize(evidence / "child", MANIFEST, roles=roles, caller_role="owner")
                assert caught.value.reason == "busy" and caught.value.code == 1
                assert "team-mailbox-evidence.lock" in caught.value.next_action
            finally:
                release.set()
                pending.exception(timeout=5)
            with refusal("invalid_record"):
                pending.result(timeout=5)
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names


@pytest.mark.parametrize("surface", ["status", "mkdir", "directory", "publish", "lock"])
def test_direct_evidence_mutators_refuse_missing_ancestors(tmp_path, surface):
    root = make_store(tmp_path)
    target = tmp_path / "absent" / "evidence"
    before = snapshot(tmp_path)
    names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    with store_module.Store(root) as store, refusal("missing") as caught:
        if surface == "status":
            raw = b" M owned.py\0"
            store.publish_status_evidence(target, raw, hashlib.sha256(raw).hexdigest())
        elif surface == "mkdir":
            store.mkdir(target)
        elif surface == "directory":
            with store.directory(target, create=True):
                pytest.fail("missing parent admitted")
        elif surface == "publish":
            store.publish(target / "artifact.status", b"bounded")
        else:
            with store.lock(target, create=True):
                pytest.fail("missing parent admitted")
    assert caught.value.code == 1
    assert snapshot(tmp_path) == before
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names


def test_host_stage_publication_expires_with_its_observation(tmp_path):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    observe = hosts["test-host"].source_witness
    stages = []

    def witness(path, directory):
        stages.append(directory)
        return observe(path, directory)

    hosts["test-host"].source_witness = witness
    with mailbox(root, hosts=hosts, roles=roles) as box:
        result = box.source_witness(worktree, tmp_path / "evidence")
    before = snapshot(tmp_path)
    raw = b" M owned.py\0"
    with store_module.Store(root) as store, refusal("invalid_record"):
        store.publish_status_evidence(stages[0], raw, hashlib.sha256(raw).hexdigest())
    assert snapshot(tmp_path) == before
    assert Path(result["dirty_evidence"]).read_bytes() == raw
    assert not Path(stages[0]).exists()


@pytest.mark.parametrize("surface,existing", [("status", False), ("status", True),
    ("publish", False), ("publish", True), ("borrowed", True)])
def test_direct_evidence_failure_rolls_back_before_owner_release(tmp_path, monkeypatch, surface, existing):
    root = make_store(tmp_path)
    evidence = tmp_path / "evidence"
    if existing:
        evidence.mkdir(mode=0o700)
        (evidence / "sentinel").write_bytes(b"preserved")
    failed = []

    def fail_directory_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed.append(fd)
            raise OSError("private sync diagnostic")
        return os.fsync(fd)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "fsync": fail_directory_sync}))
    before = snapshot(tmp_path)
    names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    with store_module.Store(root) as store:
        with store.directory(evidence if surface == "borrowed" else root) as parent:
            with refusal("io") as caught:
                raw = b" M owned.py\0"
                if surface == "status":
                    store.publish_status_evidence(evidence, raw, hashlib.sha256(raw).hexdigest())
                else:
                    store.publish(evidence / "artifact.status", raw, parent=parent if surface == "borrowed" else None)
            assert caught.value.code == 1
    assert failed
    assert snapshot(tmp_path) == before
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names


@pytest.mark.parametrize("surface", ["status", "initialize"])
def test_direct_evidence_commit_warns_on_owner_release_failure(tmp_path, monkeypatch, surface):
    root = make_store(tmp_path)
    failed, warnings = [], []

    def failed_release(name, **kwargs):
        result = os.unlink(name, **kwargs)
        if name == "team-mailbox-evidence.lock" and not failed:
            failed.append(name)
            raise OSError("private release diagnostic")
        return result

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": failed_release}))
    if surface == "status":
        raw = b" M owned.py\0"
        with store_module.Store(root) as store:
            path = store.publish_status_evidence(tmp_path / "evidence", raw, hashlib.sha256(raw).hexdigest(), warnings=warnings)
        assert Path(path).read_bytes() == raw
    else:
        result = mail.initialize(tmp_path / "peer-mail", MANIFEST, roles=ROLES, caller_role="owner")
        warnings = result["warnings"]
        assert (tmp_path / "peer-mail" / "manifest.json").is_file()
    assert len(failed) == len(warnings) == 1
    assert warnings[0]["reason"] == "lock_release" and warnings[0]["code"] == 0
    assert "private release diagnostic" not in json.dumps(warnings)
    assert not list(tmp_path.rglob("*.lock"))


@pytest.mark.parametrize("surface,lock_kind", [("status", "owner"), ("directory", "owner"),
    ("mkdir", "owner"), ("publish", "owner"), ("lock", "owner"), ("lock", "local")])
@pytest.mark.parametrize("next_api", ["source", "draft", "status", "bindings", "git", "messages"])
def test_standalone_release_warning_survives_until_public_result(tmp_path, monkeypatch, owner_plane, surface, lock_kind, next_api):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    evidence = tmp_path / "standalone-evidence"
    retained = []

    def retain_release(name, **kwargs):
        matches = name == ("team-mailbox-evidence.lock" if lock_kind == "owner" else ".write.lock")
        if matches and not retained:
            retained.append(name)
            raise OSError("private release diagnostic")
        return os.unlink(name, **kwargs)

    with mailbox(root, hosts=hosts, roles=roles) as box:
        box.publish(request("warnings"))
        history = box.bindings("alpha/orchestrator")
        records = box.messages()
        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": retain_release}))
        raw = b" M owned.py\0"
        if surface == "status":
            path = box.store.publish_status_evidence(evidence, raw, hashlib.sha256(raw).hexdigest())
            assert type(path) is str and Path(path).read_bytes() == raw
        elif surface == "directory":
            with box.store.directory(evidence, create=True) as descriptor:
                assert type(descriptor) is int
        elif surface == "mkdir":
            assert box.store.mkdir(evidence) is None
        elif surface == "publish":
            assert box.store.publish(evidence / "artifact.status", raw) is None
            assert (evidence / "artifact.status").read_bytes() == raw
        else:
            with box.store.lock(evidence, create=True) as marker:
                assert marker is None
        assert evidence.is_dir() and len(retained) == 1
        pending = getattr(box.store, "warnings", None)
        assert pending, "standalone release warning was discarded"
        assert len(pending) == 1
        warning = pending[0]
        assert warning["status"] == "warning" and warning["reason"] == "lock_release" and warning["code"] == 0
        lock = (owner_plane if lock_kind == "owner" else evidence) / retained[0]
        assert lock.is_file() and warning["lock_path"].endswith("/" + lock.name)
        assert "private release diagnostic" not in json.dumps(pending)
        if lock_kind == "owner":
            with pytest.raises(BusyError):
                box.source_witness(worktree)
            assert box.store.warnings == pending
        lock.unlink()
        if next_api == "source":
            result = box.source_witness(worktree)
            assert result["worktree"] == worktree
        elif next_api == "draft":
            result = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                                        "outgoing_stopped": True})
            assert all("warnings" not in source for source in result["checkpoint"]["sources"])
        elif next_api == "status":
            result = box.status()
            assert result["messages"] == len(records)
        elif next_api == "bindings":
            result = box.bindings("alpha/orchestrator")
            assert result == history and box.store.warnings == [warning]
            result = box.status()
        elif next_api == "git":
            result = box.git(worktree, "branch", "--show-current")
            assert result == "branch" and box.store.warnings == [warning]
            result = box.status()
        else:
            result = box.messages()
            assert result == records and box.store.warnings == [warning]
            result = box.status()
        assert result["warnings"] == [warning]
        assert box.store.warnings is pending and pending == []
        assert "warnings" not in box.status()


@pytest.fixture
def default_delivery_store(tmp_path):
    root = make_store(tmp_path)
    with mail.Mailbox(root, clock=lambda: NOW, roles=ROLES, hosts=HOSTS, caller_role="owner") as box:
        bind(box, "alpha/front-door")
        bind(box, "alpha/orchestrator")
        box.publish(request())
        yield root, box


def write_default_receipt(box, directory, surface):
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["message"]}
    if surface == "record_read":
        return box.record_read(directory, {"from": "alpha/orchestrator", "host": "test-host",
                                           "session": "alpha/orchestrator", "binding_generation": 1}, ["message"])
    if surface == "wakes":
        receipt.update(wake_id="wake", state="started", exit_code=None, timed_out=False)
    return box.write_delivery_receipt(directory, surface, receipt)


@pytest.mark.parametrize("surface", ["reads", "wakes", "record_read"])
def test_default_delivery_configuration_creates_fresh_ledger(tmp_path, default_delivery_store, surface):
    _root, box = default_delivery_store
    directory = tmp_path / "fresh" / "delivery"
    assert box.delivery_roots == ()
    assert write_default_receipt(box, directory, surface) is None
    kind = "wakes" if surface == "wakes" else "reads"
    rows = box.delivery_receipts(directory, kind, "alpha/orchestrator", box.messages())
    assert len(rows) == 1 and rows[0]["message_ids"] == ["message"]
    assert (directory / kind / "alpha" / "orchestrator").is_dir()


@pytest.mark.parametrize("surface", ["reads", "wakes", "record_read"])
@pytest.mark.parametrize("lock_kind", ["owner", "mailbox", "ledger"])
def test_none_receipt_results_retain_release_warning_for_next_result(tmp_path, default_delivery_store, monkeypatch, owner_plane, surface, lock_kind):
    root, box = default_delivery_store
    directory = tmp_path / "fresh" / "delivery"
    retained = []
    root_identity = root.stat()

    def retain_release(name, **kwargs):
        info = os.fstat(kwargs["dir_fd"])
        mailbox_parent = (info.st_dev, info.st_ino) == (root_identity.st_dev, root_identity.st_ino)
        matches = (name == "team-mailbox-evidence.lock" if lock_kind == "owner" else
                   name == ".write.lock" and (mailbox_parent if lock_kind == "mailbox" else not mailbox_parent))
        if matches and not retained:
            retained.append(name)
            raise OSError("private receipt release diagnostic")
        return os.unlink(name, **kwargs)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": retain_release}))
    assert write_default_receipt(box, directory, surface) is None
    kind = "wakes" if surface == "wakes" else "reads"
    folder = directory / kind / "alpha" / "orchestrator"
    assert json.loads(next(folder.glob("*.json")).read_bytes())["message_ids"] == ["message"]
    pending = getattr(box.store, "warnings", None)
    assert pending and len(pending) == 1
    warning = pending[0]
    assert warning["status"] == "warning" and warning["reason"] == "lock_release" and warning["code"] == 0
    lock = {"owner": owner_plane, "mailbox": root, "ledger": folder}[lock_kind] / retained[0]
    assert lock.is_file() and warning["lock_path"].endswith("/" + lock.name)
    assert box.status()["warnings"] == [warning]
    assert box.store.warnings is pending and pending == []
    assert "warnings" not in box.status()
    lock.unlink()


@pytest.mark.parametrize("surface", ["reads", "wakes", "record_read"])
def test_default_delivery_creation_rolls_back_failed_publication(tmp_path, default_delivery_store, monkeypatch, surface):
    _root, box = default_delivery_store
    failed = []

    def fail_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed.append(fd)
            raise OSError("private receipt sync diagnostic")
        return os.fsync(fd)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "fsync": fail_sync}))
    before = snapshot(tmp_path)
    names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    with refusal("io") as caught:
        write_default_receipt(box, tmp_path / "fresh" / "delivery", surface)
    assert failed and caught.value.code == 1
    assert snapshot(tmp_path) == before
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names


def test_bind_directory_sync_refusal_preserves_generation_and_tree(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    failed = []

    def fail_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not failed:
            failed.append(fd)
            raise OSError("private binding sync diagnostic")
        return os.fsync(fd)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "fsync": fail_sync}))
    with mailbox(root) as box:
        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with refusal("io") as caught:
            bind(box, "alpha/orchestrator")
        assert failed and caught.value.code == 1
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
        assert box.bindings("alpha/orchestrator") == []
        assert bind(box, "alpha/orchestrator")["generation"] == 1


def test_status_evidence_inside_mailbox_keeps_missing_ancestor_rule(tmp_path):
    root = make_store(tmp_path)
    before = snapshot(tmp_path)
    names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
    with store_module.Store(root) as store, refusal("missing"):
        store.publish_status_evidence(root / "bindings" / "alpha" / "orchestrator", b"", hashlib.sha256(b"").hexdigest())
    assert snapshot(tmp_path) == before
    assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
    with mailbox(root) as box:
        assert box.bindings("alpha/orchestrator") == []


@pytest.mark.parametrize("draft", [False, True])
@pytest.mark.parametrize("keywords", [False, True])
def test_evidence_authorization_precedes_owner_contention(tmp_path, draft, keywords):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    calls.clear()
    git_calls = []
    git = hosts["test-host"].git

    def tracked_git(*args):
        git_calls.append(args)
        return git(*args)

    hosts["test-host"].git = tracked_git
    directory = tmp_path / "evidence"
    with mailbox(root, hosts=hosts, roles=roles) as owner, mailbox(root, hosts=hosts, roles=roles, caller_role="reader") as reader:
        before = snapshot(tmp_path)
        with owner.store.evidence_transaction(), refusal("unauthorized") as caught:
            if draft:
                request = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                           "outgoing_stopped": True, "evidence_dir": str(directory)}
                if keywords:
                    reader.draft_handoff(request=request)
                else:
                    reader.draft_handoff(request)
            elif keywords:
                reader.source_witness(worktree=worktree, evidence_dir=directory)
            else:
                reader.source_witness(worktree, directory)
        assert caught.value.code == 1 and calls == [] and git_calls == []
        assert snapshot(tmp_path) == before
        assert reader.source_witness(worktree)["worktree"] == worktree


def test_warning_capacity_refuses_before_mutation_then_public_read_drains(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    failed = []

    def failed_release(name, **kwargs):
        result = os.unlink(name, **kwargs)
        if name == "team-mailbox-evidence.lock" and len(failed) < 2:
            failed.append(name)
            raise OSError("private release diagnostic")
        return result

    monkeypatch.setattr(store_module, "MAX_RELEASE_WARNINGS", 2)
    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": failed_release}))
    raw = b" M owned.py\0"
    sha = hashlib.sha256(raw).hexdigest()
    with mailbox(root) as box:
        for _index in range(2):
            box.store.publish_status_evidence(tmp_path / "evidence", raw, sha)
        pending = box.store.warnings
        assert len(pending) == 2
        expected = pending[:]
        before = snapshot(tmp_path)
        with refusal("too_large"):
            box.store.publish_status_evidence(tmp_path / "another-evidence", raw, sha)
        assert snapshot(tmp_path) == before and not (tmp_path / "another-evidence").exists()
        assert box.status()["warnings"] == expected
        assert box.store.warnings is pending and pending == []
        assert box.store.publish_status_evidence(tmp_path / "evidence", raw, sha).endswith(sha + ".status")
        assert box.store.warnings == []


def test_warning_reservations_refuse_before_witness_publication(tmp_path, monkeypatch):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    calls.clear()
    monkeypatch.setattr(store_module, "MAX_RELEASE_WARNINGS", 2)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        before = snapshot(tmp_path)
        names = sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*"))
        with refusal("too_large"):
            box.source_witness(worktree, tmp_path / "evidence")
        assert calls == [] and box.store.warnings == []
        assert snapshot(tmp_path) == before
        assert sorted(str(path.relative_to(tmp_path)) for path in tmp_path.rglob("*")) == names
        monkeypatch.setattr(store_module, "MAX_RELEASE_WARNINGS", 3)
        assert Path(box.source_witness(worktree, tmp_path / "evidence")["dirty_evidence"]).is_file()


def test_concurrent_public_read_cannot_hide_originating_release_warning(tmp_path, monkeypatch, owner_plane):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    identity = owner_plane.stat()
    paused, release = Event(), Event()
    failed = []

    def failed_release(name, **kwargs):
        result = os.unlink(name, **kwargs)
        if name == "team-mailbox-evidence.lock" and not failed:
            failed.append(name)
            raise OSError("private release diagnostic")
        return result

    def paused_close(fd):
        info = os.fstat(fd)
        os.close(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino) and failed and not paused.is_set():
            paused.set()
            assert release.wait(5)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": failed_release, "close": paused_close}))
    with mailbox(root, hosts=hosts, roles=roles) as box, ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(box.source_witness, worktree)
        try:
            assert paused.wait(5)
            observed = box.status()["warnings"]
            assert len(observed) == 1 and box.store.warnings == []
        finally:
            release.set()
        result = pending.result(timeout=5)
        assert result["warnings"] == observed and len(result["warnings"]) == 1
        assert "warnings" not in box.status()


@pytest.mark.parametrize("helper", ["independent_session", "evidence_directory"])
def test_public_validation_helpers_keep_nested_warning_delivery_at_boundary(tmp_path, monkeypatch, owner_plane, helper):
    root, hosts, roles, _calls, _worktree = active_handoff_store(tmp_path)
    retained = []

    def retain_release(name, **kwargs):
        if name == "team-mailbox-evidence.lock" and not retained:
            retained.append(name)
            raise OSError("private release diagnostic")
        return os.unlink(name, **kwargs)

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": retain_release}))
    with mailbox(root, hosts=hosts, roles=roles) as box:
        raw = b" M owned.py\0"
        box.store.publish_status_evidence(tmp_path / "evidence", raw, hashlib.sha256(raw).hexdigest())
        expected = box.store.warnings[:]
        assert len(expected) == 1
        (owner_plane / retained[0]).unlink()
        if helper == "independent_session":
            assert box.require_independent_session("alpha/orchestrator", "test-host", "new-session") is None
            assert box.store.warnings == expected
            assert box.status()["warnings"] == expected
        else:
            directory = tmp_path / "validated-evidence"
            result = box.evidence_directory(directory)
            assert result == directory and box.store.warnings == expected
            assert box.status()["warnings"] == expected
        assert box.store.warnings == [] and "warnings" not in box.status()


def queue_release_warning(box, tmp_path, monkeypatch):
    failed = []

    def failed_release(name, **kwargs):
        result = os.unlink(name, **kwargs)
        if name == "team-mailbox-evidence.lock" and not failed:
            failed.append(name)
            raise OSError("private release diagnostic")
        return result

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": failed_release}))
    raw = b" M owned.py\0"
    box.store.publish_status_evidence(tmp_path / "warning-evidence", raw, hashlib.sha256(raw).hexdigest())
    assert failed and box.store.warnings
    return box.store.warnings[:]


@pytest.mark.parametrize("message_id", [None, "ordinary", "warnings"], ids=["empty", "ordinary", "warnings-id"])
def test_warning_sink_does_not_change_data_query_shapes(tmp_path, monkeypatch, message_id):
    root, box = populated(tmp_path)
    with box:
        if message_id is not None:
            box.publish(request(message_id))
        expected = box.messages()
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        records = box.messages()
        assert records == expected
        primitives.record_types(records)
        assert box.endpoint("alpha/orchestrator") == {}
        assert box.dispatch_history(records) == (set(), [])
        assert box.open_job_requests(records) == []
        assert box.delivery_receipts(tmp_path / "delivery", "reads", "alpha/orchestrator", records) == []
        assert box.store.warnings == pending
        result = box.status()
        assert result["warnings"] == pending and result["messages"] == len(expected)
        assert box.store.warnings == []


def test_warning_bearing_draft_round_trips_through_bind_without_persistence(tmp_path, monkeypatch):
    root, hosts, roles, _calls, _worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                                   "outgoing_stopped": True})
        assert draft["warnings"] == pending
        bound = box.bind(draft)
        assert bound["generation"] == 2 and box.ready(bound) is False
        assert "warnings" not in json.loads((root / "bindings" / "alpha" / "orchestrator" / "000002.json").read_bytes())


def test_warning_bearing_binding_round_trips_through_ready_without_persistence(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        bound = bind(box, "alpha/orchestrator")
        assert bound["warnings"] == pending
        assert box.ready(bound) is True
        assert "warnings" not in json.loads((root / "bindings" / "alpha" / "orchestrator" / "000001.json").read_bytes())


def warning_accumulator_case(tmp_path, kind):
    warning = primitives.LockReleaseWarning(tmp_path / "example.lock").as_dict()
    if kind == "string":
        return "invalid", "invalid_record"
    if kind == "mapping":
        return {}, "invalid_record"
    if kind == "oversize":
        return [warning] * (store_module.MAX_RELEASE_WARNINGS + 1), "too_large"
    if kind == "empty-entry":
        return [{}], "invalid_record"
    if kind == "bool-code":
        warning["code"] = False
    elif kind == "wrong-status":
        warning["status"] = "refused"
    elif kind == "bad-action":
        warning["next_action"] = []
    elif kind == "bad-path":
        warning["lock_path"] = "x" * 1025
    elif kind == "extra-field":
        warning["extra"] = "invalid"
    return [warning], "invalid_record"


@pytest.mark.parametrize("surface", ["transaction", "witnesses", "status", "stage"])
@pytest.mark.parametrize("kind", ["string", "mapping", "oversize", "empty-entry", "bool-code",
    "wrong-status", "bad-action", "bad-path", "extra-field"])
def test_warning_accumulators_refuse_invalid_values_before_publication(tmp_path, monkeypatch, surface, kind):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    invalid, reason = warning_accumulator_case(tmp_path, kind)
    raw = b" M owned.py\0"
    sha = hashlib.sha256(raw).hexdigest()
    with mailbox(root, hosts=hosts, roles=roles) as box:
        if surface == "stage":
            original = hosts["test-host"].source_witness
            observed = []

            def witness(path, directory):
                before = sorted(p.name for p in Path(directory).iterdir())
                with store_module.Store(root) as peer, refusal(reason) as caught:
                    peer.publish_status_evidence(directory, raw, sha, warnings=invalid)
                assert caught.value.code == 1
                assert sorted(p.name for p in Path(directory).iterdir()) == before
                observed.append(True)
                return original(path, directory)

            hosts["test-host"].source_witness = witness
            result = box.source_witness(worktree, tmp_path / "evidence")
            assert observed and Path(result["dirty_evidence"]).is_file()
        else:
            before = snapshot(tmp_path)
            names = sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*"))
            with refusal(reason) as caught:
                if surface == "transaction":
                    with box.store.evidence_transaction(invalid):
                        pytest.fail("invalid accumulator admitted")
                elif surface == "witnesses":
                    box.store.witnesses([worktree], tmp_path / "evidence", box.host_call, warnings=invalid)
                else:
                    box.store.publish_status_evidence(tmp_path / "evidence", raw, sha, warnings=invalid)
            assert caught.value.code == 1 and snapshot(tmp_path) == before
            assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == names


@pytest.mark.parametrize("surface", ["transaction", "witnesses", "status", "stage"])
def test_nonempty_typed_warning_accumulators_are_reusable(tmp_path, surface):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    existing = primitives.LockReleaseWarning(tmp_path / "earlier.lock").as_dict()
    accumulator = [existing]
    raw = b" M owned.py\0"
    with mailbox(root, hosts=hosts, roles=roles) as box:
        if surface == "transaction":
            with box.store.evidence_transaction(accumulator):
                pass
        elif surface == "witnesses":
            result = box.store.witnesses([worktree], tmp_path / "evidence", box.host_call, warnings=accumulator)
            assert Path(result[0]["dirty_evidence"]).is_file()
        elif surface == "status":
            result = box.store.publish_status_evidence(tmp_path / "evidence", raw, hashlib.sha256(raw).hexdigest(), warnings=accumulator)
            assert Path(result).read_bytes() == raw
        else:
            original = hosts["test-host"].source_witness

            def witness(path, directory):
                with store_module.Store(root) as peer:
                    peer.publish_status_evidence(directory, raw, hashlib.sha256(raw).hexdigest(), warnings=accumulator)
                return original(path, directory)

            hosts["test-host"].source_witness = witness
            assert Path(box.source_witness(worktree, tmp_path / "evidence")["dirty_evidence"]).is_file()
        assert accumulator == [existing]


@pytest.mark.parametrize("surface", ["bind", "ready"])
@pytest.mark.parametrize("kind", ["string", "mapping", "oversize", "empty-entry", "bool-code",
    "wrong-status", "bad-action", "bad-path", "extra-field"])
def test_result_warning_metadata_is_validated_before_use(tmp_path, surface, kind):
    root = make_store(tmp_path)
    invalid, reason = warning_accumulator_case(tmp_path, kind)
    with mailbox(root) as box:
        binding = bind(box, "alpha/front-door")
        before = snapshot(tmp_path)
        with refusal(reason) as caught:
            if surface == "bind":
                box.bind({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                          "expected_generation": 0, "warnings": invalid})
            else:
                box.ready({**binding, "warnings": invalid})
        assert caught.value.code == 1 and snapshot(tmp_path) == before


def test_large_bounded_warning_metadata_does_not_enter_record_budget(tmp_path):
    root = make_store(tmp_path)
    warning = primitives.LockReleaseWarning(Path("/") / ("x" * 200) / ("y" * 200) / ("z" * 200) / "example.lock").as_dict()
    warnings = [warning] * store_module.MAX_RELEASE_WARNINGS
    assert len(json.dumps(warnings).encode()) > primitives.MAX_BYTES
    with mailbox(root) as box:
        bound = box.bind({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                          "expected_generation": 0, "warnings": warnings})
        assert "warnings" not in bound and box.ready({**bound, "warnings": warnings}) is True
        assert "warnings" not in json.loads((root / "bindings" / "alpha" / "orchestrator" / "000001.json").read_bytes())


def test_mailbox_platform_probe_precedes_backslash_delivery_root_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(store_module, "descriptor_supported", lambda: False)
    with refusal("unsupported_platform") as caught:
        mailbox(tmp_path / "mail", delivery_roots=(r"C:\owner\delivery",))
    assert caught.value.code == 1 and list(tmp_path.iterdir()) == []


def test_caller_warning_accumulator_reuses_actual_release_warnings(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    failures, accumulator = [], []

    def fail_release(name, **kwargs):
        result = os.unlink(name, **kwargs)
        if name == "team-mailbox-evidence.lock" and len(failures) < 2:
            failures.append(name)
            raise OSError("private release diagnostic")
        return result

    monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": fail_release}))
    with mailbox(root) as box:
        raw = b" M owned.py\0"
        for _index in range(2):
            box.store.publish_status_evidence(tmp_path / "evidence", raw, hashlib.sha256(raw).hexdigest(), warnings=accumulator)
        assert len(failures) == len(accumulator) == 2
        assert box.store.warnings == accumulator and box.store.warnings is not accumulator
        expected = accumulator[:]
        assert box.status()["warnings"] == expected and box.store.warnings == []
        box.store.publish_status_evidence(tmp_path / "evidence", raw, hashlib.sha256(raw).hexdigest(), warnings=accumulator)
        assert accumulator == expected and box.store.warnings == []


def test_nonempty_store_sink_can_be_a_witness_accumulator(tmp_path, monkeypatch):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        failures = []

        def fail_release(name, **kwargs):
            result = os.unlink(name, **kwargs)
            if name.startswith(".witness-") and not failures:
                failures.append(name)
                raise OSError("private release diagnostic")
            return result

        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": fail_release}))
        result = box.store.witnesses([worktree], tmp_path / "evidence", box.host_call, warnings=box.store.warnings)
        assert Path(result[0]["dirty_evidence"]).is_file() and failures
        assert box.store.warnings[0] == pending[0] and len(box.store.warnings) == 2
        expected = box.store.warnings[:]
        assert box.status()["warnings"] == expected and box.store.warnings == []


def test_warning_accumulator_capacity_is_reserved_before_publication(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    warning = primitives.LockReleaseWarning(tmp_path / "earlier.lock").as_dict()
    accumulator = [warning] * store_module.MAX_RELEASE_WARNINGS
    with store_module.Store(root) as store:
        before = snapshot(tmp_path)
        raw = b" M owned.py\0"
        with refusal("too_large"):
            store.publish_status_evidence(tmp_path / "evidence", raw, hashlib.sha256(raw).hexdigest(), warnings=accumulator)
        assert snapshot(tmp_path) == before and not (tmp_path / "evidence").exists()
        assert len(accumulator) == store_module.MAX_RELEASE_WARNINGS and store.warnings == []
        accumulator.pop()

        def fail_release(name, **kwargs):
            result = os.unlink(name, **kwargs)
            if name == "team-mailbox-evidence.lock":
                raise OSError("private release diagnostic")
            return result

        monkeypatch.setattr(store_module, "os", SimpleNamespace(**{**vars(os), "unlink": fail_release}))
        assert Path(store.publish_status_evidence(tmp_path / "evidence", raw, hashlib.sha256(raw).hexdigest(), warnings=accumulator)).is_file()
        assert len(accumulator) == store_module.MAX_RELEASE_WARNINGS and len(store.warnings) == 1


def source_result_consumer(box, source, draft, worktree, directory, surface):
    checkpoint = {**draft["checkpoint"], "sources": [source]}
    if surface == "bind":
        return box.bind({**draft, "checkpoint": checkpoint})
    if surface == "witness":
        return primitives.witness_record(source, worktree)
    if surface == "checkpoint":
        return box.checkpoint(checkpoint, box.messages())
    if surface == "assignments":
        return box.checkpoint_assignments("alpha/orchestrator", checkpoint, box.messages())
    if surface == "ready":
        binding = {**box.current_binding("alpha/orchestrator"), "checkpoint": checkpoint}
        return box.ready(binding)
    assert surface == "expected"
    return box.store.witnesses([worktree], directory, box.host_call, expected=[source])


@pytest.mark.parametrize("surface", ["bind", "witness", "checkpoint", "assignments", "ready", "expected"])
@pytest.mark.parametrize("large", [False, True], ids=["actual-warning", "large-diagnostics"])
def test_source_result_warning_metadata_round_trips_from_copy(tmp_path, monkeypatch, surface, large):
    root, hosts, roles, _calls, worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                                   "outgoing_stopped": True})
        if surface == "ready":
            box.bind(draft)
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        source = box.source_witness(worktree)
        assert source["warnings"] == pending
        if large:
            warning = primitives.LockReleaseWarning(Path("/") / ("x" * 200) / ("y" * 200) / ("z" * 200) / "example.lock").as_dict()
            source["warnings"] = [warning] * store_module.MAX_RELEASE_WARNINGS
            assert len(json.dumps(source["warnings"]).encode()) > primitives.MAX_BYTES
        original = json.loads(json.dumps(source))
        before = snapshot(root)
        result = source_result_consumer(box, source, draft, worktree, tmp_path / "evidence", surface)
        assert source == original and source["warnings"]
        clean = {key: value for key, value in source.items() if key != "warnings"}
        if surface == "bind":
            assert result["checkpoint"]["sources"] == [clean]
            persisted = json.loads((root / "bindings" / "alpha" / "orchestrator" / "000002.json").read_bytes())
            assert persisted["checkpoint"]["sources"] == [clean]
            assert "warnings" not in persisted and "warnings" not in json.dumps(persisted)
            assert box.bindings("alpha/orchestrator")[-1] == persisted
        elif surface == "witness":
            assert result == clean and result is not source
        elif surface == "expected":
            assert result[0] == {**clean, "dirty_evidence": result[0]["dirty_evidence"]}
            assert Path(result[0]["dirty_evidence"]).read_bytes() == b" M owned.py\0"
        elif surface == "ready":
            assert result is False
        else:
            assert result is None if surface == "checkpoint" else result == []
        if surface != "bind":
            assert snapshot(root) == before


@pytest.mark.parametrize("surface", ["bind", "witness", "checkpoint", "assignments", "ready", "expected"])
@pytest.mark.parametrize("kind", ["string", "mapping", "oversize", "empty-entry", "bool-code",
    "wrong-status", "bad-action", "bad-path", "extra-field", "null"])
def test_source_result_warning_metadata_refuses_before_observation(tmp_path, surface, kind):
    root, hosts, roles, calls, worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                                   "outgoing_stopped": True})
        if surface == "ready":
            box.bind(draft)
        invalid, reason = (None, "invalid_record") if kind == "null" else warning_accumulator_case(tmp_path, kind)
        source = {**box.source_witness(worktree), "warnings": invalid}
        original = json.loads(json.dumps(source))
        before, observations = snapshot(tmp_path), calls[:]
        with refusal(reason) as caught:
            source_result_consumer(box, source, draft, worktree, tmp_path / "evidence", surface)
        assert caught.value.code == 1 and source == original
        assert calls == observations and snapshot(tmp_path) == before
        assert not (tmp_path / "evidence").exists()


@pytest.mark.parametrize("location", ["binding", "checkpoint", "source"])
def test_persisted_binding_warning_metadata_is_still_refused(tmp_path, location):
    root, hosts, roles, _calls, _worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                                   "outgoing_stopped": True})
        box.bind(draft)
        path = root / "bindings" / "alpha" / "orchestrator" / "000002.json"
        record = json.loads(path.read_bytes())
        target = record if location == "binding" else record["checkpoint"] if location == "checkpoint" else record["checkpoint"]["sources"][0]
        target["warnings"] = [primitives.LockReleaseWarning(tmp_path / "earlier.lock").as_dict()]
        record["checkpoint_sha256"] = primitives.digest(record["checkpoint"])
        path.write_bytes(primitives.encoded(record) + b"\n")
        before = snapshot(root)
        with refusal("invalid_record"):
            box.bindings("alpha/orchestrator")
        assert snapshot(root) == before


@pytest.mark.parametrize("surface", ["records", "reply", "dispatch", "jobs", "inbox"])
@pytest.mark.parametrize("kind", ["valid", "bool-code", "oversize"])
def test_publish_and_inbox_result_metadata_is_validated_from_copy(tmp_path, monkeypatch, surface, kind):
    root, box = populated(tmp_path)
    with box:
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        published = box.publish(request("warnings"))
        assert published["warnings"] == pending
        if kind != "valid":
            published["warnings"], reason = warning_accumulator_case(tmp_path, kind)
        records = {"warnings": published}
        original = json.loads(json.dumps(records))
        inbox = box.inbox("alpha/orchestrator")
        inbox["messages"] = [published]
        inbox["warnings"] = pending

        def consume():
            if surface == "records":
                return primitives.record_types(records)
            if surface == "reply":
                return mail.Mailbox.reply({"from": "alpha/orchestrator", "to": "alpha/front-door", "in_reply_to": "warnings"}, records)
            if surface == "dispatch":
                return mail.Mailbox.dispatch_history(records)
            if surface == "jobs":
                return mail.Mailbox.open_job_requests(records)
            return primitives.bounded_inbox(inbox, lambda value: json.dumps(value))

        if kind == "valid":
            result = consume()
            if surface == "inbox":
                assert result["warnings"] == pending and result["messages"][0]["warnings"] == pending
                assert result["messages"][0]["message"]["message_id"] == "warnings"
        else:
            with refusal(reason) as caught:
                consume()
            assert caught.value.code == 1
        assert records == original


@pytest.mark.parametrize("location", ["envelope", "message", "binding", "source"])
@pytest.mark.parametrize("kind", ["valid", "bool-code", "oversize"])
def test_inbox_result_metadata_is_validated_before_rendering(tmp_path, monkeypatch, location, kind):
    root, hosts, roles, _calls, _worktree = active_handoff_store(tmp_path)
    with mailbox(root, hosts=hosts, roles=roles) as box:
        draft = box.draft_handoff({"endpoint": "alpha/orchestrator", "host": "test-host", "session": "next",
                                   "outgoing_stopped": True})
        box.bind(draft)
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        inbox = box.inbox("alpha/orchestrator")
        warning, reason = (pending, None) if kind == "valid" else warning_accumulator_case(tmp_path, kind)
        targets = {"envelope": inbox, "message": inbox["messages"][0], "binding": inbox["binding"],
                   "source": inbox["binding"]["checkpoint"]["sources"][0]}
        target = targets[location]
        target["warnings"] = warning
        original = json.loads(json.dumps(inbox))
        rendered = []

        def render(value):
            rendered.append(value)
            assert value["warnings"] == pending
            if location == "binding":
                assert value["binding"]["warnings"] == warning
            elif location == "source":
                assert value["binding"]["checkpoint"]["sources"][0]["warnings"] == warning
            elif location == "message" and value["messages"]:
                assert value["messages"][0]["warnings"] == warning
            return json.dumps(value)

        if kind == "valid":
            assert primitives.bounded_inbox(inbox, render)["binding"]["endpoint"] == "alpha/orchestrator"
            assert rendered
        else:
            with refusal(reason):
                primitives.bounded_inbox(inbox, render)
            assert not rendered
        assert inbox == original


@pytest.mark.parametrize("producer", ["bind", "status", "inbox", "binding_view"])
@pytest.mark.parametrize("large_warnings", [False, True], ids=["ready-metadata", "large-diagnostics"])
def test_binding_at_admission_limit_round_trips_from_every_producer(tmp_path, producer, large_warnings):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bind(box, "alpha/front-door")
        candidate = replacement_request(tmp_path, 1)
        checks = candidate["checkpoint"]["completed_checks"] = ["x" * 4096] * 63 + ["x"]
        model = {**box.current_binding("alpha/front-door"), "session": candidate["session"], "generation": 2,
                 "checkpoint": candidate["checkpoint"], "checkpoint_sha256": "0" * 64}
        wire_size = len(json.dumps(model, sort_keys=True, separators=(",", ":")).encode()) + 1
        fill = primitives.MAX_BYTES - wire_size
        assert 0 <= fill < 4096
        checks[-1] += "x" * fill
        bound = box.bind(candidate)
        path = root / "bindings" / "alpha" / "front-door" / "000002.json"
        raw = path.read_bytes()
        assert len(raw) == primitives.MAX_BYTES
        if producer == "bind":
            result = bound
        elif producer == "status":
            result = box.status()["bindings"]["alpha/front-door"]
        elif producer == "inbox":
            result = box.inbox("alpha/front-door")["binding"]
        else:
            result = box.binding_view("alpha/front-door")["binding"]
        if large_warnings:
            warning = primitives.LockReleaseWarning(Path("/") / ("x" * 200) / ("y" * 200) / ("z" * 200) / "example.lock").as_dict()
            result = {**result, "warnings": [warning] * store_module.MAX_RELEASE_WARNINGS}
        original = json.loads(json.dumps(result))
        assert len(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()) > primitives.MAX_BYTES
        assert box.ready(binding=result) is False
        assert result == original and path.read_bytes() == raw
        box.acknowledge_handoff(handoff_ack(bound))
        assert box.ready(binding=result) is True
        assert result == original and path.read_bytes() == raw


@pytest.mark.parametrize("value", [None, 0, 1, "true", [], {}, "x" * (primitives.MAX_BYTES + 1)],
                         ids=["null", "zero", "one", "text", "array", "mapping", "large-text"])
def test_binding_ready_metadata_has_separate_type_validation(tmp_path, value):
    root = make_store(tmp_path)
    with mailbox(root) as box:
        bound = bind(box, "alpha/orchestrator")
        before = snapshot(root)
        with refusal("invalid_record") as caught:
            box.ready({**bound, "ready": value})
        assert caught.value.code == 1 and snapshot(root) == before


def test_paged_inbox_preserves_one_pending_warning_within_transport_budget(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    with box:
        box.publish(request("first"))
        box.publish(request("second"))
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        inbox = box.inbox("alpha/orchestrator")
        assert inbox["warnings"] == pending and box.store.warnings == []
        first = {**inbox, "messages": inbox["messages"][:1], "remaining": 1, "next_after": "first"}
        original = json.loads(json.dumps(inbox))
        render = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        limit = len(render(first))
        assert len(render(inbox)) > limit
        monkeypatch.setattr(primitives, "MAX_INBOX_RESPONSE_BYTES", limit)
        page = primitives.bounded_inbox(inbox, render)
        assert page == first and len(render(page)) == limit
        assert render(page).count(json.dumps(pending[0]["next_action"]).encode()) == 1
        assert page["warnings"] == pending and inbox == original
        assert "warnings" not in box.inbox("alpha/orchestrator")


def test_paged_inbox_warning_counts_against_transport_budget(tmp_path, monkeypatch):
    root, box = populated(tmp_path)
    with box:
        pending = queue_release_warning(box, tmp_path, monkeypatch)
        inbox = box.inbox("alpha/orchestrator")
        render = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        clean = {key: value for key, value in inbox.items() if key != "warnings"}
        limit = len(render(clean))
        assert len(render(inbox)) > limit
        monkeypatch.setattr(primitives, "MAX_INBOX_RESPONSE_BYTES", limit)
        with refusal("invalid_record") as caught:
            primitives.bounded_inbox(inbox, render)
        assert caught.value.code == 1 and inbox["warnings"] == pending
        monkeypatch.setattr(primitives, "MAX_INBOX_RESPONSE_BYTES", len(render(inbox)))
        assert primitives.bounded_inbox(inbox, render)["warnings"] == pending


@pytest.mark.parametrize("kind,state", [("reads", "read"), ("wakes", "woken")])
def test_delivery_receipt_wire_bytes_after_busy_refusal_and_retry(tmp_path, kind, state):
    root, box = populated(tmp_path)
    directory = tmp_path / "delivery"
    folder = directory / kind / "alpha" / "orchestrator"
    receipt = {"endpoint": "alpha/orchestrator", "host": "test-host", "session": "alpha/orchestrator",
               "generation": 1, "message_ids": ["message"]}
    if kind == "wakes":
        receipt.update(wake_id="wake-1", state="started", exit_code=None, timed_out=False)
    with box:
        box.publish(request())
        before = snapshot(tmp_path)
        with refusal("invalid_record") as caught:
            box.write_delivery_receipt(directory, kind, {**receipt, "message_ids": ["mes\nsage"]})
        assert caught.value.code == 1 and snapshot(tmp_path) == before
        folder.mkdir(parents=True)
        with box.store.lock(folder, create=True), ThreadPoolExecutor(max_workers=1) as workers:
            before = snapshot(tmp_path)
            attempt = workers.submit(box.write_delivery_receipt, directory, kind, receipt)
            with refusal("busy") as caught:
                attempt.result(timeout=5)
            assert caught.value.code == 1 and snapshot(tmp_path) == before
        assert box.write_delivery_receipt(directory, kind, receipt) is None
        paths = list(folder.glob("*.json"))
        assert len(paths) == 1
        expected = {"schema": "aegis.hierarchy-delivery-receipt/v1",
                    "at": "2026-11-16T12:00:00.000000Z", **receipt}
        assert paths[0].read_bytes() == json.dumps(expected, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        assert box.delivery(directory, message_id="message")["message"]["state"] == state
