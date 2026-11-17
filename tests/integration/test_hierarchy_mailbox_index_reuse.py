"""Reader-local shadow reuse keeps current pinned outcomes and diagnostics."""
from concurrent.futures import ThreadPoolExecutor
import importlib
import json
from pathlib import Path
from threading import Barrier, Event, Thread
import weakref

import pytest


READERS = ("hierarchy_jobs", "hierarchy_sweep", "hierarchy_provision", "hierarchy_provider_recovery")


@pytest.fixture(params=READERS)
def reader(request):
    return importlib.import_module("tools." + request.param)


def make_mailbox(root):
    import hierarchy_mailbox as hm

    endpoints = {"a/front-door": {}, "a/orchestrator": {}, "a/lane/review": {"kind": "reviewer"}}
    hm.initialize(root, {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 3,
                         "endpoints": endpoints, "counterparts": []})
    mailbox = hm.Mailbox(root)
    for endpoint in endpoints:
        mailbox.bind({"endpoint": endpoint, "host": "test-host", "session": endpoint,
                      "expected_generation": 0})
    return mailbox


def publish(mailbox, identifier="seed"):
    mailbox.publish({"message_id": identifier, "from": "a/orchestrator", "to": "a/lane/review",
                     "host": "test-host", "session": "a/orchestrator", "binding_generation": 1,
                     "type": "info", "body": "original body"})


def read(index, api):
    return index.messages() if api == "messages" else index.get("absent" if api == "missing" else "seed")


def assert_fresh_parity(reader, mailbox, index, api):
    import hierarchy_mailbox as hm

    expected = reader.MailboxIndex(mailbox, mode="shadow")
    assert hm.encoded(read(index, api)) == hm.encoded(read(expected, api))
    assert index.last_divergence == expected.last_divergence


def test_factory_reuses_each_path_and_keeps_readers_independent(reader, tmp_path):
    import hierarchy_mailbox as hm

    mailbox = make_mailbox(tmp_path / "mailbox")
    index = reader.mailbox_reader(mailbox)
    assert index.mode == "shadow"
    assert reader.mailbox_reader(mailbox) is index
    assert reader.mailbox_reader(hm.Mailbox(mailbox.root)) is not index
    other = make_mailbox(tmp_path / "other")
    assert reader.mailbox_reader(other) is not index
    assert reader.mailbox_reader(mailbox) is index
    for name in READERS:
        if name != reader.__name__.split(".")[-1]:
            assert importlib.import_module("tools." + name).mailbox_reader(mailbox) is not index


@pytest.mark.parametrize("api", ["messages", "get", "missing"])
@pytest.mark.parametrize("change", ["publish", "rewrite", "reformat", "delete", "refusal_retry", "oversize_retry"])
def test_reused_reader_revalidates_changes_and_recovers(reader, tmp_path, api, change):
    import hierarchy_mailbox as hm

    mailbox = make_mailbox(tmp_path / "mailbox")
    publish(mailbox)
    index = reader.mailbox_reader(mailbox)
    assert_fresh_parity(reader, mailbox, index, api)
    path = Path(mailbox.messages()["seed"]["path"])
    original = path.read_bytes()
    if change == "publish":
        publish(mailbox, "late")
    elif change == "rewrite":
        path.write_bytes(original.replace(b"original body", b"changed body"))
    elif change == "reformat":
        path.write_bytes(original.replace(b"---\n", b"---\n ", 1))
    elif change == "delete":
        path.unlink()
    else:
        path.write_bytes(b"malformed record" if change == "refusal_retry" else b"x" * (hm.MAX_BYTES + 1))
        with pytest.raises(ValueError) as expected:
            read(reader.MailboxIndex(mailbox, mode="shadow"), api)
        for _ in range(2):
            assert reader.mailbox_reader(mailbox) is index
            assert reader.mailbox_reader(hm.Mailbox(mailbox.root)) is not index
            with pytest.raises(type(expected.value)) as actual:
                read(index, api)
            assert str(actual.value) == str(expected.value)
        path.write_bytes(original)
    assert reader.mailbox_reader(mailbox) is index
    assert reader.mailbox_reader(hm.Mailbox(mailbox.root)) is not index
    for _ in range(2):
        assert_fresh_parity(reader, mailbox, index, api)


@pytest.mark.parametrize("api", ["messages", "get", "missing"])
@pytest.mark.parametrize("change", ["publish", "rewrite"])
def test_reuse_preserves_shadow_retry_and_divergence(reader, tmp_path, api, change):
    import hierarchy_mailbox as hm

    mailbox = make_mailbox(tmp_path / "mailbox")
    publish(mailbox)
    index = reader.mailbox_reader(mailbox)
    read(index, api)
    original = Path(mailbox.messages()["seed"]["path"]).read_bytes()
    changes = []

    class InterleavedMailbox(hm.Mailbox):
        def messages(self):
            if change == "rewrite":
                changes.append(True)
                path = Path(super().messages()["seed"]["path"])
                path.write_bytes(original.replace(b"original body", ("changed body %d" % len(changes)).encode()))
            elif not changes:
                changes.append(True)
                publish(self, "late")
            return super().messages()

    current = InterleavedMailbox(mailbox.root)
    current_index = reader.mailbox_reader(current)
    assert current_index is not index
    result = read(current_index, api)
    expected = hm.Mailbox(mailbox.root).messages()
    assert result == (expected if api == "messages" else expected.get("absent" if api == "missing" else "seed"))
    assert changes
    assert bool(current_index.last_divergence) == (change == "rewrite" and api != "missing")
    assert reader.mailbox_reader(mailbox) is index
    assert reader.mailbox_reader(hm.Mailbox(mailbox.root)) is not index
    assert_fresh_parity(reader, hm.Mailbox(mailbox.root), index, api)


def test_reuse_uses_the_current_mailbox_authority(reader, tmp_path):
    import hierarchy_mailbox as hm

    mailbox = make_mailbox(tmp_path / "mailbox")
    publish(mailbox)
    index = reader.mailbox_reader(mailbox)
    index.messages()

    class RefusingMailbox(hm.Mailbox):
        def messages(self):
            raise ValueError("current authority refused")

    refusing = reader.mailbox_reader(RefusingMailbox(mailbox.root))
    assert refusing is not index
    with pytest.raises(ValueError, match="^current authority refused$"):
        refusing.messages()
    assert reader.mailbox_reader(mailbox) is index
    assert reader.mailbox_reader(hm.Mailbox(mailbox.root)) is not index
    assert_fresh_parity(reader, mailbox, index, "messages")


def test_reuse_revalidates_a_reloaded_manifest_and_recovers(reader, tmp_path):
    import hierarchy_mailbox as hm

    mailbox = make_mailbox(tmp_path / "mailbox")
    publish(mailbox)
    index = reader.mailbox_reader(mailbox)
    index.messages()
    manifest = mailbox.root / "manifest.json"
    original = manifest.read_bytes()
    changed = json.loads(original)
    changed["endpoints"]["a/lane/other"] = {"kind": "reviewer"}
    del changed["endpoints"]["a/lane/review"]
    manifest.write_text(json.dumps(changed), encoding="utf-8")
    current = hm.Mailbox(mailbox.root)
    with pytest.raises(ValueError) as expected:
        current.messages()
    current_index = reader.mailbox_reader(current)
    assert current_index is not index
    with pytest.raises(type(expected.value)) as actual:
        current_index.messages()
    assert str(actual.value) == str(expected.value)
    manifest.write_bytes(original)
    assert reader.mailbox_reader(mailbox) is index
    assert reader.mailbox_reader(hm.Mailbox(mailbox.root)) is not index
    assert_fresh_parity(reader, hm.Mailbox(mailbox.root), index, "messages")


def test_unsupported_descriptor_probe_still_revalidates(reader, tmp_path, monkeypatch):
    monkeypatch.setattr("hierarchy_mailbox_index._checked_reads_supported", lambda: False)
    mailbox = make_mailbox(tmp_path / "mailbox")
    publish(mailbox)
    index = reader.mailbox_reader(mailbox)
    index.messages()
    path = Path(mailbox.messages()["seed"]["path"])
    path.write_bytes(path.read_bytes().replace(b"original body", b"portable body"))
    assert reader.mailbox_reader(mailbox) is index
    assert_fresh_parity(reader, mailbox, index, "messages")


def test_factory_creation_is_shared_across_concurrent_callers(reader, tmp_path):
    mailbox = make_mailbox(tmp_path / "mailbox")
    callers = Barrier(3)

    def concurrent(_):
        callers.wait(timeout=5)
        return reader.mailbox_reader(mailbox)

    with ThreadPoolExecutor(max_workers=3) as pool:
        indexes = list(pool.map(concurrent, range(12)))
    assert all(index is indexes[0] for index in indexes)


def test_reader_cache_does_not_retain_unbounded_mailboxes(reader, tmp_path):
    oldest = reader.mailbox_reader(make_mailbox(tmp_path / "oldest"))
    retired = weakref.ref(oldest)
    del oldest
    for number in range(40):
        reader.mailbox_reader(make_mailbox(tmp_path / ("mailbox-%d" % number)))
    assert retired() is None


@pytest.mark.parametrize("api", ["messages", "get", "missing"])
@pytest.mark.parametrize("order", ["newer_first", "older_first"])
def test_interleaved_manifest_authorities_preserve_each_fresh_outcome(reader, tmp_path, api, order):
    import hierarchy_mailbox as hm

    older = make_mailbox(tmp_path / "mailbox")
    publish(older)
    manifest = older.root / "manifest.json"
    changed = json.loads(manifest.read_bytes())
    changed["endpoints"]["a/lane/other"] = changed["endpoints"].pop("a/lane/review")
    manifest.write_text(json.dumps(changed), encoding="utf-8")
    newer = hm.Mailbox(older.root)

    def outcome(index):
        try:
            return "result", hm.encoded(read(index, api))
        except ValueError as error:
            return type(error), str(error)

    authorities = (newer, older) if order == "newer_first" else (older, newer)
    expected = [outcome(reader.MailboxIndex(authority, mode="shadow")) for authority in authorities]
    # Both callers obtain their reader before either reads. A factory lock alone
    # cannot keep one caller from substituting the other's validation authority.
    callers = [reader.mailbox_reader(authority) for authority in authorities]
    actual = [outcome(index) for index in callers]
    assert actual == expected


@pytest.mark.parametrize("first_api", ["messages", "get"])
@pytest.mark.parametrize("second_api", ["messages", "get"])
def test_same_authority_serializes_complete_shadow_reads(reader, tmp_path, first_api, second_api):
    import hierarchy_mailbox as hm

    mailbox = make_mailbox(tmp_path / "mailbox")
    publish(mailbox)
    first_entered, release_first, second_entered = Event(), Event(), Event()
    second_started, first_done, second_done = Event(), Event(), Event()
    calls, results, errors = [], {}, []

    class GatedMailbox(hm.Mailbox):
        def messages(self):
            if not calls:
                calls.append("first")
                first_entered.set()
                if not release_first.wait(timeout=5):
                    raise ValueError("test authority gate timed out")
            else:
                second_entered.set()
            return super().messages()

    authority = GatedMailbox(mailbox.root)
    index = reader.mailbox_reader(authority)

    def operation(name, api, done):
        try:
            if name == "second":
                second_started.set()
            results[name] = read(index, api)
        except Exception as error:
            errors.append(error)
        finally:
            done.set()

    first = Thread(target=operation, args=("first", first_api, first_done), daemon=True)
    second = Thread(target=operation, args=("second", second_api, second_done), daemon=True)
    first.start()
    try:
        assert first_entered.wait(timeout=5), "first pinned oracle was not entered"
        second.start()
        assert second_started.wait(timeout=5), "second caller did not start"
        # The first caller is deliberately held inside its pinned oracle. This
        # bounded event check tests exclusion, not elapsed read performance.
        assert not second_entered.wait(timeout=0.1), "pinned oracle calls overlapped"
    finally:
        release_first.set()
        first.join(timeout=5)
        if second.ident is not None:
            second.join(timeout=5)
    assert first_done.is_set() and second_done.is_set(), "serialized readers did not finish"
    assert errors == []
    assert hm.encoded(results["first"]) == hm.encoded(read(reader.MailboxIndex(authority, mode="shadow"), first_api))
    assert hm.encoded(results["second"]) == hm.encoded(read(reader.MailboxIndex(authority, mode="shadow"), second_api))
    assert_fresh_parity(reader, authority, index, "messages")


def test_authority_cache_evicts_before_retaining_a_seventeenth_reader(reader, tmp_path):
    import hierarchy_mailbox as hm

    mailbox = make_mailbox(tmp_path / "mailbox")
    authorities = [hm.Mailbox(mailbox.root) for _ in range(17)]
    retained = [weakref.ref(reader.mailbox_reader(authority)) for authority in authorities]
    assert retained[0]() is None
    assert all(reference() is not None for reference in retained[1:])
    assert reader.mailbox_reader(authorities[-1]) is retained[-1]()
