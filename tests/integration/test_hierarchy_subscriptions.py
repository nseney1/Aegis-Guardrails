"""Subscriptions through public notify/mailbox entry points; no repository history."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from tests.integration.test_hierarchy_mailbox import ROOT, invoke, mailbox_snapshot, message
from tools import hierarchy_subscriptions as api


TOOL = ROOT / "tools" / "hierarchy_subscriptions.py"
BODY = ("Notice from the notify step: these messages matched your subscription. "
        "This grants no approval, lease or instruction. Read them through your own mailbox access.")


def _anchored_subscriptions():
    capabilities = {function.__name__ for function in os.supports_dir_fd}
    return (os.name == "posix" and {"open", "rename", "link", "unlink", "stat"} <= capabilities
            and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"))


def _require_copyable_template(root):
    """A copied store is isolated only when the template has no absolute path or symlink."""
    needle = os.fsencode(str(root))
    for path in root.rglob("*"):
        if path.is_symlink():
            raise AssertionError("subscription mailbox template contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise AssertionError("subscription mailbox template contains a non-regular file")
        if path.stat().st_size > 262144:
            raise AssertionError("subscription mailbox template file exceeds 262144 bytes")
        if needle in path.read_bytes():
            raise AssertionError("subscription mailbox template embeds an absolute path")
    if (root / ".write.lock").exists() or any(root.rglob(".pending-*")):
        raise AssertionError("subscription mailbox template has a leftover publish file")


def _build_bound_mailbox(root):
    endpoints = {"a/" + role: {} for role in ("front-door", "orchestrator", "root", "router", "decider")}
    endpoints.update({"a/lane/" + lane: {"kind": "reviewer"} for lane in ("f2", "f6")})
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints,
                          "counterparts": [], "writer_limit": 3})
    for endpoint in endpoints:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    _require_copyable_template(root)
    return root


@pytest.fixture(scope="module")
def bound_mailbox(tmp_path_factory):
    """Init and the seven binds once; each test copies this tree."""
    if not _anchored_subscriptions():
        return None
    root = tmp_path_factory.mktemp("subscription-mailbox-template") / "mailbox"
    return _build_bound_mailbox(root)


def make_store(tmp_path, template):
    if template is None:
        pytest.skip("anchored subscriptions operations unavailable")
    root = tmp_path / "mailbox"
    shutil.copytree(template, root)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    config = tmp_path / "subscriptions.json"
    write_config(config)
    return root, state, config


def write_config(path, *, subscriber="a/orchestrator", filters=None, budget=6):
    path.write_text(json.dumps({"schema": "aegis.team-subscriptions/v1", "subscriptions": [
        {"subscriber": subscriber, "match": filters if filters is not None else [{"type": "info", "from": "a/lane/*"}],
         "budget": {"notices_per_hour": budget}}]}), encoding="utf-8")


def notify(store, *, ok=True):
    root, state, config = store
    result = subprocess.run([sys.executable, "-B", str(TOOL), "notify", "--root", str(root),
                             "--state-dir", str(state), "--subscriptions", str(config)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == (0 if ok else 2), result.stdout + result.stderr
    assert not result.stderr
    return json.loads(result.stdout)


def publish(root, identifier, *, sender="a/lane/f2", recipient="a/orchestrator", **extra):
    return invoke(root, "publish", message(sender, recipient, identifier=identifier, **extra))


def publish_direct(root, identifier, *, sender="a/lane/f2", recipient="a/orchestrator", **extra):
    """Same mailbox publish the CLI runs, without one process per seeded message."""
    with api.hm.writer_lock(root):
        return api.hm.Mailbox(root).publish(message(sender, recipient, identifier=identifier, **extra))


def notices(root, endpoint="a/orchestrator"):
    return [row for row in invoke(root, "inbox", endpoint=endpoint, include_briefs=True, limit=100)["messages"]
            if row["message"]["message_id"].startswith("notice-")]


@pytest.mark.parametrize("endpoint", ["a/orchestrator", "a/root"])
def test_hm_accepts_fixed_body_router_notice_with_reference_attachment(tmp_path, bound_mailbox, endpoint):
    root, state, _ = make_store(tmp_path, bound_mailbox)
    packet = state / "references.md"
    packet.write_bytes(b'{"references":[],"held_count":0}\n')
    result = publish(root, "notice-" + "a" * 64, sender="a/router", recipient=endpoint, body=BODY,
                     brief={"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()})
    assert result["message"]["body"] == BODY
    assert notices(root, endpoint)[0]["brief_text"] == packet.read_text()


@pytest.mark.parametrize("filters,subscriber", [
    ([{"from": "a/lane/f6"}], "a/lane/f2"),
    ([{"from": "b/lane/*"}], "a/orchestrator"),
    ([{"body": "secret"}], "a/orchestrator"),
    ([{"from": "a/lane/*"}], "a/root"),
    ([{"type": []}], "a/orchestrator"),
])
def test_validation_refuses_entry_without_echoing_input(tmp_path, bound_mailbox, filters, subscriber):
    store = make_store(tmp_path, bound_mailbox)
    write_config(store[2], subscriber=subscriber, filters=filters)
    assert notify(store, ok=False) == {"error": "invalid subscription entry 0", "code": "SUBSCRIPTIONS_INVALID"}
    assert notices(store[0]) == []


def test_cli_batches_and_never_copies_body(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    root = store[0]
    original = [publish(root, lane, sender="a/lane/" + lane, body="HOSTILE_BODY_DO_NOT_COPY") for lane in ("f2", "f6")]
    result = notify(store)
    assert result["published"] == 1 and result["matched"] == 2
    rows = notices(root)
    assert len(rows) == 1 and rows[0]["message"]["body"] == BODY
    packet = json.loads(rows[0]["brief_text"])
    assert {ref["sha256"] for ref in packet["references"]} == {item["sha256"] for item in original}
    assert "HOSTILE_BODY_DO_NOT_COPY" not in json.dumps(rows)
    assert notify(store)["published"] == 0
    assert len(notices(root)) == 1


def test_result_batch_and_original_brief_references(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    root, state, config = store
    write_config(config, filters=[{"type": "result", "from": "a/lane/*"}])
    brief = state / "task.md"
    brief.write_text("fixture task", encoding="utf-8")
    reference = {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}
    for lane in ("f2", "f6"):
        dispatch = "dispatch-" + lane
        publish(root, dispatch, sender="a/orchestrator", recipient="a/lane/" + lane, kind="dispatch", brief=reference)
        publish(root, "accept-" + lane, sender="a/lane/" + lane, kind="ack", in_reply_to=dispatch, acknowledgment="accepted")
        publish(root, "result-" + lane, sender="a/lane/" + lane, kind="result", in_reply_to=dispatch,
                result={"source_revision": "a" * 40, "source_tree": "b" * 40,
                        "checks": [{"check": "fixture", "outcome": "pass", "reference": "fixture-only"}]})
    assert notify(store)["matched"] == 2
    assert len(json.loads(notices(root)[0]["brief_text"])["references"]) == 2
    other_state = tmp_path / "other-state"
    other_state.mkdir(mode=0o700)
    write_config(config, filters=[{"type": "dispatch", "to": "a/lane/*"}])
    # Own messages are excluded even when the envelope filter matches.
    assert notify((root, other_state, config))["matched"] == 0


def test_batch_limit_holds_unlisted_matches_for_next_pass(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    for number in range(52):
        publish_direct(store[0], "m-" + str(number))
    assert notify(store)["held"] == 2
    first = json.loads(notices(store[0])[0]["brief_text"])
    assert len(first["references"]) == 50 and first["held_count"] == 2
    assert notify(store)["matched"] == 2
    packets = [json.loads(row["brief_text"]) for row in notices(store[0])]
    assert len({ref["message_id"] for packet in packets for ref in packet["references"]}) == 52


def test_budget_held_and_released_with_count(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    write_config(store[2], budget=2)
    for number in range(5):
        publish(store[0], "m-" + str(number))
        result = api.notify(*store, now=10000 + number)
    assert len(notices(store[0])) == 2
    assert result["held"] == 3 and result["subscription_suppressed"][0]["reason"] == "budget"
    result = api.notify(*store, now=13601)
    assert result["published"] == 1 and result["matched"] == 3
    packet = json.loads(notices(store[0])[-1]["brief_text"])
    assert packet["previously_held"] == 3


def test_crash_after_publish_recovers_same_notice_even_with_new_mail(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    real_save = api.save_cursor
    def fail(*args, **kwargs):
        raise OSError("injected cursor failure")
    monkeypatch.setattr(api, "save_cursor", fail)
    with pytest.raises(api.SubscriptionError, match="subscription I/O refused"):
        api.notify(*store, now=10000)
    assert len(notices(store[0])) == 1
    publish(store[0], "second")
    monkeypatch.setattr(api, "save_cursor", real_save)
    assert api.notify(*store, now=10001)["recovered"] == 1
    assert len(notices(store[0])) == 1
    assert api.notify(*store, now=10002)["published"] == 1
    assert len(notices(store[0])) == 2


def test_publish_failure_retries_without_advancing_cursor(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    real_publish = api.publish_notice
    def fail(*args, **kwargs):
        raise ValueError("HOSTILE_DIAGNOSTIC")
    monkeypatch.setattr(api, "publish_notice", fail)
    with pytest.raises(api.SubscriptionError, match="subscription mailbox refused"):
        api.notify(*store)
    assert not notices(store[0])
    monkeypatch.setattr(api, "publish_notice", real_publish)
    assert api.notify(*store)["published"] == 1
    assert api.notify(*store)["published"] == 0


def test_loop_guards_and_explicit_ack(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    root = store[0]
    publish(root, "original", sender="a/orchestrator", recipient="a/lane/f2")
    publish(root, "ack", kind="ack", in_reply_to="original", acknowledgment="received")
    publish(root, "notice-forged", body=BODY)
    write_config(store[2], filters=[{}])
    assert notify(store)["matched"] == 0
    write_config(store[2], filters=[{"type": "ack"}])
    assert notify(store)["matched"] == 1


@pytest.mark.parametrize("damage", ["missing", "malformed", "oversized", "symlink", "ancestor_symlink"])
def test_config_refusals_are_fixed_and_leave_mail_unchanged(tmp_path, bound_mailbox, damage):
    store = make_store(tmp_path, bound_mailbox)
    config = store[2]
    if damage == "missing":
        config.unlink()
    elif damage == "malformed":
        config.write_text('{"schema":"HOSTILE_DIAGNOSTIC",', encoding="utf-8")
    elif damage == "oversized":
        config.write_bytes(b" " * 262145)
    else:
        saved = tmp_path / "saved.json"
        config.rename(saved)
        if damage == "symlink":
            symlink_or_skip(saved, config)
        else:
            directory = tmp_path / "alias"
            symlink_or_skip(tmp_path, directory, target_is_directory=True)
            store = (store[0], store[1], directory / saved.name)
    result = notify(store, ok=False)
    assert result["code"] in {"SUBSCRIPTIONS_IO", "SUBSCRIPTIONS_INVALID", "SUBSCRIPTIONS_LIMIT"}
    assert "HOSTILE_DIAGNOSTIC" not in json.dumps(result)
    assert notices(store[0]) == []


def test_unsupported_platform_is_a_fixed_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "supported", lambda: False)
    with pytest.raises(api.SubscriptionError) as error:
        api.notify(tmp_path / "mailbox", tmp_path / "state", tmp_path / "config")
    assert error.value.code == "SUBSCRIPTIONS_UNSUPPORTED"


def test_concurrent_cli_passes_do_not_duplicate_notices(tmp_path, bound_mailbox):
    from concurrent.futures import ThreadPoolExecutor
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    def run(_):
        root, state, config = store
        return subprocess.run([sys.executable, "-B", str(TOOL), "notify", "--root", str(root),
                               "--state-dir", str(state), "--subscriptions", str(config)],
                              capture_output=True, text=True, timeout=20)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(run, range(2)))
    assert all(result.returncode in (0, 2) and not result.stderr for result in results)
    for result in results:
        if result.returncode == 2:
            assert json.loads(result.stdout)["code"] == "SUBSCRIPTIONS_BUSY"
    assert len(notices(store[0])) == 1
    assert notify(store)["published"] == 0


def test_budget_backlog_survives_original_deletion(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    write_config(store[2], budget=1)
    publish(store[0], "first")
    assert api.notify(*store, now=10000)["published"] == 1
    held = publish(store[0], "held")
    assert api.notify(*store, now=10001)["held"] == 1
    Path(held["path"]).unlink()
    assert api.notify(*store, now=13600)["matched"] == 1
    packet = json.loads(notices(store[0])[-1]["brief_text"])
    assert packet["references"][0]["sha256"] == held["sha256"]
    assert packet["previously_held"] == 1


def test_config_size_and_shape_preflight_precedes_json_parser(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    seen = []
    def parse(raw):
        seen.append(True)
        raise AssertionError("parser must not receive structurally oversized JSON")
    monkeypatch.setattr(api, "hm", SimpleNamespace(**{**vars(api.hm), "strict_json": parse}))
    store[2].write_text("[" * 40 + "]" * 40, encoding="utf-8")
    with pytest.raises(api.SubscriptionError):
        api.notify(*store)
    assert seen == []


def test_configuration_sha_is_the_exact_file_hash(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    assert notify(store)["configuration_sha256"] == hashlib.sha256(store[2].read_bytes()).hexdigest()


def test_optional_batch_size_can_lower_the_hard_fifty_limit(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    config = json.loads(store[2].read_text())
    config["subscriptions"][0]["batch_size"] = 2
    store[2].write_text(json.dumps(config), encoding="utf-8")
    for number in range(3):
        publish(store[0], "item-" + str(number))
    assert notify(store)["held"] == 1
    assert len(json.loads(notices(store[0])[0]["brief_text"])["references"]) == 2
    assert notify(store)["matched"] == 1


def test_root_subscription_and_field_only_reply_filter(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    write_config(store[2], subscriber="a/root", filters=[{"type": "info"}])
    publish(store[0], "visible", sender="a/decider")
    publish(store[0], "lane-hidden")
    publish(store[0], "own-hidden", sender="a/root")
    assert notify(store)["matched"] == 1
    packet = json.loads(notices(store[0], "a/root")[0]["brief_text"])
    assert [ref["message_id"] for ref in packet["references"]] == ["visible"]
    write_config(store[2], filters=[{"type": "review"}, {"type": "ack", "in_reply_to_type": "info"}])
    publish(store[0], "original", sender="a/orchestrator", recipient="a/lane/f2")
    publish(store[0], "ack", kind="ack", in_reply_to="original", acknowledgment="received")
    assert notify(store)["matched"] == 1


def test_original_brief_is_a_reference_and_never_expanded(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    brief = store[1] / "source.md"
    brief.write_text("HOSTILE_ORIGINAL_BRIEF", encoding="utf-8")
    ref = {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}
    write_config(store[2], filters=[{"type": "brief", "from": "a/lane/*"}])
    publish(store[0], "incoming-brief", kind="brief", brief=ref)
    assert notify(store)["matched"] == 1
    row = notices(store[0])[0]
    assert json.loads(row["brief_text"])["references"][0]["brief"] == ref
    assert "HOSTILE_ORIGINAL_BRIEF" not in json.dumps(row)


@pytest.mark.parametrize("damage", ["invalid", "oversized", "symlink"])
def test_cursor_refusal_preserves_mail_and_allows_safe_retry(tmp_path, bound_mailbox, damage):
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    assert notify(store)["published"] == 1
    cursor = next(store[1].glob("*.json"))
    raw = cursor.read_bytes()
    if damage == "invalid":
        cursor.write_text('{"schema":"HOSTILE_DIAGNOSTIC"}', encoding="utf-8")
    elif damage == "oversized":
        cursor.write_bytes(b" " * (api.MAX_STATE + 1))
    else:
        cursor.unlink()
        target = tmp_path / "other.json"
        target.write_bytes(raw)
        symlink_or_skip(target, cursor)
    result = notify(store, ok=False)
    assert result["code"] in {"SUBSCRIPTIONS_STATE", "SUBSCRIPTIONS_LIMIT", "SUBSCRIPTIONS_IO"}
    assert "HOSTILE_DIAGNOSTIC" not in json.dumps(result)
    assert len(notices(store[0])) == 1
    cursor.unlink()
    cursor.write_bytes(raw)
    assert notify(store)["published"] == 0


def test_config_ancestor_rename_cannot_redirect_the_open(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    parent = tmp_path / "inputs"
    parent.mkdir()
    config = parent / "subscriptions.json"
    store[2].rename(config)
    original = config.read_bytes()
    saved, outside = tmp_path / "saved", tmp_path / "outside"
    outside.mkdir()
    (outside / config.name).write_text("HOSTILE_DIAGNOSTIC", encoding="utf-8")
    acted = []
    real_os = api.os
    def opened(path, flags, *args, **kwargs):
        if path == config.name and not acted:
            acted.append(True)
            parent.rename(saved)
            symlink_or_skip(outside, parent, target_is_directory=True)
        return real_os.open(path, flags, *args, **kwargs)
    monkeypatch.setattr(api, "os", SimpleNamespace(**{**vars(api.os), "open": opened}))
    result = api.notify(store[0], store[1], config)
    assert acted and result["configuration_sha256"] == hashlib.sha256(original).hexdigest()


@pytest.mark.parametrize("failure", [False, True])
def test_descriptor_reads_close_on_success_and_io_failure(tmp_path, bound_mailbox, monkeypatch, failure):
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    active = set()
    real_os = api.os
    def opened(*args, **kwargs):
        descriptor = real_os.open(*args, **kwargs)
        active.add(descriptor)
        return descriptor
    def closed(descriptor):
        active.remove(descriptor)
        return real_os.close(descriptor)
    def read(descriptor, count):
        if failure:
            raise OSError("injected I/O failure")
        return real_os.read(descriptor, count)
    monkeypatch.setattr(api, "os", SimpleNamespace(**{**vars(api.os), "open": opened, "close": closed, "read": read}))
    if failure:
        with pytest.raises(api.SubscriptionError) as error:
            api.notify(*store)
        assert error.value.code == "SUBSCRIPTIONS_IO"
    else:
        assert api.notify(*store)["published"] == 1
    assert active == set()


def test_oversized_packet_refuses_before_pending_and_can_retry_smaller_batch(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    directory = tmp_path
    for _ in range(12):
        directory = directory / ("\u0100" * 80)
        directory.mkdir()
    brief = directory / "source.md"
    brief.write_text("fixture", encoding="utf-8")
    ref = {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}
    write_config(store[2], filters=[{"type": "brief", "from": "a/lane/*"}])
    for number in range(50):
        publish_direct(store[0], "brief-" + str(number), kind="brief", brief=ref)
    assert notify(store, ok=False)["code"] == "SUBSCRIPTIONS_LIMIT"
    assert list(store[1].glob("*.json")) == []
    assert notices(store[0]) == []
    configuration = json.loads(store[2].read_text())
    configuration["subscriptions"][0]["batch_size"] = 20
    store[2].write_text(json.dumps(configuration), encoding="utf-8")
    result = notify(store)
    assert result["published"] == 1 and result["matched"] == 20 and result["held"] == 30


def notify_arguments(store):
    root, state, config = store
    return ["notify", "--root", str(root), "--state-dir", str(state), "--subscriptions", str(config)]


def test_routing_flush_failure_preserves_pending_on_publish_and_reconcile(tmp_path, bound_mailbox, monkeypatch, capsys):
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    route = (store[0] / "a" / "orchestrator").stat()
    real_os = api.os
    flushed = []
    def fsync(descriptor):
        info = real_os.fstat(descriptor)
        if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (route.st_dev, route.st_ino):
            flushed.append(True)
            raise OSError("HOSTILE_FLUSH_DIAGNOSTIC")
        return real_os.fsync(descriptor)
    monkeypatch.setattr(api, "os", SimpleNamespace(**{**vars(api.os), "fsync": fsync}))
    pending = None
    for _ in range(2):
        assert api.main(notify_arguments(store)) == 2
        output = capsys.readouterr()
        assert not output.err
        assert json.loads(output.out) == {"code": "SUBSCRIPTIONS_DURABILITY",
                                          "error": "subscription notice durability flush failed"}
        cursor_path = next(store[1].glob("*.json"))
        raw = cursor_path.read_bytes()
        cursor = json.loads(raw)
        assert cursor["pending"] is not None and cursor["seen"] == [] and cursor["sent"] == []
        if pending is not None:
            assert raw == pending
        pending = raw
        assert len(notices(store[0])) == 1
    assert len(flushed) == 2
    monkeypatch.setattr(api, "os", real_os)
    assert api.notify(*store)["recovered"] == 1
    assert len(notices(store[0])) == 1
    assert api.notify(*store)["published"] == 0


@pytest.mark.parametrize("placement", ["routing", "binding_history", "root", "parent"])
def test_state_directory_overlap_refuses_before_any_write(tmp_path, bound_mailbox, placement):
    root, state, config = make_store(tmp_path, bound_mailbox)
    invalid = {"routing": root / "a" / "orchestrator",
               "binding_history": root / "bindings" / "a" / "orchestrator",
               "root": root, "parent": root.parent}[placement]
    before = mailbox_snapshot(root)
    result = notify((root, invalid, config), ok=False)
    assert result == {"code": "SUBSCRIPTIONS_PATH", "error": "invalid subscription path"}
    assert mailbox_snapshot(root) == before
    assert not (invalid / ".subscriptions.lock").exists()
    assert invoke(root, "inbox", endpoint="a/orchestrator")["messages"] == []
    publish(root, "still-readable")
    assert notify((root, state, config))["published"] == 1


KILL_BEFORE_CURSOR_SAVE = r"""
import os, signal, sys
from tools import hierarchy_subscriptions as api
def killed(*args, **kwargs):
    os.kill(os.getpid(), signal.SIGKILL)
api.save_cursor = killed
sys.exit(api.main(sys.argv[1:]))
"""


def test_sigkill_requires_operator_lock_recovery_then_reconciles_once(tmp_path, bound_mailbox):
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    child = subprocess.run([sys.executable, "-B", "-c", KILL_BEFORE_CURSOR_SAVE, *notify_arguments(store)],
                           cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert child.returncode == -signal.SIGKILL and not child.stdout and not child.stderr
    lock = store[0] / ".write.lock"
    lock_bytes = lock.read_bytes()
    cursor = next(store[1].glob("*.json"))
    pending_bytes = cursor.read_bytes()
    assert json.loads(pending_bytes)["pending"] is not None
    assert len(notices(store[0])) == 1
    for _ in range(2):
        result = notify(store, ok=False)
        shown_path = result.pop("lock_path")
        assert isinstance(shown_path, str) and shown_path.endswith("/mailbox/.write.lock")
        assert result == {"code": "SUBSCRIPTIONS_MAILBOX_LOCKED", "error": "mailbox write lock requires operator inspection",
                          "hold": True,
                          "recovery": "Confirm no live mailbox writer, then manually remove only this root's .write.lock and retry notify."}
        assert lock.read_bytes() == lock_bytes and cursor.read_bytes() == pending_bytes
    # The killed subprocess has been reaped, so this fixture's only writer is confirmed gone.
    lock.unlink()
    assert notify(store)["recovered"] == 1
    assert len(notices(store[0])) == 1
    assert notify(store)["published"] == 0
    assert not lock.exists()


def test_live_mailbox_lock_hold_redacts_path_and_preserves_lock(tmp_path, bound_mailbox):
    secret = "ghp_" + "a" * 24
    directory = tmp_path / secret
    directory.mkdir()
    store = make_store(directory, bound_mailbox)
    lock = store[0] / ".write.lock"
    with api.hm.writer_lock(store[0]):
        original = lock.read_bytes()
        result = notify(store, ok=False)
        assert result["code"] == "SUBSCRIPTIONS_MAILBOX_LOCKED" and result["hold"] is True
        assert result["error"] == "mailbox write lock requires operator inspection"
        assert secret not in json.dumps(result) and "REDACTED" in result["lock_path"]
        assert lock.read_bytes() == original
    assert not lock.exists()


def test_concurrent_pass_during_failed_notice_flush_does_not_advance_cursor(tmp_path, bound_mailbox, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    store = make_store(tmp_path, bound_mailbox)
    publish(store[0], "first")
    route = (store[0] / "a" / "orchestrator").stat()
    entered, release = Event(), Event()
    real_os = api.os
    def fsync(descriptor):
        info = real_os.fstat(descriptor)
        if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (route.st_dev, route.st_ino):
            entered.set()
            assert release.wait(10), "flush barrier was not released"
            raise OSError("injected routing flush failure")
        return real_os.fsync(descriptor)
    monkeypatch.setattr(api, "os", SimpleNamespace(**{**vars(api.os), "fsync": fsync}))
    with ThreadPoolExecutor(max_workers=1) as worker:
        first = worker.submit(api.notify, *store)
        try:
            assert entered.wait(10), "notification did not reach routing flush"
            assert notify(store, ok=False) == {"code": "SUBSCRIPTIONS_BUSY", "error": "subscription writer busy"}
            cursor = json.loads(next(store[1].glob("*.json")).read_bytes())
            assert cursor["seen"] == [] and cursor["pending"] is not None
        finally:
            release.set()
        with pytest.raises(api.SubscriptionError, match="subscription notice durability flush failed"):
            first.result(timeout=10)
    monkeypatch.setattr(api, "os", real_os)
    assert api.notify(*store)["recovered"] == 1
    assert len(notices(store[0])) == 1
    assert api.notify(*store)["published"] == 0


def _tree_bytes(root):
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_seen_record_is_hashed_before_verification_and_not_walked_again(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    published = {}
    for name in ("m0", "m1", "m2"):
        published[name] = publish_direct(store[0], name)
    referenced, verified = [], []
    real_build, real_verify = api._reference_from_verified, api._verify_record

    def build(record, digest):
        referenced.append(record["message"]["message_id"])
        return real_build(record, digest)

    def verify(raw, record):
        verified.append(record["message"]["message_id"])
        return real_verify(raw, record)

    monkeypatch.setattr(api, "_reference_from_verified", build)
    monkeypatch.setattr(api, "_verify_record", verify)
    assert api.notify(*store)["published"] == 1
    assert set(referenced) == {"m0", "m1", "m2"}
    assert {"m0", "m1", "m2"} <= set(verified)
    referenced.clear()
    verified.clear()
    publish_direct(store[0], "fresh")
    assert api.notify(*store)["published"] == 1
    assert referenced == ["fresh"]
    # A matching re-read is verified once and then not walked. The seen set skips only the build.
    assert {"m0", "m1", "m2", "fresh"} <= set(verified)
    assert verified.count("m0") == 1 and verified.count("m1") == 1 and verified.count("m2") == 1
    assert verified.count("fresh") == 1
    replaced = publish_direct(store[0], "replaced")
    replaced_path = Path(replaced["path"])
    fresh_bytes = replaced_path.read_bytes()
    old_bytes = Path(published["m0"]["path"]).read_bytes()
    old_digest = hashlib.sha256(old_bytes).hexdigest()
    assert old_digest != replaced["sha256"]
    cursor_path = next(store[1].glob("*.json"))
    cursor = json.loads(cursor_path.read_bytes())
    assert old_digest in cursor["seen"] and replaced["sha256"] not in cursor["seen"]
    state_before = _tree_bytes(store[1])
    mailbox_before = _tree_bytes(store[0])
    notice_before = len(notices(store[0]))
    referenced.clear()
    verified.clear()
    real_messages = api.hm.Mailbox.messages

    def messages(self):
        # messages() has already built the new envelope; the file is then the seen bytes.
        records = real_messages(self)
        replaced_path.write_bytes(old_bytes)
        return records

    monkeypatch.setattr(api.hm.Mailbox, "messages", messages)
    with pytest.raises(api.SubscriptionError) as caught:
        api.notify(*store)
    assert caught.value.code == "SUBSCRIPTIONS_MAILBOX"
    assert str(caught.value) == "subscription mailbox refused"
    assert "replaced" in verified and "replaced" not in referenced
    assert verified.count("replaced") == 1
    assert _tree_bytes(store[1]) == state_before
    relative = replaced_path.relative_to(store[0])
    attacked = _tree_bytes(store[0])
    assert attacked[relative] == old_bytes
    attacked.pop(relative)
    expected_mailbox = dict(mailbox_before)
    expected_mailbox.pop(relative)
    assert attacked == expected_mailbox
    monkeypatch.setattr(api.hm.Mailbox, "messages", real_messages)
    replaced_path.write_bytes(fresh_bytes)
    assert len(notices(store[0])) == notice_before
    verified.clear()
    referenced.clear()
    assert api.notify(*store)["published"] == 1
    assert verified.count("replaced") == 1 and referenced == ["replaced"]
    assert len(notices(store[0])) == notice_before + 1
    assert api.notify(*store)["published"] == 0


def test_unseen_verification_failure_leaves_storage_untouched_and_retries(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    publish_direct(store[0], "m-ok")
    publish_direct(store[0], "m-bad")
    before = _tree_bytes(store[0])
    active, record_open = set(), set()
    real_os, real_verify = api.os, api._verify_record

    def opened(path, *args, **kwargs):
        descriptor = real_os.open(path, *args, **kwargs)
        active.add(descriptor)
        if isinstance(path, str) and "m-bad" in path:
            record_open.add(descriptor)
        return descriptor

    def closed(descriptor):
        active.discard(descriptor)
        record_open.discard(descriptor)
        return real_os.close(descriptor)

    def verify(raw, record):
        if record["message"]["message_id"] == "m-bad":
            assert record_open == set()
            raise api.SubscriptionError("MAILBOX")
        return real_verify(raw, record)

    monkeypatch.setattr(api, "os", SimpleNamespace(**{**vars(api.os), "open": opened, "close": closed}))
    monkeypatch.setattr(api, "_verify_record", verify)
    with pytest.raises(api.SubscriptionError) as caught:
        api.notify(*store)
    assert caught.value.code == "SUBSCRIPTIONS_MAILBOX"
    assert str(caught.value) == "subscription mailbox refused"
    assert active == set()
    assert list(store[1].glob("*.json")) == []
    assert notices(store[0]) == []
    assert _tree_bytes(store[0]) == before
    monkeypatch.setattr(api, "_verify_record", real_verify)
    monkeypatch.setattr(api, "os", real_os)
    assert api.notify(*store)["published"] == 1
    assert len(notices(store[0])) == 1
    assert api.notify(*store)["published"] == 0


def test_seen_hash_read_survives_directory_rename_and_closes_descriptors(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    published = publish_direct(store[0], "kept")
    record_path = Path(published["path"])
    assert api.notify(*store)["published"] == 1
    assert len(notices(store[0])) == 1
    acted, active = [], set()
    real_os = api.os
    parent = record_path.parent
    saved = parent.with_name(parent.name + "-saved")
    hostile = tmp_path / "hostile-record"

    def opened(path, flags, *args, **kwargs):
        if path == record_path.name and not acted:
            acted.append(True)
            parent.rename(saved)
            hostile.mkdir()
            (hostile / record_path.name).write_bytes(b"HOSTILE")
            symlink_or_skip(hostile, parent, target_is_directory=True)
        descriptor = real_os.open(path, flags, *args, **kwargs)
        active.add(descriptor)
        return descriptor

    def closed(descriptor):
        active.discard(descriptor)
        return real_os.close(descriptor)

    monkeypatch.setattr(api, "os", SimpleNamespace(**{**vars(api.os), "open": opened, "close": closed}))
    assert api.notify(*store)["published"] == 0
    assert acted and active == set()
    assert len(list(saved.glob("*notice-*"))) == 1
    assert list(hostile.glob("*notice-*")) == []
    cursor = json.loads(next(store[1].glob("*.json")).read_bytes())
    assert published["sha256"] in cursor["seen"]
    assert b"HOSTILE" not in next(store[1].glob("*.json")).read_bytes()


def test_repeat_pass_concurrent_callers_skip_seen_records(tmp_path, bound_mailbox, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    store = make_store(tmp_path, bound_mailbox)
    publish_direct(store[0], "seen-one")
    assert api.notify(*store)["published"] == 1
    verified, referenced = [], []
    entered, release = Event(), Event()
    real_verify, real_bytes, real_build = api._verify_record, api._record_bytes, api._reference_from_verified

    def verify(raw, record):
        verified.append(record["message"]["message_id"])
        return real_verify(raw, record)

    def record_bytes(mailbox, record):
        raw = real_bytes(mailbox, record)
        if record["message"]["message_id"] == "seen-one" and not entered.is_set():
            entered.set()
            assert release.wait(10), "seen-record barrier was not released"
        return raw

    def build(record, digest):
        referenced.append(record["message"]["message_id"])
        return real_build(record, digest)

    monkeypatch.setattr(api, "_verify_record", verify)
    monkeypatch.setattr(api, "_record_bytes", record_bytes)
    monkeypatch.setattr(api, "_reference_from_verified", build)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(api.notify, *store)
        try:
            assert entered.wait(10), "repeat pass did not reach the seen record"
            with pytest.raises(api.SubscriptionError) as caught:
                api.notify(*store)
            assert caught.value.code == "SUBSCRIPTIONS_BUSY"
            # The in-flight read has not verified yet, and the busy caller must not either.
            assert "seen-one" not in verified and referenced == []
        finally:
            release.set()
        assert first.result(timeout=10)["published"] == 0
    assert verified == ["seen-one"] and referenced == []
    assert len(notices(store[0])) == 1
    assert api.notify(*store)["published"] == 0


def _verify_counts(monkeypatch):
    verified = []
    real_verify = api._verify_record

    def verify(raw, record):
        verified.append(record["message"]["message_id"])
        return real_verify(raw, record)

    monkeypatch.setattr(api, "_verify_record", verify)
    return verified


def test_each_matching_record_is_verified_once_including_budget_hold(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    write_config(store[2], budget=1)
    verified = _verify_counts(monkeypatch)
    publish_direct(store[0], "fresh-a")
    publish_direct(store[0], "fresh-b")
    assert api.notify(*store, now=10000)["published"] == 1
    assert verified.count("fresh-a") == 1 and verified.count("fresh-b") == 1
    verified.clear()
    publish_direct(store[0], "held-c")
    held = api.notify(*store, now=10001)
    assert held["published"] == 0 and held["subscription_suppressed"][0]["reason"] == "budget"
    assert verified.count("held-c") == 1
    assert verified.count("fresh-a") == 1 and verified.count("fresh-b") == 1
    verified.clear()
    again = api.notify(*store, now=10002)
    assert again["published"] == 0 and again["subscription_suppressed"][0]["reason"] == "budget"
    assert verified.count("held-c") == 1 and verified.count("fresh-a") == 1
    state_before = _tree_bytes(store[1])
    notice_before = len(notices(store[0]))
    verified.clear()
    released = api.notify(*store, now=13601)
    assert released["published"] == 1 and released["subscription_suppressed"] == []
    assert verified.count("held-c") == 1 and verified.count("fresh-a") == 1
    assert len(notices(store[0])) == notice_before + 1
    assert _tree_bytes(store[1]) != state_before


def test_reference_without_a_prior_verify_still_verifies(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    published = publish_direct(store[0], "direct")
    mailbox = api.hm.Mailbox(store[0])
    record = next(item for item in mailbox.messages().values()
                  if item["message"]["message_id"] == "direct")
    raw = Path(published["path"]).read_bytes()
    verified = _verify_counts(monkeypatch)
    built = api._reference(mailbox, record, raw)
    assert verified == ["direct"]
    assert built["message_id"] == "direct" and built["sha256"] == hashlib.sha256(raw).hexdigest()


def test_budget_held_verify_is_once_when_a_second_pass_is_busy(tmp_path, bound_mailbox, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    store = make_store(tmp_path, bound_mailbox)
    write_config(store[2], budget=1)
    publish_direct(store[0], "fresh-a")
    assert api.notify(*store, now=10000)["published"] == 1
    publish_direct(store[0], "held-c")
    verified = []
    entered, release = Event(), Event()
    real_verify = api._verify_record

    def verify(raw, record):
        if record["message"]["message_id"] == "held-c" and not entered.is_set():
            entered.set()
            assert release.wait(10), "budget-held barrier was not released"
        verified.append(record["message"]["message_id"])
        return real_verify(raw, record)

    monkeypatch.setattr(api, "_verify_record", verify)
    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(api.notify, *store, now=10001)
        try:
            assert entered.wait(10), "budget-held pass did not reach verification"
            with pytest.raises(api.SubscriptionError) as caught:
                api.notify(*store, now=10001)
            assert caught.value.code == "SUBSCRIPTIONS_BUSY"
            assert verified.count("held-c") == 0
        finally:
            release.set()
        result = first.result(timeout=10)
    assert result["published"] == 0 and result["subscription_suppressed"][0]["reason"] == "budget"
    assert verified.count("held-c") == 1
    assert api.notify(*store, now=13601)["published"] == 1


def test_notify_reuses_a_matching_mailbox_and_refuses_a_different_root(tmp_path, bound_mailbox, monkeypatch):
    store = make_store(tmp_path, bound_mailbox)
    publish_direct(store[0], "once")
    mailbox = api.hm.Mailbox(store[0])
    calls = []
    real = api.hm.Mailbox

    def counting(root):
        calls.append(str(root))
        return real(root)

    monkeypatch.setattr(api.hm, "Mailbox", counting)
    assert api.notify(*store, mailbox=mailbox)["published"] == 1
    assert calls == []
    before = next(store[1].glob("*.json")).read_bytes()
    notice_count = len(notices(store[0]))
    with pytest.raises(api.SubscriptionError) as caught:
        api.notify(*store, mailbox=SimpleNamespace(root=store[1]))
    assert caught.value.code == "SUBSCRIPTIONS_MAILBOX"
    assert calls == []
    assert next(store[1].glob("*.json")).read_bytes() == before
    assert len(notices(store[0])) == notice_count
