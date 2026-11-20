"""Mailbox adapter public entry point, legacy parity and refusal atomicity."""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import io
import hashlib
import json
import os
from types import SimpleNamespace
from threading import Event

import pytest

from conftest import symlink_or_skip
from aegis_cli.cli import main
from aegis_cli import team_mail
from aegis_core import team_mailbox_store as storage
from aegis_core import team_profile
from aegis_core.model_select import MAX_INPUT_BYTES
from aegis_core.team_mailbox_primitives import MAX_BYTES, OWNER_EVIDENCE_LOCK
from tools import hierarchy_mailbox as legacy


NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)
MANIFEST = {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 2,
            "endpoints": {"a/front-door": {}, "a/orchestrator": {}, "a/root": {}}, "counterparts": []}
# The adapter renames the legacy publish/inbox operations; validation stays core-owned.
PARITY = {"send": "publish", "read": "inbox", "doctor": "inspect_mailbox"}


@pytest.fixture
def mailbox(tmp_path, monkeypatch):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / "mailbox"
    legacy.initialize(root, MANIFEST)
    box = legacy.Mailbox(root)
    for endpoint in MANIFEST["endpoints"]:
        box.bind({"endpoint": endpoint, "host": "primary", "session": endpoint, "expected_generation": 0})
    monkeypatch.setattr(team_profile, "load", lambda root: team_profile.resolve(preset="solo"))
    owner = tmp_path / "owner"
    (owner / ".aegis").mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(storage, "pwd", SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_dir=str(owner))))
    return root


def request(**changes):
    return {"message_id": "one", "from": "a/front-door", "to": "a/orchestrator", "host": "primary",
            "session": "a/front-door", "binding_generation": 1, "type": "info", "body": "hello", **changes}


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def invoke(root, capsys, verb, *options):
    result = main(["--workspace", str(root.parent), "team", "mail", verb, "--root", str(root), "--json", *options])
    captured = capsys.readouterr()
    assert captured.err == ""
    return result, json.loads(captured.out)


def test_send_read_and_legacy_success_parity(mailbox, capsys, monkeypatch):
    monkeypatch.setattr(team_mail, "now_utc", lambda: NOW)
    path = mailbox.parent / "request.json"
    path.write_text(json.dumps(request()), encoding="utf-8")
    code, sent = invoke(mailbox, capsys, "send", "--request", str(path))
    assert code == 0 and sent["message"]["body"] == "hello"
    before = snapshot(mailbox)
    code, page = invoke(mailbox, capsys, "read", "--endpoint", "a/orchestrator")
    assert code == 0 and page == legacy.Mailbox(mailbox).inbox("a/orchestrator", limit=20)
    assert snapshot(mailbox) == before
    code, refused = invoke(mailbox, capsys, "send", "--request", str(path))
    assert code == 1 and refused["reason"] == "invalid_record" and refused["next_action"]
    assert snapshot(mailbox) == before


@pytest.mark.parametrize("raw,reason", [(b"{", "invalid_record"), (b"x" * 262145, "too_large"),
                                         (b'{}', "invalid_record"), (b'"\\ud800"', "invalid_record")],
                         ids=["malformed", "oversized", "shape", "surrogate"])
def test_bad_request_refuses_without_writes_then_retry(mailbox, capsys, raw, reason):
    path = mailbox.parent / "request.json"
    path.write_bytes(raw)
    before = snapshot(mailbox)
    code, result = invoke(mailbox, capsys, "send", "--request", str(path))
    assert code == 1 and result["reason"] == reason and result["status"] == "refused"
    assert result["next_action"] and snapshot(mailbox) == before
    path.write_text(json.dumps(request()), encoding="utf-8")
    assert invoke(mailbox, capsys, "send", "--request", str(path))[0] == 0


def test_missing_and_symlink_requests_are_fixed_refusals(mailbox, tmp_path, capsys):
    path = tmp_path / "request.json"
    code, result = invoke(mailbox, capsys, "send", "--request", str(path))
    assert code == 1 and result["reason"] == "missing"
    target = tmp_path / "target.json"
    target.write_text(json.dumps(request()), encoding="utf-8")
    symlink_or_skip(target, path)
    code, result = invoke(mailbox, capsys, "send", "--request", str(path))
    assert code == 1 and result["reason"] == "unsafe_path"


def test_busy_lock_is_one_refusal_then_retry(mailbox, capsys):
    path = mailbox.parent / "request.json"
    path.write_text(json.dumps(request()), encoding="utf-8")
    with storage.Store(mailbox) as peer, peer.lock(mailbox):
        before = snapshot(mailbox)
        code, result = invoke(mailbox, capsys, "send", "--request", str(path))
        assert code == 1 and result["reason"] == "busy" and result["next_action"]
        assert snapshot(mailbox) == before
    assert invoke(mailbox, capsys, "send", "--request", str(path))[0] == 0


@pytest.mark.parametrize("verb,reason", [("read", "unsupported_platform"), ("doctor", "MD_PLATFORM")])
def test_unsupported_platform_is_testable_without_posix(tmp_path, capsys, monkeypatch, verb, reason):
    monkeypatch.setattr(storage, "descriptor_supported", lambda: False)
    monkeypatch.setattr(team_profile, "load", lambda root: team_profile.resolve(preset="solo"))
    flags = ["--endpoint", "a/orchestrator"] if verb == "read" else []
    code, result = invoke(tmp_path / "mailbox", capsys, verb, *flags)
    assert code == 1 and result["reason"] == reason


@pytest.mark.parametrize("verb,options", [("send", []), ("read", ["--endpoint", "x", "--limit", "SECRET"]),
                                         ("read", ["--unknown", "SECRET"]), ("SECRET", [])])
def test_usage_does_not_echo_input(tmp_path, capsys, verb, options):
    with pytest.raises(SystemExit) as caught:
        invoke(tmp_path / "mailbox", capsys, verb, *options)
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert "SECRET" not in captured.out + captured.err
    result = json.loads(captured.out)
    assert result["reason"] == "invalid_arguments" and result["next_action"]


def assert_mail_board_usage(captured):
    assert captured.err == ""
    assert len(captured.out.splitlines()) == 1
    assert json.loads(captured.out) == {
        "status": "refused", "reason": "invalid_arguments", "exit_code": 2,
        "next_action": "Use aegis team mail or board --help and supply the required options.",
    }


@pytest.mark.parametrize("verb", ["send", "read", "doctor"])
@pytest.mark.parametrize("where", ["root", "team", "command", "verb", "option-value", "separator",
                                   "with-msg", "with-model", "with-queue", "with-all"])
def test_mail_invocation_usage_at_each_parser_level(capsys, verb, where):
    argv = ["team", "mail", verb, "--root", "/unused"]
    if verb == "send":
        argv += ["--request", "-"]
    elif verb == "read":
        argv += ["--endpoint", "a/orchestrator"]
    if where == "option-value":
        argv = ["--workspace", "team", "PRIVATE_SENTINEL", "--workspace", "mail", *argv[2:]]
    elif where == "separator":
        argv[:0] = ["--", "--unknown=PRIVATE_SENTINEL"]
    elif where == "root":
        argv.insert(0, "--json=PRIVATE_SENTINEL")
    elif where.startswith("with-"):
        argv.append("--unknown=PRIVATE_SENTINEL")
        for value in (("msg", "model", "queue") if where == "with-all" else (where[5:],)):
            argv += ["--workspace", value]
    else:
        argv.insert({"team": 1, "command": 2, "verb": 3}[where], "--unknown=PRIVATE_SENTINEL")
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    assert_mail_board_usage(capsys.readouterr())


@pytest.mark.parametrize("scope", ["mail", "board"])
@pytest.mark.parametrize("overlap", ["msg", "model", "queue", "all", "model-action", "queue-action", "removed"])
def test_mail_board_invocation_usage_owns_overlapping_parse_failures(capsys, scope, overlap):
    if overlap == "model-action":
        argv = ["team", "model", "--subject", scope, "--host-kind", "x" * 129]
    elif overlap == "queue-action":
        argv = ["team", "queue", "list", "--capability", scope, "--view", "PRIVATE_SENTINEL"]
    elif overlap == "removed":
        argv = ["audit", "--workspace", "team", "--workspace", scope]
    else:
        argv = ["--json=PRIVATE_SENTINEL", "team", scope]
        argv.extend(["msg", "queue", "model"] if overlap == "all" else [overlap])
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    assert_mail_board_usage(capsys.readouterr())


@pytest.mark.parametrize("scope", ["mail", "board"])
def test_successful_retry_keeps_model_and_queue_policy_composition(capsys, scope):
    argv = ["team", "claim", "model", "--paths", scope, "--owner", "queue"]
    with pytest.raises(SystemExit) as caught:
        main(["--json=PRIVATE_SENTINEL", *argv])
    assert caught.value.code == 2
    assert_mail_board_usage(capsys.readouterr())

    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"error": "invalid_model_arguments"}


@pytest.mark.parametrize("scope", ["mail", "board"])
def test_successful_parse_with_scope_as_option_value_dispatches(capsys, tmp_path, scope):
    (tmp_path / ".aegis" / "rules").mkdir(parents=True)
    argv = ["team", "--workspace", scope, "config", "presets", "--workspace", str(tmp_path), "--json"]
    with pytest.raises(SystemExit) as caught:
        main([*argv, "--unknown=PRIVATE_SENTINEL"])
    assert caught.value.code == 2
    assert_mail_board_usage(capsys.readouterr())

    assert main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["schema"] == "aegis.team.config.presets/v1"


@pytest.mark.parametrize("scope", ["mail", "board"])
@pytest.mark.parametrize("unknown", [False, True])
def test_hook_syntax_failure_uses_mail_board_refusal(capsys, scope, unknown):
    argv = ["hook", "run", "team", scope]
    if unknown:
        argv.append("--unknown=PRIVATE_SENTINEL")
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    assert_mail_board_usage(capsys.readouterr())
    assert main(["hook", "run", "team", "other", *argv[4:]]) == 0
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("scope", ["mail", "board"])
@pytest.mark.parametrize("failure", ["queue-workspace", "model-workspace", "model-size"])
def test_delegated_validation_uses_mail_board_refusal(capsys, scope, failure):
    if failure == "queue-workspace":
        argv = ["--workspace=../PRIVATE_SENTINEL", "team", "queue", "list", "--capability", scope]
    else:
        argv = ["team", "model", "--subject", scope, "--host-kind", "codex-cli", "--task-kind", "T1",
                "--role-kind", "orchestrator", "--bindings", "bindings.json", "--policy", "policy.json",
                "--history", "history.jsonl"]
        if failure == "model-workspace":
            argv += ["--workspace", "/" * 257]
        else:
            argv += ["--intent", "x" * (MAX_INPUT_BYTES + 1)]
    with pytest.raises(SystemExit) as caught:
        main(argv)
    assert caught.value.code == 2
    assert_mail_board_usage(capsys.readouterr())


@pytest.mark.parametrize("scope", ["model", "mail-model", "queue"])
def test_mixed_cli_policies_leave_concurrent_streams_available(capsys, scope):
    entered, resume = Event(), Event()

    class PausedOption(str):
        def __getitem__(self, index):
            if index == 0:
                entered.set()
                assert resume.wait(10)
            return super().__getitem__(index)

    def refuse(argv):
        try:
            return main(argv)
        except SystemExit as error:
            return error.code

    names = {"model": ["model"], "mail-model": ["mail", "model"], "queue": ["queue", "list"]}
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(refuse, [PausedOption("--json=PRIVATE_SENTINEL"), "team", *names[scope]])
        try:
            assert entered.wait(10)
            assert refuse(["--json=PRIVATE_SENTINEL", "team", "board"]) == 2
            assert_mail_board_usage(capsys.readouterr())
            assert refuse(["--json=ORDINARY_SENTINEL", "team", "list"]) == 2
            captured = capsys.readouterr()
            assert captured.out == "" and "ORDINARY_SENTINEL" in captured.err
        finally:
            resume.set()
        assert pending.result(timeout=10) == 2

    captured = capsys.readouterr()
    if scope == "mail-model":
        assert_mail_board_usage(captured)
    elif scope == "model":
        assert captured.err == "" and json.loads(captured.out) == {"error": "invalid_model_arguments"}
    else:
        assert captured.err == "" and json.loads(captured.out)["schema"] == "aegis.team.queue.usage/v1"


def test_mail_board_invocation_policy_is_local_to_each_parse(capsys):
    def parse(scope):
        with pytest.raises(SystemExit) as caught:
            main(["--json=PRIVATE_SENTINEL", "team", scope])
        return caught.value.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(parse, ("mail", "board"), timeout=10))
    assert codes == [2, 2]
    captured = capsys.readouterr()
    assert captured.err == ""
    first, second = captured.out.splitlines()
    assert first == second
    assert json.loads(first)["reason"] == "invalid_arguments"

    with pytest.raises(SystemExit) as caught:
        main(["--json=ORDINARY_SENTINEL", "team", "list"])
    assert caught.value.code == 2
    assert "ORDINARY_SENTINEL" in capsys.readouterr().err


def test_profile_timeout_is_fixed_and_has_no_effect(mailbox, capsys, monkeypatch):
    def timeout(root):
        raise TimeoutError("SECRET")

    monkeypatch.setattr(team_profile, "load", timeout)
    before = snapshot(mailbox)
    code, result = invoke(mailbox, capsys, "read", "--endpoint", "a/orchestrator")
    assert code == 1 and result["reason"] == "host_unavailable"
    assert "SECRET" not in json.dumps(result) and snapshot(mailbox) == before


def test_mailbox_doctor_is_separate_from_profile_doctor(mailbox, capsys):
    code, result = invoke(mailbox, capsys, "doctor")
    assert code == 0 and result["schema"] == "aegis.hierarchy-mailbox-doctor/v1" and result["healthy"]


def test_unhealthy_doctor_has_fixed_recovery_advice(mailbox, capsys):
    (mailbox / "a/orchestrator/bad.md").write_bytes(b"broken")
    before = snapshot(mailbox)
    code, result = invoke(mailbox, capsys, "doctor")
    assert code == 1 and result["status"] == "refused" and result["reason"] == "mailbox_unhealthy"
    assert result["next_action"] and result["issues"] and snapshot(mailbox) == before


def test_stdin_send_redacts_every_output_field(mailbox, capsys, monkeypatch):
    raw = json.dumps(request(body="ｔｏｋｅｎ＝PRIVATE\x1b[0m")).encode("utf-8")
    monkeypatch.setattr(team_mail, "sys", SimpleNamespace(stdin=SimpleNamespace(buffer=io.BytesIO(raw))))
    code, result = invoke(mailbox, capsys, "send", "--request", "-")
    assert code == 0 and "PRIVATE" not in json.dumps(result)
    assert result["message"]["body"] != "ｔｏｋｅｎ＝PRIVATE\x1b[0m"


def test_concurrent_writer_busy_and_retry(mailbox, capsys):
    entered, release = Event(), Event()

    def hold():
        with storage.Store(mailbox) as store, store.lock(mailbox):
            entered.set()
            assert release.wait(5)

    path = mailbox.parent / "request.json"
    path.write_text(json.dumps(request()), encoding="utf-8")
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(hold)
        try:
            assert entered.wait(5)
            before = snapshot(mailbox)
            code, result = invoke(mailbox, capsys, "send", "--request", str(path))
            assert code == 1 and result["reason"] == "busy" and snapshot(mailbox) == before
        finally:
            release.set()
        future.result(timeout=5)
    assert invoke(mailbox, capsys, "send", "--request", str(path))[0] == 0


def test_request_outside_mailbox_parent_retains_legacy_support(mailbox, tmp_path_factory, capsys):
    folder = tmp_path_factory.mktemp("outside-request")
    path = folder / "request.json"
    path.write_text(json.dumps(request()), encoding="utf-8")
    assert invoke(mailbox, capsys, "send", "--request", str(path))[0] == 0


def test_mark_read_uses_the_callers_binding_after_output(mailbox, capsys):
    path = mailbox.parent / "request.json"
    path.write_text(json.dumps(request(**{"from": "a/orchestrator", "to": "a/root", "session": "a/orchestrator"})))
    assert invoke(mailbox, capsys, "send", "--request", str(path))[0] == 0
    delivery = mailbox.parent / "delivery"
    delivery.mkdir()
    flags = ["--endpoint", "a/root", "--mark-read", "--delivery-dir", str(delivery),
             "--host", "primary", "--session", "a/root", "--generation", "1"]
    code, page = invoke(mailbox, capsys, "read", *flags)
    assert code == 0 and page["messages"][0]["message"]["message_id"] == "one"
    report = legacy.Mailbox(mailbox).delivery(delivery, endpoint="a/root")
    assert report["endpoints"]["a/root"]["read"] == 1
    before = snapshot(delivery)
    assert invoke(mailbox, capsys, "read", *flags)[0] == 0
    assert snapshot(delivery) == before


def test_root_before_verb_keeps_legacy_option_position(mailbox, capsys):
    assert main(["--workspace", str(mailbox.parent), "team", "mail", "--root", str(mailbox),
                 "read", "--endpoint", "a/orchestrator", "--json"]) == 0
    output = capsys.readouterr()
    assert output.err == "" and json.loads(output.out)["endpoint"] == "a/orchestrator"


def test_rotation_during_stdout_flush_refuses_retired_read_receipt(mailbox, capsys, monkeypatch):
    legacy.Mailbox(mailbox).publish(request(**{"from": "a/orchestrator", "to": "a/root", "session": "a/orchestrator"}))
    delivery = mailbox.parent / "delivery"
    delivery.mkdir()
    brief = mailbox.parent / "brief.md"
    brief.write_bytes(b"replacement checkpoint\n")
    checkpoint = {"outgoing_stopped": True, "briefs": [{"path": str(brief),
        "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}], "sources": [], "lease_refs": [],
        "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}

    def rotate():
        legacy.Mailbox(mailbox).bind({"endpoint": "a/root", "host": "primary", "session": "replacement",
                                     "expected_generation": 1, "checkpoint": checkpoint})

    errors = io.StringIO()
    monkeypatch.setattr(team_mail, "sys", SimpleNamespace(stdout=SimpleNamespace(flush=rotate), stderr=errors))
    code = main(["--workspace", str(mailbox.parent), "team", "mail", "read", "--root", str(mailbox),
                 "--endpoint", "a/root", "--mark-read", "--delivery-dir", str(delivery), "--host", "primary",
                 "--session", "a/root", "--generation", "1", "--json"])
    output = capsys.readouterr()
    assert code == 1 and output.err == "" and json.loads(output.out)["binding"]["generation"] == 1
    refusal = json.loads(errors.getvalue())
    assert refusal["reason"] == "binding" and refusal["next_action"]
    assert list(delivery.rglob("*.json")) == []


@pytest.mark.parametrize("flag,value", [("--host", "primary"), ("--session", "a/root"), ("--generation", "1")],
                         ids=["host", "session", "generation"])
def test_r1b_unmarked_binding_options_keep_legacy_refusal(mailbox, capsys, flag, value):
    before = snapshot(mailbox)
    assert legacy.main(["--root", str(mailbox), "inbox", "--endpoint", "a/root", flag, value]) == 2
    capsys.readouterr()
    code, result = invoke(mailbox, capsys, "read", "--endpoint", "a/root", flag, value)
    assert code == 1 and result["reason"] == "invalid_record" and result["next_action"]
    assert snapshot(mailbox) == before
    assert invoke(mailbox, capsys, "read", "--endpoint", "a/root")[0] == 0


@pytest.mark.parametrize("location", ["message", "checkpoint"])
def test_r1b_full_admitted_brief_matches_legacy_before_mark_read(mailbox, capsys, location):
    raw = (b"brief content\n" * MAX_BYTES)[:MAX_BYTES]
    path = mailbox.parent / "brief.md"
    path.write_bytes(raw)
    reference = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
    box = legacy.Mailbox(mailbox)
    if location == "checkpoint":
        checkpoint = {"outgoing_stopped": True, "briefs": [reference], "sources": [], "lease_refs": [],
                      "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
        box.bind({"endpoint": "a/root", "host": "primary", "session": "replacement", "expected_generation": 1,
                  "checkpoint": checkpoint})
        session, generation = "replacement", "2"
    else:
        session, generation = "a/root", "1"
    box.publish(request(**{"from": "a/orchestrator", "to": "a/root", "session": "a/orchestrator", "brief": reference}))
    expected = box.inbox("a/root", include_briefs=True, limit=20)
    expected_text = expected["messages"][0]["brief_text"] if location == "message" else expected["checkpoint_briefs"][0]["text"]
    assert expected_text.encode("utf-8") == raw
    delivery = mailbox.parent / "delivery"
    delivery.mkdir()
    code, page = invoke(mailbox, capsys, "read", "--endpoint", "a/root", "--include-briefs", "--mark-read",
                        "--delivery-dir", str(delivery), "--host", "primary", "--session", session,
                        "--generation", generation)
    assert code == 0
    actual_text = page["messages"][0]["brief_text"] if location == "message" else page["checkpoint_briefs"][0]["text"]
    assert actual_text == expected_text
    assert box.delivery(delivery, endpoint="a/root")["endpoints"]["a/root"]["read"] == 1


@pytest.mark.parametrize("lock_kind", ["mailbox", "delivery", "owner"])
def test_r1b_receipt_lock_release_warnings_reach_stderr_then_retry(mailbox, capsys, monkeypatch, lock_kind):
    legacy.Mailbox(mailbox).publish(request(**{"from": "a/orchestrator", "to": "a/root", "session": "a/orchestrator"}))
    delivery = mailbox.parent / "delivery"
    delivery.mkdir()
    target = {"mailbox": mailbox, "delivery": delivery / "reads/a/root",
              "owner": mailbox.parent / "owner/.aegis"}[lock_kind]
    lock_name = OWNER_EVIDENCE_LOCK if lock_kind == "owner" else ".write.lock"

    def fail_release(name, *args, **kwargs):
        parent = kwargs.get("dir_fd")
        if name == lock_name and parent is not None and target.exists():
            actual, wanted = os.fstat(parent), target.stat()
            if (actual.st_dev, actual.st_ino) == (wanted.st_dev, wanted.st_ino):
                raise PermissionError("PRIVATE RELEASE FAILURE")
        return os.unlink(name, *args, **kwargs)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "unlink": fail_release}))
    flags = ["--workspace", str(mailbox.parent), "team", "mail", "read", "--root", str(mailbox),
             "--endpoint", "a/root", "--mark-read", "--delivery-dir", str(delivery), "--host", "primary",
             "--session", "a/root", "--generation", "1", "--json"]
    code = main(flags)
    output = capsys.readouterr()
    assert code == 0 and json.loads(output.out)["messages"][0]["message"]["message_id"] == "one"
    warning = json.loads(output.err)
    assert warning["reason"] == "lock_release" and warning["code"] == 0 and warning["next_action"]
    assert warning["warnings"] and "PRIVATE RELEASE FAILURE" not in output.err
    assert (target / lock_name).exists()
    monkeypatch.setattr(storage, "os", os)
    (target / lock_name).unlink()
    assert main(flags) == 0
    retry = capsys.readouterr()
    assert retry.err == ""


def test_r1b_brief_pages_record_only_fully_shown_messages(mailbox, capsys):
    path = mailbox.parent / "brief.md"
    raw = (b"brief content\n" * MAX_BYTES)[:MAX_BYTES]
    path.write_bytes(raw)
    reference = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
    box = legacy.Mailbox(mailbox)
    for index in range(20):
        box.publish(request(**{"message_id": "m%02d" % index, "from": "a/orchestrator", "to": "a/root",
                              "session": "a/orchestrator", "brief": reference}))
    assert legacy.main(["--root", str(mailbox), "inbox", "--endpoint", "a/root", "--include-briefs"]) == 0
    expected = json.loads(capsys.readouterr().out)
    delivery = mailbox.parent / "delivery"
    delivery.mkdir()
    flags = ["--endpoint", "a/root", "--include-briefs", "--mark-read", "--delivery-dir", str(delivery),
             "--host", "primary", "--session", "a/root", "--generation", "1"]
    code, page = invoke(mailbox, capsys, "read", *flags)
    assert code == 0 and len(page["messages"]) == len(expected["messages"]) < 20
    assert page["remaining"] == expected["remaining"] and page["next_after"] == expected["next_after"]
    assert all(row["brief_text"].encode() == raw for row in page["messages"])
    state = box.delivery(delivery, endpoint="a/root")["endpoints"]["a/root"]
    assert state["read"] == len(page["messages"]) and state["unread_count"] == page["remaining"]
    code, remainder = invoke(mailbox, capsys, "read", *flags, "--after", page["next_after"])
    assert code == 0 and remainder["remaining"] == 0
    assert all(row["brief_text"].encode() == raw for row in remainder["messages"])
    assert box.delivery(delivery, endpoint="a/root")["endpoints"]["a/root"]["read"] == 20


def test_r1b_oversized_checkpoint_briefs_refuse_before_receipts(mailbox, capsys):
    raw = b"v" * MAX_BYTES
    references = []
    for index in range(16):
        path = mailbox.parent / ("brief-%02d.md" % index)
        path.write_bytes(raw)
        references.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()})
    box = legacy.Mailbox(mailbox)
    checkpoint = {"outgoing_stopped": True, "briefs": references, "sources": [], "lease_refs": [],
                  "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
    box.bind({"endpoint": "a/root", "host": "primary", "session": "replacement", "expected_generation": 1,
              "checkpoint": checkpoint})
    delivery = mailbox.parent / "delivery"
    delivery.mkdir()
    before = snapshot(mailbox)
    code, result = invoke(mailbox, capsys, "read", "--endpoint", "a/root", "--include-briefs", "--mark-read",
                          "--delivery-dir", str(delivery), "--host", "primary", "--session", "replacement",
                          "--generation", "2")
    assert code == 1 and result["reason"] == "too_large" and result["next_action"]
    assert snapshot(delivery) == {} and snapshot(mailbox) == before
