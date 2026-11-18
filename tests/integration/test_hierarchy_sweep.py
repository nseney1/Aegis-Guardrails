"""The sweep wakes sessions with unread mail across initiatives and reports what stayed unread.

Hosts are the fake host on PATH, which reads and replies through the real adapter. These tests show
the tools work together, not that real sessions behave this way.
"""
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import inspect
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

from tests.integration.test_hierarchy_background import STUB
from tests.integration.test_hierarchy_delivery import HELPER
from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke
from tests.integration.test_hierarchy_mailbox_index_reuse import make_mailbox, publish
from tests.integration.test_hierarchy_provision import INITIATIVE, LANES, Setup, provision
from tests.conftest import symlink_or_skip


SWEEP = ROOT / "tools" / "hierarchy_sweep.py"
FAKE_HOST = Path(__file__).with_name("hierarchy_fake_host.py")
posix_only = pytest.mark.skipif(os.name == "nt", reason="the wake tool supports POSIX process groups only")
pytestmark = posix_only


class Fleet(Setup):
    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.bin = tmp_path / "fake-bin"
        self.bin.mkdir()
        for name in ("claude", "codex"):
            path = self.bin / name
            path.write_text("#!" + sys.executable + "\n" + FAKE_HOST.read_text(encoding="utf-8"), encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.log = tmp_path / "fake-host.log"
        self.plan_path = tmp_path / "fake-host-plan.json"
        self.claude_home = tmp_path / "claude-home"
        self.plan({})

    def plan(self, plan):
        self.plan_path.write_text(json.dumps(plan), encoding="utf-8")

    def add_role(self, endpoint, host="claude-code", *, expect=0, **changes):
        role = super().add_role(endpoint, host, expect=expect, **changes)
        if expect == 0:
            started(self, host, role["session"])
        return role

    def env(self):
        return {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1",
                "FAKE_HOST_LOG": str(self.log), "FAKE_HOST_PLAN": str(self.plan_path),
                "CLAUDE_CONFIG_DIR": str(self.claude_home), "CODEX_HOME": str(self.tmp / "codex-home")}

    def sweep(self, *flags, expect=0, store=None):
        result = subprocess.run([sys.executable, "-I", str(SWEEP), "--store", str(store or self.workspace.store), *flags],
                                capture_output=True, text=True, timeout=90, env=self.env())
        assert not result.stderr, result.stderr
        assert result.returncode in (expect if isinstance(expect, tuple) else (expect,)), result.stdout
        return json.loads(result.stdout)

    def launches(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def send(self, sender, recipient, identifier, *, root=None, **extra):
        root = root or self.root
        binding = invoke(root, "status")["bindings"][sender]
        return invoke(root, "publish", {"message_id": identifier, "from": sender, "to": recipient, "host": binding["host"],
                                        "session": binding["session"], "binding_generation": binding["generation"],
                                        "type": "info", "body": "UNTRUSTED-BODY", **extra})


def started(fleet, host, session):
    """A real session has a transcript from its first turn, which is how the meter finds its active time."""
    if host == "claude-code":
        folder = fleet.claude_home / "projects" / "-pilot"
        name = session + ".jsonl"
    elif host == "codex-cli":
        folder = fleet.tmp / "codex-home" / "sessions" / "2026"
        name = "rollout-2026-" + session + ".jsonl"
    else:
        return
    folder.mkdir(parents=True, exist_ok=True)
    if not (folder / name).exists():
        (folder / name).write_text("")


@pytest.fixture
def fleet(tmp_path):
    built = Fleet(tmp_path)
    built.init()
    built.front_door = built.add_role("pilot/front-door", cwd=str(tmp_path))
    built.orchestrator = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    return built


@posix_only
def test_nothing_unread_means_nothing_is_launched(fleet):
    result = fleet.sweep()
    assert result["quiet"] is True and result["rows"] == []
    assert result["root_queue"] == [] and result["still_unread"] == []
    assert fleet.launches() == []


@pytest.mark.parametrize("action", ["quiet", "publish", "cross_publish", "fail_once"])
def test_sweep_shares_each_pass_summary_and_refreshes_after_wakes(fleet, monkeypatch, action):
    import hierarchy_sweep as candidate

    original = candidate.summaries
    calls = []
    other = second_initiative(fleet) if action == "cross_publish" else None

    def observed(initiative, durable=False, **kwargs):
        calls.append(initiative["id"])
        if action == "fail_once" and len(calls) == 1:
            raise ValueError("mailbox unavailable")
        return original(initiative, durable, **kwargs)

    def wake(initiative, name, summary, dry_run, durable=False):
        if other is None:
            fleet.send("pilot/orchestrator", "pilot/front-door", "published-during-wake")
        else:
            fleet.send("second/orchestrator", "second/front-door", "published-during-wake", root=other)
        return {"initiative": initiative["id"], "endpoint": name, "state": "refused"}

    monkeypatch.setattr("hierarchy_sweep.summaries", observed)
    monkeypatch.setattr("hierarchy_sweep.wake_endpoint", wake)
    if action in ("publish", "cross_publish"):
        fleet.send("pilot/front-door", "pilot/orchestrator", "wake-trigger")
    code, result = candidate.run(fleet.workspace.store, 1, (), False)
    assert len(calls) == (2 if action == "quiet" else 4 if action == "cross_publish" else 2)
    if action in ("publish", "cross_publish"):
        assert code == 3
        assert {row["endpoint"] for row in result["still_unread"]} == {
            "pilot/orchestrator", "second/front-door" if other is not None else "pilot/front-door"}
    elif action == "fail_once":
        assert code == 3 and result["rows"][0]["error"] == "mailbox unavailable"
    else:
        assert code == 0 and result["quiet"] is True


def test_sweep_failed_pass_does_not_reuse_a_previous_pass_summary(fleet, monkeypatch):
    import hierarchy_sweep as candidate

    other = second_initiative(fleet, priority=10)
    fleet.send("pilot/front-door", "pilot/orchestrator", "wake-trigger")
    original = candidate.summaries
    second_reads = []

    def observed(initiative, durable=False, **kwargs):
        if initiative["id"] == "second":
            second_reads.append(True)
            if len(second_reads) == 2:
                fleet.send("second/orchestrator", "second/front-door", "published-before-failure", root=other)
                raise ValueError("later pass unavailable")
        return original(initiative, durable, **kwargs)

    def wake(initiative, name, summary, dry_run, durable=False):
        return {"initiative": initiative["id"], "endpoint": name, "state": "started", "wake_exit": 0}

    monkeypatch.setattr("hierarchy_sweep.summaries", observed)
    monkeypatch.setattr("hierarchy_sweep.wake_endpoint", wake)
    code, result = candidate.run(fleet.workspace.store, 2, (), False)
    assert code == 3 and result["rounds"] == 1
    assert len(second_reads) == 3
    assert {row["endpoint"] for row in result["still_unread"]} == {"pilot/orchestrator", "second/front-door"}
    assert result["rows"][-1]["error"] == "later pass unavailable"


def test_sweep_revalidates_manifest_before_reusing_a_quiet_snapshot(fleet, monkeypatch):
    import hierarchy_sweep as candidate

    original = candidate.Mailbox
    changed = []

    class ChangedManifestMailbox(original):
        def endpoint_delivery(self, directory, endpoint, records):
            result = super().endpoint_delivery(directory, endpoint, records)
            if not changed and endpoint == sorted(self.manifest["endpoints"])[-1]:
                changed.append(True)
                (self.root / "manifest.json").write_text(
                    json.dumps({**self.manifest, "writer_limit": 2}), encoding="utf-8")
                fleet.send("pilot/orchestrator", "pilot/front-door", "published-with-new-manifest")
            return result

    monkeypatch.setattr("hierarchy_sweep.Mailbox", ChangedManifestMailbox)
    code, report = candidate.run(fleet.workspace.store, 1, (), True)
    expected = [{"initiative": "pilot", "endpoint": "pilot/front-door", "unread_count": 1}]
    assert code == 3 and report["still_unread"] == expected
    assert report["rows"] == []
    # A later run uses the current authority and does not retain the old pass.
    code, report = candidate.run(fleet.workspace.store, 1, (), True, skip=("pilot/front-door",))
    assert code == 3 and report["still_unread"] == expected
    assert report["rows"][0]["state"] == "skipped"


@pytest.mark.parametrize("change", [
    "corrupt_message", "publish", "routing_symlink", "corrupt_binding", "corrupt_receipt", "remove_message",
    "message_reformat", "binding_reformat", "receipt_reformat", "new_receipt",
])
def test_sweep_rechecks_all_summary_dependencies_after_an_external_change(fleet, monkeypatch, change):
    import hierarchy_sweep as candidate

    original_mailbox, original_summaries = candidate.Mailbox, candidate.summaries
    fleet.send("pilot/orchestrator", "pilot/front-door", "seed")
    box = original_mailbox(fleet.root)
    binding = box.current_binding("pilot/front-door")
    box.record_read(str(fleet.base / "delivery"), {
        "from": "pilot/front-door", "host": binding["host"], "session": binding["session"],
        "binding_generation": binding["generation"]}, ["seed"])
    message_path = Path(box.messages()["seed"]["path"])
    binding_path = fleet.root / "bindings/pilot/front-door/000001.json"
    receipt_path = next((fleet.base / "delivery/reads/pilot/front-door").glob("*.json"))
    later = second_initiative(fleet, identifier="later", priority=10)
    before_manifest, mutated, builds = (fleet.root / "manifest.json").read_bytes(), [], []

    class LaterMailbox(original_mailbox):
        def __init__(self, root):
            super().__init__(root)
            if self.root != later or mutated:
                return
            mutated.append(True)
            if change == "publish":
                fleet.send("pilot/orchestrator", "pilot/front-door", "external-publication")
            elif change == "routing_symlink":
                directory = fleet.root / "pilot/orchestrator"
                target = fleet.tmp / "old-orchestrator-routing"
                directory.rename(target)
                symlink_or_skip(target, directory, target_is_directory=True)
            elif change == "remove_message":
                message_path.unlink()
            elif change == "message_reformat":
                header, body = message_path.read_bytes()[4:].split(b"\n---\n\n", 1)
                message_path.write_bytes(b"---\n" + json.dumps(json.loads(header), indent=2).encode() + b"\n---\n\n" + body)
            elif change == "new_receipt":
                (receipt_path.parent / "additional.json").write_bytes(receipt_path.read_bytes())
            else:
                path = {"corrupt_message": message_path, "corrupt_binding": binding_path,
                        "corrupt_receipt": receipt_path, "binding_reformat": binding_path,
                        "receipt_reformat": receipt_path}[change]
                if change.endswith("reformat"):
                    path.write_text(json.dumps(json.loads(path.read_bytes()), indent=2), encoding="utf-8")
                else:
                    path.write_bytes(b"garbage")

    def observed(initiative, durable=False, **kwargs):
        builds.append(initiative["id"])
        return original_summaries(initiative, durable, **kwargs)

    monkeypatch.setattr("hierarchy_sweep.Mailbox", LaterMailbox)
    monkeypatch.setattr("hierarchy_sweep.summaries", observed)
    code, report = candidate.run(fleet.workspace.store, 1, (), True)
    assert mutated == [True] and fleet.launches() == []
    assert (fleet.root / "manifest.json").read_bytes() == before_manifest
    if change == "publish":
        assert code == 3 and report["quiet"] is False
        assert report["still_unread"] == [{"initiative": "pilot", "endpoint": "pilot/front-door", "unread_count": 1}]
        assert report["rows"] == []
    elif change.endswith("reformat") or change == "new_receipt":
        assert code == 0 and report["quiet"] is True and report["rows"] == []
        assert builds.count("pilot") == 2, "changed filesystem inputs require a fresh derived summary"
    else:
        with pytest.raises(ValueError) as expected:
            pinned = original_mailbox(fleet.root)
            pinned.endpoint_delivery(str(fleet.base / "delivery"), "pilot/front-door", pinned.messages())
        assert code == 3 and report["quiet"] is False
        assert report["rows"] == [{"initiative": "pilot", "state": "mailbox_error", "error": str(expected.value)[:512]}]


@pytest.mark.parametrize("durable", [False, True])
def test_non_durable_admission_defers_an_idle_marker_refusal_until_reporting(fleet, durable):
    import hierarchy_sweep as candidate

    fleet.send("pilot/front-door", "pilot/orchestrator", "healthy-unread")
    target = fleet.tmp / "idle-marker-target"
    target.write_text("fixture marker", encoding="utf-8")
    symlink_or_skip(target, fleet.root / ".wake-pilot%2Ffront-door.lock")
    report = fleet.sweep("--dry-run", *(("--durable",) if durable else ()), expect=3)
    assert report["quiet"] is False
    assert [row["state"] for row in report["rows"]] == (["mailbox_error"] if durable else ["would_wake", "mailbox_error"])
    if not durable:
        assert report["rows"][0]["endpoint"] == "pilot/orchestrator"
    with pytest.raises(ValueError) as expected:
        candidate.Mailbox(fleet.root).wake_marker("pilot/front-door")
    assert report["rows"][-1]["error"] == str(expected.value)[:512]
    assert fleet.launches() == []


def test_sweep_without_descriptor_capabilities_refreshes_through_pin(fleet, monkeypatch):
    import hierarchy_sweep as candidate

    original, calls = candidate.summaries, []

    def observed(initiative, durable=False, **kwargs):
        calls.append(durable)
        return original(initiative, durable, **kwargs)

    monkeypatch.setattr("hierarchy_mailbox_index._checked_reads_supported", lambda: False)
    monkeypatch.setattr("hierarchy_sweep.summaries", observed)
    code, report = candidate.run(fleet.workspace.store, 1, (), True)
    assert code == 0 and report["quiet"] is True and report["rows"] == []
    assert calls == [False, True]


def test_durable_admission_preserves_the_first_endpoints_refusal(fleet):
    import hierarchy_sweep as candidate

    target = fleet.tmp / "idle-marker-target"
    target.write_text("fixture marker", encoding="utf-8")
    symlink_or_skip(target, fleet.root / ".wake-pilot%2Ffront-door.lock")
    (fleet.root / "bindings/pilot/orchestrator/000001.json").write_bytes(b"invalid binding")
    with pytest.raises(ValueError) as expected:
        candidate.Mailbox(fleet.root).wake_marker("pilot/front-door")
    report = fleet.sweep("--dry-run", "--durable", expect=3)
    assert report["quiet"] is False
    assert report["rows"] == [{"initiative": "pilot", "state": "mailbox_error", "error": str(expected.value)[:512]}]


def quiet_sweep_store(tmp_path, message_count):
    import hierarchy_workspace as workspace

    mailbox = make_mailbox(tmp_path / "mailbox")
    for number in range(message_count):
        publish(mailbox, "seed-%d" % number)
    if message_count:
        mailbox.record_read(str(tmp_path / "delivery"), {
            "from": "a/lane/review", "host": "test-host", "session": "a/lane/review", "binding_generation": 1},
            ["seed-%d" % number for number in range(message_count)])
    store = tmp_path / "store"
    for command, request in (
        ("init", {"writer_limit": 3, "heavy_limit": 1}),
        ("register", {"id": "quiet", "project": "aegis", "repository": "aegis", "priority": 1,
                      "target_branch": "develop", "mailbox_root": str(mailbox.root),
                      "delivery_dir": str(tmp_path / "delivery")}),
    ):
        path = tmp_path / "request.json"
        path.write_text(json.dumps(request), encoding="utf-8")
        code, result = workspace.run(SimpleNamespace(store=str(store), command=command, request=str(path)))
        assert code == 0, result
    return store


@pytest.mark.parametrize("message_count", [0, 20])
def test_quiet_sweep_matches_round1_cached_report(tmp_path, message_count):
    import hierarchy_sweep as candidate
    from hierarchy_mailbox import encoded

    # Captured before O132 from the round-1 cached implementation, source SHA256
    # 3eead7b644f1dbfb58700a3f3bf65b3690a7b4bd9cf28096fa0ca037790f663f.
    # Keep the actual return-code/report bytes here: history-less snapshots need
    # neither Git history nor a second implementation of the deleted cache.
    expected = (
        b'[0,{"lifecycle":{"coverage":"untracked","execution_enabled":false,"state":"untracked",'
        b'"work_complete":false},"mail_quiet":true,"quiet":true,"root_queue":[],"root_time":[],"rotate_needed":[],'
        b'"rounds":0,"rows":[],"silent_roles":[],"stalled_dispatches":[],"still_unread":[],"work_complete":false}]'
    )
    store = quiet_sweep_store(tmp_path, message_count)
    assert encoded(candidate.run(store, 1, (), True)) == expected


def test_mail_quiet_does_not_claim_that_untracked_work_is_complete(fleet):
    result = fleet.sweep()
    assert result["quiet"] is True
    assert result.get("work_complete") is False, "mail quiet must not erase untracked FINAL/HOLD obligations"
    assert result["lifecycle"]["state"] == "untracked"


def test_an_unavailable_lifecycle_is_hold_even_when_mail_is_quiet(fleet):
    missing = fleet.tmp / "missing-lifecycle"
    result = fleet.sweep("--lifecycle", str(missing), expect=3)
    assert result["quiet"] is False and result["mail_quiet"] is True
    assert result["work_complete"] is False
    assert result["lifecycle"]["state"] == "hold"
    assert "No such file" in result["lifecycle"]["error"]
    assert fleet.launches() == []


def test_lifecycle_preflight_holds_unread_work_before_any_host_wake(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "must-remain-unread")
    result = fleet.sweep("--lifecycle", str(fleet.tmp / "missing-lifecycle"), expect=3)
    assert result["lifecycle"]["state"] == "hold"
    assert fleet.launches() == [], "invalid lifecycle destination must refuse before dispatch"


@posix_only
def test_owned_lifecycle_obligation_keeps_zero_job_sweep_pending(fleet):
    from tests.integration.test_hierarchy_lifecycle import Ledger, request

    folder = fleet.tmp / "recovery"
    folder.mkdir()
    ledger = Ledger(folder)
    value = request()
    ledger.publish(value)
    ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "engine/coordinator",
                 "next_decision": "authorize P1 recovery", "condition": "controls reviewed", "evidence": ledger.evidence},
                 **ledger.target(value))
    result = fleet.sweep("--lifecycle", str(ledger.path), expect=3)
    assert result["mail_quiet"] is True and result["quiet"] is False
    assert result["root_queue"] == [] and result["work_complete"] is False
    assert result["lifecycle"]["obligations"][0]["owner"] == "engine/coordinator"
    assert fleet.launches() == []


def test_a_mailbox_error_on_the_final_read_keeps_its_original_diagnostic(fleet):
    # The filesystem is the real boundary: fail only its later manifest read,
    # while using the public entry point and real stores/mailbox objects.
    script = """
import errno, importlib.util, io, json, os, sys
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('sweep_entry', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_open, reads = io.open, 0
def open_boundary(path, *args, **kwargs):
    global reads
    if os.fspath(path) == sys.argv[3]:
        reads += 1
        if reads > 1:
            raise PermissionError(errno.EACCES, 'fixture final-read denied', sys.argv[3])
    return real_open(path, *args, **kwargs)
with patch('io.open', open_boundary):
    sys.exit(module.main(['--store', sys.argv[2], '--dry-run']))
"""
    proc = subprocess.run([sys.executable, "-c", script, str(SWEEP), str(fleet.workspace.store),
                           str(fleet.root / "manifest.json")], capture_output=True, text=True, timeout=15, env=fleet.env())
    assert proc.returncode == 3 and not proc.stderr, proc.stdout + proc.stderr
    result = json.loads(proc.stdout)
    assert result["quiet"] is False
    errors = [row for row in result["rows"] if row["state"] == "mailbox_error"]
    assert len(errors) == 1 and "fixture final-read denied" in errors[0]["error"]
    assert fleet.launches() == []


@posix_only
def test_a_session_with_unread_mail_is_woken_and_reads_it(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep()
    assert result["quiet"] is True
    assert [(row["endpoint"], row["state"]) for row in result["rows"]] == [("pilot/orchestrator", "read")]
    assert result["rows"][0]["read"] == ["hello"]
    launched = fleet.launches()
    assert [row["endpoint"] for row in launched] == ["pilot/orchestrator"]
    assert "UNTRUSTED-BODY" not in json.dumps(launched), "message text must never reach the command line or prompt"
    assert "mailbox_inbox" in launched[0]["stdin"]


@posix_only
@pytest.mark.parametrize("state", ["alive", "exited", "assertion_failure", "exit_race", "permission_error"])
def test_background_mode_holder_cleanup_only_signals_live_handles(state):
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    signals = []

    def signal_group(pid, sig):
        assert holder.returncode is None and holder.poll() is None, "signalled a reaped holder"
        assert pid == holder.pid
        signals.append((pid, sig))
        if state == "exit_race":
            if holder.poll() is None:
                holder.kill()
            holder.wait(timeout=5)
            raise ProcessLookupError("holder exited before group signal")
        if state == "permission_error":
            raise PermissionError("group signal denied")
        os.killpg(pid, sig)

    try:
        if state == "exited":
            if holder.poll() is None:
                holder.kill()
            holder.wait(timeout=5)
        if state == "assertion_failure":
            with pytest.raises(AssertionError, match="fixture assertion failed"):
                try:
                    raise AssertionError("fixture assertion failed")
                finally:
                    reap_background_mode_holder(holder, signal_group)
        else:
            reap_background_mode_holder(holder, signal_group)
        assert holder.returncode is not None
        assert signals == ([] if state == "exited" else [(holder.pid, 9)])
        reap_background_mode_holder(holder, signal_group)
        assert signals == ([] if state == "exited" else [(holder.pid, 9)]), "retry signalled a reaped holder"
    finally:
        if holder.poll() is None:
            holder.kill()
        holder.wait(timeout=5)


def reap_background_mode_holder(holder, signal_group, sig=9):
    """Keep the OS signal boundary explicit so cleanup can be checked with real children."""
    try:
        if holder.poll() is None:
            try:
                signal_group(holder.pid, sig)
            except (ProcessLookupError, PermissionError):
                if holder.poll() is None:
                    holder.kill()
    finally:
        holder.wait(timeout=5)


@posix_only
def test_a_sweep_wake_in_background_mode_reports_the_idle_session_it_stopped(fleet):
    row = run_background_mode_sweep(fleet)
    assert row["state"] == "read" and row["read"] == ["hello"], row
    # The stop of the earlier idle session and how this turn ended must reach ROOT through the sweep row.
    assert row["stopped_idle"] == "old00000", row
    assert row["background"]["ended"] == "idle" and row["background"]["stop_confirmed"] is True, row


def background_process_identity(pid, proc=Path("/proc")):
    try:
        fields = (proc / str(pid) / "stat").read_text().rpartition(")")[2].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    if len(fields) <= 19 or not fields[19].isdigit():
        raise AssertionError("invalid process start identity")
    return None if fields[0] in ("Z", "X") else int(fields[19])


def background_reader_supported():
    return sys.platform == "linux" and Path("/proc/self/stat").is_file()


def require_background_reader_identity():
    if not background_reader_supported():
        pytest.skip("background reader cleanup needs Linux process start identities")
    if not background_pidfd_supported():
        raise RuntimeError("background reader cleanup requires pidfd signalling on " + sys.platform)


def background_pidfd_supported():
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return False
    try:
        fd = os.pidfd_open(os.getpid())
    except OSError:
        return False
    try:
        signal.pidfd_send_signal(fd, 0)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def observed_background_reader(state):
    record = state / "reader-identity.json"
    return json.loads(record.read_text()) if record.exists() else None


def stop_observed_background_reader(observed, signal_reader=None, identity=background_process_identity, timeout=5,
                                    open_pidfd=None):
    if observed is None:
        return
    pid, started_at = observed
    if started_at is None:
        return
    require_background_reader_identity()
    opener = os.pidfd_open if open_pidfd is None else open_pidfd
    sender = signal.pidfd_send_signal if signal_reader is None else signal_reader
    try:
        fd = opener(pid)
    except ProcessLookupError:
        return
    try:
        if identity(pid) != started_at:
            return
        try:
            sender(fd, signal.SIGTERM)
        except ProcessLookupError:
            return
        if not select.select([fd], [], [], timeout)[0]:
            raise TimeoutError("background reader did not exit")
    finally:
        os.close(fd)


@pytest.mark.parametrize("state", ["live", "gone", "reused", "exit_race", "denied", "timeout"])
def test_background_reader_cleanup_checks_identity_and_bounds_exit(state):
    require_background_reader_identity()
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    signals, descriptors = [], []

    def open_bound(pid):
        fd = os.pidfd_open(pid)
        descriptors.append(fd)
        return fd

    def signal_reader(fd, sig):
        assert holder.poll() is None
        assert (holder.pid, background_process_identity(holder.pid)) == observed
        signals.append((holder.pid, sig))
        if state == "exit_race":
            if holder.poll() is None:
                holder.kill()
            holder.wait(timeout=5)
            raise ProcessLookupError("reader exited before group signal")
        if state == "denied":
            raise PermissionError("reader group signal denied")
        if state != "timeout":
            signal.pidfd_send_signal(fd, sig)

    try:
        observed = (holder.pid, background_process_identity(holder.pid))
        assert observed[1] is not None
        if state == "gone":
            reap_background_mode_holder(holder, os.killpg)
        target = (holder.pid, observed[1] + 1) if state == "reused" else observed
        if state in ("denied", "timeout"):
            error, message = ((PermissionError, "reader group signal denied") if state == "denied"
                              else (TimeoutError, "background reader did not exit"))
            with pytest.raises(error, match="^" + message + "$"):
                stop_observed_background_reader(target, signal_reader, timeout=0, open_pidfd=open_bound)
            assert holder.poll() is None
            reap_background_mode_holder(holder, os.killpg)
        else:
            stop_observed_background_reader(target, signal_reader, open_pidfd=open_bound)
        if state == "reused":
            assert holder.poll() is None, "a different start identity must remain untouched"
        else:
            holder.wait(timeout=5)
        expected = [] if state in ("gone", "reused") else [(holder.pid, signal.SIGTERM)]
        assert signals == expected
        stop_observed_background_reader(target, signal_reader, open_pidfd=open_bound)
        assert signals == expected, "cleanup retry must not signal a departed or different process"
        for fd in descriptors:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
    finally:
        reap_background_mode_holder(holder, os.killpg)


def test_background_reader_cleanup_without_an_observation_does_not_signal():
    def unexpected_signal(pid, sig):
        raise AssertionError("an unobserved reader must not be signalled")

    stop_observed_background_reader(None, unexpected_signal)
    stop_observed_background_reader((1, None), unexpected_signal)


def test_background_reader_identity_error_closes_bound_descriptor():
    require_background_reader_identity()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    descriptors = []

    def open_bound(pid):
        fd = os.pidfd_open(pid)
        descriptors.append(fd)
        return fd

    def denied_identity(pid):
        raise PermissionError("reader identity read denied")

    try:
        observed = (child.pid, background_process_identity(child.pid))
        with pytest.raises(PermissionError, match="^reader identity read denied$"):
            stop_observed_background_reader(observed, identity=denied_identity, open_pidfd=open_bound)
        assert child.poll() is None
        for fd in descriptors:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
    finally:
        reap_background_mode_holder(child, os.killpg)


@pytest.mark.parametrize("state,expected", [("S", 901), ("Z", None), ("X", None)])
def test_background_reader_identity_handles_process_names_and_exit_states(tmp_path, state, expected):
    process = tmp_path / "123"
    process.mkdir()
    (process / "stat").write_text("123 (name with ) and spaces) " + " ".join([state] + ["0"] * 18 + ["901"]))
    assert background_process_identity(123, tmp_path) == expected


def test_background_reader_identity_handles_missing_and_malformed_records(tmp_path):
    assert background_process_identity(123, tmp_path) is None
    process = tmp_path / "123"
    process.mkdir()
    (process / "stat").write_text("123 (short) S")
    with pytest.raises(AssertionError, match="^invalid process start identity$"):
        background_process_identity(123, tmp_path)


def test_background_reader_identity_probe_skips_unsupported_platform(monkeypatch):
    monkeypatch.setattr("tests.integration.test_hierarchy_sweep.background_reader_supported", lambda: False)
    with pytest.raises(pytest.skip.Exception, match="^background reader cleanup needs Linux process start identities$"):
        require_background_reader_identity()


def test_background_reader_missing_pidfd_support_refuses_without_numeric_fallback(monkeypatch):
    monkeypatch.setattr("tests.integration.test_hierarchy_sweep.background_pidfd_supported", lambda: False)
    with pytest.raises(RuntimeError, match="^background reader cleanup requires pidfd signalling on " + sys.platform + "$"):
        require_background_reader_identity()


def publish_background_reader(state, child, fail_at=None):
    def step(name):
        if fail_at == name:
            raise OSError("reader identity publication " + name + " failed")

    record = state / "reader-identity.json"
    temporary = state / "reader-identity.json.tmp"
    try:
        step("open")
        stream = temporary.open("w", encoding="utf-8")
        try:
            step("write")
            json.dump([child.pid, background_process_identity(child.pid)], stream)
        finally:
            stream.close()
            step("close")
        step("rename")
        os.replace(temporary, record)
    except BaseException:
        reap_background_mode_holder(child, os.killpg, sig=signal.SIGTERM)
        raise


def exit_background_reader(signum, frame):
    raise SystemExit(0)


def run_background_reader_helper(argv, *, input, text, capture_output, check, pass_fds=()):
    assert text and capture_output, "reader helper requires captured text"
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    try:
        restore = ("import os, signal, sys; signal.pthread_sigmask(signal.SIG_SETMASK, "
                   + repr(sorted(int(item) for item in previous)) + "); os.execv(sys.argv[1], sys.argv[1:])")
        child = subprocess.Popen([sys.executable, "-c", restore, *argv],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True, pass_fds=pass_fds)
        with child.stdin, child.stdout, child.stderr:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                stdout, stderr = child.communicate(input)
            finally:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
                reap_background_mode_holder(child, os.killpg)
        if check and child.returncode:
            raise subprocess.CalledProcessError(child.returncode, argv, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, child.returncode, stdout, stderr)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@pytest.mark.parametrize("fail_at", ["open", "write", "close", "rename"])
def test_background_reader_publication_failure_reaps_its_unpublished_child(tmp_path, fail_at):
    require_background_reader_identity()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    try:
        with pytest.raises(OSError, match="^reader identity publication " + fail_at + " failed$"):
            publish_background_reader(tmp_path, child, fail_at)
        assert child.poll() is not None, "unpublished reader survived publication failure"
        assert not (tmp_path / "reader-identity.json").exists()
    finally:
        reap_background_mode_holder(child, os.killpg)
    replacement = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    try:
        publish_background_reader(tmp_path, replacement)
        publish_background_reader(tmp_path, replacement)
        assert replacement.poll() is None
        assert observed_background_reader(tmp_path) == [replacement.pid, background_process_identity(replacement.pid)]
    finally:
        reap_background_mode_holder(replacement, os.killpg)


def test_background_reader_real_publication_open_error_reaps_child(tmp_path):
    require_background_reader_identity()
    (tmp_path / "reader-identity.json.tmp").mkdir()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    try:
        with pytest.raises(IsADirectoryError):
            publish_background_reader(tmp_path, child)
        assert child.poll() is not None
    finally:
        reap_background_mode_holder(child, os.killpg)


@pytest.mark.parametrize("stop_method", ["pidfd", "open", "write", "close", "rename"])
def test_background_reader_pidfd_stop_reaps_helper_group_and_descendant(tmp_path, stop_method):
    require_background_reader_identity()
    definitions = (background_process_identity, reap_background_mode_holder,
                   exit_background_reader, run_background_reader_helper)
    imports = "import json, os, signal, subprocess, sys\nfrom pathlib import Path\n"
    helper = (imports + inspect.getsource(background_process_identity) + '''
grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
members = [[os.getpid(), background_process_identity(os.getpid())],
           [grandchild.pid, background_process_identity(grandchild.pid)]]
os.write(int(sys.argv[1]), (json.dumps(members) + "\\n").encode())
grandchild.wait(timeout=60)
''')
    script = (imports + "\n".join(inspect.getsource(function) for function in definitions) + '''
signal.signal(signal.SIGTERM, exit_background_reader)
ready = int(sys.argv[1])
run_background_reader_helper([sys.executable, "-c", sys.argv[2], str(ready)], input="", text=True,
                             capture_output=True, check=True, pass_fds=(ready,))
''')
    ready_r, ready_w = os.pipe()
    reader, members, member_fds = None, [], []
    try:
        reader = subprocess.Popen([sys.executable, "-c", script, str(ready_w), helper], pass_fds=(ready_w,),
                                  start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(ready_w)
        ready_w = None
        assert select.select([ready_r], [], [], 5)[0], "helper group did not announce readiness"
        members = json.loads(os.read(ready_r, 4096))
        assert len(members) == 2 and all(start is not None for _, start in members)
        assert os.getpgid(members[0][0]) == members[0][0]
        assert os.getpgid(members[1][0]) == members[0][0]
        for pid, start in members:
            member_fds.append(os.pidfd_open(pid))
            assert background_process_identity(pid) == start
        observed = (reader.pid, background_process_identity(reader.pid))
        if stop_method == "pidfd":
            stop_observed_background_reader(observed)
        else:
            with pytest.raises(OSError, match="^reader identity publication " + stop_method + " failed$"):
                publish_background_reader(tmp_path, reader, fail_at=stop_method)
        reader.wait(timeout=5)
        assert all(select.select([fd], [], [], 5)[0] for fd in member_fds), "helper group did not exit"
        assert all(background_process_identity(pid) != start for pid, start in members)
    finally:
        try:
            if reader is not None:
                try:
                    stop_observed_background_reader((reader.pid, background_process_identity(reader.pid)))
                finally:
                    reap_background_mode_holder(reader, os.killpg)
        finally:
            try:
                for fd in member_fds:
                    try:
                        if not select.select([fd], [], [], 0)[0]:
                            signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    assert select.select([fd], [], [], 5)[0], "helper rescue did not exit"
            finally:
                try:
                    for fd in member_fds:
                        os.close(fd)
                finally:
                    os.close(ready_r)
                    if ready_w is not None:
                        os.close(ready_w)


def test_background_reader_reuse_after_identity_check_never_signals_replacement():
    require_background_reader_identity()
    original = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    descriptors, replacement_signals = [], []

    def open_bound(pid):
        fd = os.pidfd_open(pid)
        descriptors.append(fd)
        return fd

    def identity_then_exit(pid):
        result = background_process_identity(pid)
        if original.poll() is None:
            original.kill()
        original.wait(timeout=5)
        return result

    def signal_bound(handle, sig):
        if handle in descriptors:
            signal.pidfd_send_signal(handle, sig)
        else:
            # Model a numeric PID now resolving to the replacement process.
            replacement_signals.append(sig)

    try:
        observed = (original.pid, background_process_identity(original.pid))
        stop_observed_background_reader(observed, signal_bound, identity=identity_then_exit, open_pidfd=open_bound)
        assert replacement_signals == [], "numeric signal reached replacement after identity check"
        for fd in descriptors:
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
    finally:
        reap_background_mode_holder(original, os.killpg)


def background_reader_stub():
    launch = 'row = next(row for row in rows() if row["id"] == identifier)\nrow["pid"] = child.pid'
    assert STUB.count(launch) == 1, "background launch seam changed"
    capture = 'publish_background_reader(Path(state), child)\n'
    failure = '''
if sys.argv[2:4] == ["control", "agents"]:
    folder = Path(sys.argv[1])
    if (folder / "fail-after-launch").exists() and (folder / "reader-identity.json").exists():
        sys.exit(7)
'''
    helper_call = 'subprocess.run([sys.executable, "-I", helper,'
    assert STUB.count(helper_call) == 1, "background helper seam changed"
    definitions = (background_process_identity, reap_background_mode_holder, publish_background_reader,
                   exit_background_reader, run_background_reader_helper)
    setup = '\nif sys.argv[2] == "turn":\n    signal.signal(signal.SIGTERM, exit_background_reader)\n'
    return ("import json, os, signal, subprocess, sys\nfrom pathlib import Path\n"
            + "\n".join(inspect.getsource(function) for function in definitions) + setup + failure
            + STUB.replace(launch, capture + launch).replace(helper_call, 'run_background_reader_helper([sys.executable, "-I", helper,'))


@posix_only
def test_background_mode_failure_after_reader_launch_stops_only_the_observed_reader(fleet):
    require_background_reader_identity()
    bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    state = fleet.tmp / "background-state"
    signals = []

    def signal_reader(fd, sig):
        observed = observed_background_reader(state)
        assert observed is not None and sig == signal.SIGTERM
        assert background_process_identity(observed[0]) == observed[1]
        signals.append((observed[0], sig))
        signal.pidfd_send_signal(fd, sig)

    try:
        with pytest.raises(RuntimeError, match="^fixture failure after reader launch$"):
            run_background_mode_sweep(fleet, fail_after_launch=True, signal_reader=signal_reader)
        observed = observed_background_reader(state)
        assert observed is not None, "failure must occur after reader launch"
        assert signals == [(observed[0], signal.SIGTERM)], "teardown must signal exactly the observed reader"
        assert background_process_identity(observed[0]) != observed[1], "reader escaped teardown"
        calls = [json.loads(line) for line in (state / "calls.log").read_text().splitlines()]
        assert ["stop", "old00000"] in calls
        assert ["stop", fleet.orchestrator["session"][:8]] not in calls
        assert bystander.poll() is None
    finally:
        try:
            # Rescue the real detached child even when the regression assertion fails.
            stop_observed_background_reader(observed_background_reader(state))
        finally:
            reap_background_mode_holder(bystander, os.killpg)


def run_background_mode_sweep(fleet, fail_after_launch=False, signal_reader=None):
    require_background_reader_identity()
    stub, state = fleet.tmp / "claude_stub.py", fleet.tmp / "background-state"
    stub.write_text(background_reader_stub(), encoding="utf-8")
    state.mkdir()
    if fail_after_launch:
        (state / "fail-after-launch").touch()
    session, endpoint = fleet.orchestrator["session"], "pilot/orchestrator"
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    try:
        (state / "old00000.row").write_text(json.dumps({
            "id": "old00000", "sessionId": session, "status": "idle", "state": "blocked", "kind": "background",
            "name": endpoint + "-g1", "pid": holder.pid}))
        path = Path(fleet.orchestrator["wake_profile"])
        profile = json.loads(path.read_text())
        profile.update(mode="background", prompt_via="argv", control=[sys.executable, str(stub), str(state), "control"],
                       argv=[sys.executable, str(stub), str(state), "reader", str(HELPER), str(fleet.root), endpoint,
                             "claude-code", session, str(fleet.base / "delivery"), str(fleet.tmp / "stub-record.json"),
                             "--bg", "--name", endpoint + "-g1", "--resume", session, "--"])
        path.write_text(json.dumps(profile))
        fleet.send("pilot/front-door", endpoint, "hello")
        row = fleet.sweep(expect=(0, 3) if fail_after_launch else 0)["rows"][0]
        if fail_after_launch:
            assert row["state"] == "refused" and row["error"] == "could not list background sessions: exit 7", row
            observed = observed_background_reader(state)
            assert observed is not None and observed[1] is not None
            assert background_process_identity(observed[0]) == observed[1], "reader must be live before fixture failure"
            raise RuntimeError("fixture failure after reader launch")
    finally:
        try:
            reap_background_mode_holder(holder, os.killpg)
        finally:
            stop_observed_background_reader(observed_background_reader(state), signal_reader)
    return row


@posix_only
def test_a_conversation_runs_over_rounds_without_anyone_starting_each_turn(fleet):
    fleet.plan({"pilot/orchestrator": {"send": [{"message_id": "reply", "to": "pilot/front-door", "type": "info", "body": "Done."}]}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "question")
    result = fleet.sweep("--rounds", "3")
    assert result["quiet"] is True and result["rounds"] == 2
    assert [row["endpoint"] for row in result["rows"]] == ["pilot/orchestrator", "pilot/front-door"]
    assert [row["state"] for row in result["rows"]] == ["read", "read"]


@posix_only
def test_one_round_leaves_the_reply_unread_and_says_so(fleet):
    fleet.plan({"pilot/orchestrator": {"send": [{"message_id": "reply", "to": "pilot/front-door", "type": "info", "body": "Done."}]}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "question")
    result = fleet.sweep(expect=3)
    assert result["quiet"] is False
    assert result["still_unread"] == [{"initiative": "pilot", "endpoint": "pilot/front-door", "unread_count": 1}]


@posix_only
def test_a_session_that_ignores_its_mail_is_not_retried_in_the_same_sweep(fleet):
    fleet.plan({"pilot/orchestrator": {"ignore": True}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep("--rounds", "4", expect=3)
    assert [row["state"] for row in result["rows"]] == ["woken_unread"]
    assert len(fleet.launches()) == 1
    assert result["still_unread"][0]["endpoint"] == "pilot/orchestrator"


@posix_only
def test_a_new_message_gives_an_ignoring_session_another_wake_in_a_later_sweep(fleet):
    fleet.plan({"pilot/orchestrator": {"ignore": True}})
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    fleet.sweep(expect=3)
    fleet.sweep(expect=3)
    assert len(fleet.launches()) == 2


def claude_transcript(fleet, session, minutes):
    folder = fleet.claude_home / "projects" / "-pilot"
    folder.mkdir(parents=True, exist_ok=True)
    rows = [{"type": "user", "timestamp": "2026-11-02T00:00:00.000Z", "message": {"content": "work"}},
            {"type": "assistant", "timestamp": "2026-11-02T%02d:%02d:00.000Z" % (minutes // 60, minutes % 60), "message": {"content": []}}]
    (folder / (session + ".jsonl")).write_text("".join(json.dumps(row) + "\n" for row in rows))


def codex_transcript(fleet, session, minutes):
    folder = fleet.tmp / "codex-home" / "sessions" / "2026"
    folder.mkdir(parents=True, exist_ok=True)
    rows = [{"type": "event_msg", "timestamp": "2026-11-02T00:00:00.000Z", "payload": {"type": "task_started"}},
            {"type": "event_msg", "timestamp": "2026-11-02T%02d:%02d:00.000Z" % (minutes // 60, minutes % 60), "payload": {"type": "task_complete"}}]
    (folder / ("rollout-2026-" + session + ".jsonl")).write_text("".join(json.dumps(row) + "\n" for row in rows))


@posix_only
def test_a_session_over_60_active_minutes_is_not_woken_and_needs_rotation(fleet):
    session = fleet.orchestrator["session"]
    claude_transcript(fleet, session, 60)
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep(expect=3)
    assert fleet.launches() == []
    assert result["rows"][0]["state"] == "rotate_needed"
    assert result["rows"][0]["active_seconds"] == 3600
    assert result["rotate_needed"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "session": session}]


@posix_only
def test_a_session_under_60_active_minutes_is_woken_with_a_warning(fleet):
    claude_transcript(fleet, fleet.orchestrator["session"], 50)
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    row = fleet.sweep()["rows"][0]
    assert row["state"] == "read" and row["meter_before"] == "rotate_soon" and row["active_seconds_before"] == 3000


@pytest.mark.parametrize("minutes, state", [(70, "ok"), (80, "rotate_soon"), (90, "rotate_now")])
def test_the_sweep_tells_root_its_own_time_against_90_minutes(fleet, minutes, state):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    codex_transcript(fleet, "root-session", minutes)
    result = fleet.sweep()
    assert result["root_time"] == [{"session": "root-session", "host": "codex-cli", "state": state,
                                    "active_seconds": minutes * 60, "limit": 5400}]


def test_one_root_serving_two_initiatives_is_reported_once(fleet):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    second_initiative(fleet)
    provision("add-role", fleet.request(base=str(fleet.tmp / "initiatives" / "second"), endpoint="second/root", host="codex-cli",
                                        session="root-session"))
    codex_transcript(fleet, "root-session", 10)
    assert [row["session"] for row in fleet.sweep()["root_time"]] == ["root-session"]


def test_a_native_thread_with_unread_mail_is_left_for_root_to_message(fleet):
    fleet.add_role("pilot/lane/review", "codex", session="native-review")
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review", "host": "claude-code",
                                   "session": fleet.orchestrator["session"], "binding_generation": 1, "type": "info", "body": "Look."})
    result = fleet.sweep(expect=3)
    assert result["quiet"] is False and result["root_queue"] == []
    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/lane/review", "state": "message_thread", "session": "native-review",
                               "unread_count": 1, "meter_before": "no_transcript", "active_seconds_before": None}]
    assert fleet.launches() == []


def test_a_native_thread_past_its_limit_needs_rotation_instead(fleet):
    fleet.add_role("pilot/lane/review", "codex", session="native-review")
    codex_transcript(fleet, "native-review", 60)
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review", "host": "claude-code",
                                   "session": fleet.orchestrator["session"], "binding_generation": 1, "type": "info", "body": "Look."})
    assert fleet.sweep(expect=3)["rows"][0]["state"] == "rotate_needed"


@posix_only
def test_a_cli_session_with_no_transcript_is_not_woken(fleet):
    """Its active time is unknown, so a wake could carry it past its limit."""
    session = fleet.orchestrator["session"]
    (fleet.claude_home / "projects" / "-pilot" / (session + ".jsonl")).unlink()
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep(expect=3)
    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "state": "time_unknown", "session": session,
                               "unread_count": 1}]
    assert fleet.launches() == []


@posix_only
def test_a_session_whose_active_time_cannot_be_measured_is_not_woken(fleet):
    session = str(uuid.uuid4())
    invoke(fleet.root, "bind", {"endpoint": "pilot/lane/review", "host": "other-host", "session": session,
                                "expected_generation": 0})
    profile = json.loads(Path(fleet.orchestrator["wake_profile"]).read_text())
    profile.update(endpoint="pilot/lane/review", host="other-host", session=session, argv=["claude", "--resume", session])
    (fleet.base / "profiles" / "pilot%2Flane%2Freview-g1.wake.json").write_text(json.dumps(profile))
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review",
                                   "host": "claude-code", "session": fleet.orchestrator["session"], "binding_generation": 1,
                                   "type": "info", "body": "Look."})
    result = fleet.sweep(expect=3)
    assert result["rows"][0]["state"] == "meter_error"
    assert fleet.launches() == []


@posix_only
def test_an_endpoint_with_no_profile_is_reported_not_skipped_silently(fleet):
    invoke(fleet.root, "bind", {"endpoint": "pilot/lane/review", "host": "claude-code", "session": str(uuid.uuid4()),
                                "expected_generation": 0})
    invoke(fleet.root, "publish", {"message_id": "for-review", "from": "pilot/orchestrator", "to": "pilot/lane/review",
                                   "host": "claude-code", "session": fleet.orchestrator["session"], "binding_generation": 1,
                                   "type": "info", "body": "Look."})
    result = fleet.sweep(expect=3)
    assert result["quiet"] is False and result["root_queue"] == []
    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/lane/review", "state": "no_profile", "unread_count": 1}]


@posix_only
def test_an_unbound_endpoint_with_no_session_cannot_receive_mail_and_is_not_an_error(fleet):
    assert fleet.sweep()["quiet"] is True


@posix_only
def test_root_job_requires_attention_even_when_worker_inboxes_are_quiet(fleet):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    brief = fleet.base / "packet.md"
    brief.write_bytes(b"Run it.\n")
    invoke(fleet.root, "publish", {"message_id": "job-1", "from": "pilot/orchestrator", "to": "pilot/root",
                                   "host": "claude-code", "session": fleet.orchestrator["session"], "binding_generation": 1,
                                   "type": "job_request", "body": "Run.",
                                   "brief": {"path": str(brief), "sha256": hashlib.sha256(b"Run it.\n").hexdigest()}})
    result = fleet.sweep(expect=3)
    assert fleet.launches() == [] and result["rows"] == []
    assert result["still_unread"] == []  # Worker quiet does not clear ROOT's obligations.
    assert result["root_queue"] == [{"initiative": "pilot", "endpoint": "pilot/root", "unread_count": 1, "open_jobs": 1}]
    assert result["quiet"] is False


def test_root_reading_its_mail_clears_unread_but_not_its_open_jobs(fleet):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    brief = fleet.base / "packet.md"
    brief.write_bytes(b"Run it.\n")
    orchestrator = {"from": "pilot/orchestrator", "to": "pilot/root", "host": "claude-code",
                    "session": fleet.orchestrator["session"], "binding_generation": 1}
    invoke(fleet.root, "publish", {**orchestrator, "message_id": "note", "type": "info", "body": "Please add a lane."})
    invoke(fleet.root, "publish", {**orchestrator, "message_id": "job-1", "type": "job_request", "body": "Run.",
                                   "brief": {"path": str(brief), "sha256": hashlib.sha256(b"Run it.\n").hexdigest()}})
    entry = {"initiative": "pilot", "endpoint": "pilot/root"}
    assert fleet.sweep(expect=3)["root_queue"] == [{**entry, "unread_count": 2, "open_jobs": 1}]
    delivery = str(fleet.base / "delivery")
    page = invoke(fleet.root, "inbox", endpoint="pilot/root", delivery_dir=delivery, mark_read=True, limit=1,
                  host="codex-cli", session="root-session", generation=1)
    assert [row["message"]["message_id"] for row in page["messages"]] == ["note"]
    assert fleet.sweep(expect=3)["root_queue"] == [{**entry, "unread_count": 1, "open_jobs": 1}]
    invoke(fleet.root, "inbox", endpoint="pilot/root", delivery_dir=delivery, mark_read=True, host="codex-cli", session="root-session", generation=1)
    result = fleet.sweep(expect=3)
    assert result["root_queue"] == [{**entry, "unread_count": 0, "open_jobs": 1}]
    assert result["quiet"] is False and result["still_unread"] == []
    assert fleet.launches() == []


def test_unread_root_information_requires_attention_until_root_reads_it(fleet):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    fleet.send("pilot/orchestrator", "pilot/root", "root-note")
    result = fleet.sweep(expect=3)
    assert result["quiet"] is False and result["still_unread"] == []
    assert result["root_queue"] == [{"initiative": "pilot", "endpoint": "pilot/root",
                                    "unread_count": 1, "open_jobs": 0}]
    assert fleet.launches() == []
    invoke(fleet.root, "inbox", endpoint="pilot/root",
           delivery_dir=str(fleet.base / "delivery"), mark_read=True, host="codex-cli", session="root-session", generation=1)
    result = fleet.sweep()
    assert result["quiet"] is True and result["root_queue"] == []
    assert fleet.launches() == []


@pytest.mark.parametrize("state, exit_code, open_jobs", [
    ("completed", 0, 0), ("failed", 7, 0), ("refused", None, 0), ("unknown", None, 1),
])
def test_job_receipt_terminality_and_recipient_read_are_separate(fleet, state, exit_code, open_jobs):
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    packet = fleet.base / "packet.md"
    packet.write_bytes(b"Synthetic request; this test executes no job.\n")
    evidence = {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}
    invoke(fleet.root, "publish", {
        "message_id": "job-1", "from": "pilot/orchestrator", "to": "pilot/root",
        "host": "claude-code", "session": fleet.orchestrator["session"], "binding_generation": 1,
        "type": "job_request", "body": "Information only.", "brief": evidence,
    })
    delivery = str(fleet.base / "delivery")
    invoke(fleet.root, "inbox", endpoint="pilot/root", delivery_dir=delivery, mark_read=True, host="codex-cli", session="root-session", generation=1)
    pending = fleet.sweep(expect=3)
    assert pending["root_queue"] == [{"initiative": "pilot", "endpoint": "pilot/root",
                                     "unread_count": 0, "open_jobs": 1}]
    assert pending["quiet"] is False and fleet.launches() == []

    invoke(fleet.root, "publish", {
        "message_id": "job-1-receipt", "from": "pilot/root", "to": "pilot/orchestrator",
        "host": "codex-cli", "session": "root-session", "binding_generation": 1,
        "type": "job_receipt", "body": "Synthetic bookkeeping, never execution evidence.",
        "in_reply_to": "job-1",
        "receipt": {"state": state, "exit_code": exit_code, "evidence": [evidence],
                    "reason": "Synthetic fixture outcome."},
    })
    published = invoke(fleet.root, "delivery", delivery_dir=delivery, message_id="job-1-receipt")
    assert published["message"]["state"] == "published"
    assert published["message"]["read_at"] is None
    expected_root = ([{"initiative": "pilot", "endpoint": "pilot/root",
                       "unread_count": 0, "open_jobs": open_jobs}] if open_jobs else [])
    pending = fleet.sweep("--dry-run", expect=3)
    assert pending["quiet"] is False and pending["root_queue"] == expected_root
    assert pending["still_unread"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "unread_count": 1}]
    assert [row["state"] for row in pending["rows"]] == ["would_wake"]
    assert fleet.launches() == []

    result = fleet.sweep(expect=3 if open_jobs else 0)
    assert result["quiet"] is (open_jobs == 0)
    assert result["root_queue"] == expected_root and result["still_unread"] == []
    assert result["rows"][0]["read"] == ["job-1-receipt"]
    read = invoke(fleet.root, "delivery", delivery_dir=delivery, message_id="job-1-receipt")
    assert read["message"]["state"] == "read"
    assert read["message"]["read_by"]["session"] == fleet.orchestrator["session"]


def test_only_root_marks_mail_read_through_the_cli(fleet):
    delivery = str(fleet.base / "delivery")
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    refused = invoke(fleet.root, "inbox", endpoint="pilot/orchestrator", delivery_dir=delivery, mark_read=True, ok=False)
    assert "only root reads through the CLI" in refused["error"]
    fleet.add_role("pilot/root", "codex-cli", session="root-session")
    refused = invoke(fleet.root, "inbox", endpoint="pilot/root", mark_read=True, ok=False)
    assert refused["error"] == "--mark-read needs --delivery-dir"
    assert fleet.sweep("--dry-run", expect=3)["still_unread"][0]["endpoint"] == "pilot/orchestrator"


@posix_only
def test_a_replacement_without_a_new_profile_is_reported(fleet):
    brief = fleet.base / "brief.md"
    brief.write_bytes(b"Handoff.\n")
    invoke(fleet.root, "bind", invoke(fleet.root, "draft-handoff", {
        "endpoint": "pilot/orchestrator", "host": "claude-code", "session": str(uuid.uuid4()), "outgoing_stopped": True,
        "briefs": [{"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}]}))
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep(expect=3)
    assert result["rows"][0]["state"] == "no_profile"
    assert fleet.launches() == []


def second_initiative(fleet, identifier="second", priority=1, project="stormheir"):
    base = fleet.tmp / "initiatives" / identifier
    provision("init", fleet.request(store=str(fleet.workspace.store), base=str(base), source=str(fleet.source), lanes=LANES,
                                    initiative={**INITIATIVE, "id": identifier, "priority": priority, "project": project,
                                                "repository": project}))
    for role in ("front-door", "orchestrator"):
        made = provision("add-role", fleet.request(base=str(base), endpoint=identifier + "/" + role, host="claude-code",
                                                   cwd=str(fleet.tmp)))
        started(fleet, "claude-code", made["session"])
    return base / "mailbox"


@posix_only
def test_every_initiative_is_swept_in_the_owners_priority_order(fleet):
    other = second_initiative(fleet)
    fleet.send("pilot/front-door", "pilot/orchestrator", "for-pilot")
    fleet.send("second/front-door", "second/orchestrator", "for-second", root=other)
    result = fleet.sweep()
    assert [row["initiative"] for row in result["rows"]] == ["second", "pilot"]
    assert result["quiet"] is True


@posix_only
def test_one_initiative_can_be_selected_and_paused_ones_are_left_alone(fleet):
    other = second_initiative(fleet)
    fleet.send("pilot/front-door", "pilot/orchestrator", "for-pilot")
    fleet.send("second/front-door", "second/orchestrator", "for-second", root=other)
    result = fleet.sweep("--initiative", "second", expect=0)
    assert [row["initiative"] for row in result["rows"]] == ["second"]
    fleet.workspace.run("update", {"initiative": "pilot", "source": "owner", "state": "paused"})
    result = fleet.sweep()
    assert result["rows"] == []
    assert fleet.sweep("--initiative", "unknown", expect=2)["error"] == "initiative is not registered: unknown"


@posix_only
def test_a_broken_mailbox_is_reported_and_the_others_still_run(fleet):
    other = second_initiative(fleet)
    fleet.send("pilot/front-door", "pilot/orchestrator", "for-pilot")
    (other / "manifest.json").write_text("{broken")
    result = fleet.sweep(expect=3)
    assert result["quiet"] is False and result["root_queue"] == []
    states = {row["initiative"]: row["state"] for row in result["rows"]}
    assert states == {"second": "mailbox_error", "pilot": "read"}
    assert next(row for row in result["rows"] if row["initiative"] == "second")["error"]


@posix_only
def test_a_refused_wake_is_reported_with_its_reason(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    (fleet.root / ".write.lock").write_text("fixture active writer")
    result = fleet.sweep(expect=3)
    assert result["rows"][0]["state"] == "refused" and "writer is busy" in result["rows"][0]["error"]
    assert fleet.launches() == []


@posix_only
def test_a_dry_run_launches_nothing(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    result = fleet.sweep("--dry-run", expect=3)
    assert [row["state"] for row in result["rows"]] == ["would_wake"]
    assert fleet.launches() == []
    assert not (fleet.base / "delivery" / "wakes").exists()


def test_bad_round_counts_are_refused(fleet):
    assert fleet.sweep("--rounds", "0", expect=2)["error"] == "invalid rounds"
    assert fleet.sweep("--rounds", "1000", expect=2)["error"] == "invalid rounds"


class SealedFleet(Fleet):
    """PATH is only the fake binaries plus links to the tools the wake needs, so no real model binary is reachable."""

    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        for tool in ("ps", "git"):
            found = shutil.which(tool)
            assert found, "wake process census and source verification need " + tool
            (self.bin / tool).symlink_to(found)

    def env(self):
        return {**super().env(), "PATH": str(self.bin)}


@pytest.fixture
def sealed(tmp_path):
    built = SealedFleet(tmp_path)
    built.init()
    built.front_door = built.add_role("pilot/front-door", cwd=str(tmp_path))
    built.orchestrator = built.add_role("pilot/orchestrator", cwd=str(tmp_path))
    return built


def held_row(fleet, state, generation=1, **extra):
    session = invoke(fleet.root, "status")["bindings"]["pilot/orchestrator"]["session"]
    return {"initiative": "pilot", "endpoint": "pilot/orchestrator", "state": state, "session": session,
            "generation": generation, "unread_count": extra.pop("unread_count", 1), **extra}


def failed_start(fleet, message_ids, at=None, generation=1, state="failed_to_start"):
    """Written through the mailbox's own receipt API, the way a wake that could not start records it."""
    sys.path.insert(0, str(ROOT / "tools"))
    from hierarchy_mailbox import Mailbox

    binding = invoke(fleet.root, "status")["bindings"]["pilot/orchestrator"]
    receipt = {"endpoint": "pilot/orchestrator", "host": binding["host"], "session": binding["session"],
               "generation": generation, "message_ids": message_ids, "wake_id": "wake-" + uuid.uuid4().hex,
               "state": state, "exit_code": None, "timed_out": False}
    if at is not None:
        receipt["at"] = at
    Mailbox(fleet.root).write_delivery_receipt(str(fleet.base / "delivery"), "wakes", receipt)


def ago(seconds):
    moment = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def hand_off(fleet, endpoint="pilot/orchestrator"):
    """A successor binding with its own wake profile and a first-turn transcript, as provisioning leaves one."""
    session = str(uuid.uuid4())
    brief = fleet.base / "brief.md"
    brief.write_bytes(b"Handoff.\n")
    invoke(fleet.root, "bind", invoke(fleet.root, "draft-handoff", {
        "endpoint": endpoint, "host": "claude-code", "session": session, "outgoing_stopped": True,
        "briefs": [{"path": str(brief), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}]}))
    stem = endpoint.replace("/", "%2F")
    old = json.loads((fleet.base / "profiles" / (stem + "-g1.wake.json")).read_text())
    profile = json.loads(json.dumps(old).replace(old["session"], session))
    profile["generation"] = 2
    (fleet.base / "profiles" / (stem + "-g2.wake.json")).write_text(json.dumps(profile))
    started(fleet, "claude-code", session)
    return session


@posix_only
def test_durable_ignored_mail_gets_no_second_turn_from_a_later_sweep_process(sealed):
    sealed.plan({"pilot/orchestrator": {"ignore": True}})
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    assert [row["state"] for row in sealed.sweep("--durable", expect=3)["rows"]] == ["woken_unread"]

    second = sealed.sweep("--durable", expect=3)
    third = sealed.sweep("--durable", expect=3)

    assert second["rows"] == third["rows"] == [held_row(sealed, "ignored_mail")]
    assert second["still_unread"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "unread_count": 1}]
    assert len(sealed.launches()) == 1


@posix_only
def test_durable_new_mail_after_ignored_mail_wakes_once(sealed):
    sealed.plan({"pilot/orchestrator": {"ignore": True}})
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    sealed.sweep("--durable", expect=3)
    sealed.send("pilot/front-door", "pilot/orchestrator", "again")

    woken = sealed.sweep("--durable", expect=3)
    after = sealed.sweep("--durable", expect=3)

    assert [row["state"] for row in woken["rows"]] == ["woken_unread"]
    assert woken["rows"][0]["still_unread"] == ["hello", "again"]
    assert after["rows"] == [held_row(sealed, "ignored_mail", unread_count=2)]
    assert len(sealed.launches()) == 2


@posix_only
def test_durable_successor_generation_gets_one_turn_for_inherited_mail(sealed):
    sealed.plan({"pilot/orchestrator": {"ignore": True}})
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    sealed.sweep("--durable", expect=3)
    successor = hand_off(sealed)

    woken = sealed.sweep("--durable", expect=3)
    after = sealed.sweep("--durable", expect=3)

    assert [row["state"] for row in woken["rows"]] == ["woken_unread"]
    assert successor in sealed.launches()[-1]["argv"]
    assert after["rows"] == [held_row(sealed, "ignored_mail", generation=2)]
    assert len(sealed.launches()) == 2


@posix_only
def test_durable_held_wake_marker_is_reported_and_kept(sealed):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    marker = sealed.root / ".wake-pilot%2Forchestrator.lock"
    marker.write_text("fixture turn in progress")

    first = sealed.sweep("--durable", expect=3)
    second = sealed.sweep("--durable", expect=3)

    assert first["rows"] == second["rows"] == [held_row(sealed, "wake_marker_held", marker=str(marker))]
    assert marker.read_text() == "fixture turn in progress"
    assert sealed.launches() == []
    assert not (sealed.base / "delivery" / "wakes").exists()


@posix_only
def test_durable_three_failed_starts_for_unread_mail_stop_retries(sealed):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    times = [ago(3000), ago(2000), ago(1000)]
    for at in times:
        failed_start(sealed, ["hello"], at=at)

    result = sealed.sweep("--durable", expect=3)

    assert result["rows"] == [held_row(sealed, "start_failed", failed_starts=3, last_failed_at=times[-1])]
    assert sealed.launches() == []


@posix_only
def test_durable_failed_starts_from_an_earlier_generation_do_not_count(sealed):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    for at in (ago(3000), ago(2000), ago(1000)):
        failed_start(sealed, ["hello"], at=at)
    successor = hand_off(sealed)

    result = sealed.sweep("--durable", expect=3)

    # The turn starts; the fake host cannot read for a successor that has not acknowledged its handoff.
    assert [(row["state"], row["wake_exit"]) for row in result["rows"]] == [("woken_unread", 3)]
    assert [successor in row["argv"] for row in sealed.launches()] == [True]


@posix_only
def test_durable_a_failed_start_within_300_seconds_backs_off(sealed):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    recent = ago(10)
    failed_start(sealed, ["hello"], at=ago(1000))
    failed_start(sealed, ["hello"], at=recent)

    result = sealed.sweep("--durable", expect=3)

    assert result["rows"] == [held_row(sealed, "start_backoff", failed_starts=2, last_failed_at=recent)]
    assert sealed.launches() == []


@posix_only
def test_durable_a_failed_start_older_than_300_seconds_is_retried(sealed):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    failed_start(sealed, ["hello"], at=ago(1000))
    failed_start(sealed, ["hello"], at=ago(301))

    result = sealed.sweep("--durable")

    assert [row["state"] for row in result["rows"]] == ["read"]
    assert len(sealed.launches()) == 1


@posix_only
def test_without_durable_the_sweep_behaves_as_before(sealed):
    sealed.plan({"pilot/orchestrator": {"ignore": True}})
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    for at in (ago(30), ago(20), ago(10)):
        failed_start(sealed, ["hello"], at=at)
    sealed.sweep(expect=3)
    sealed.sweep(expect=3)
    assert len(sealed.launches()) == 2, "without --durable, ignored mail and recent failures do not hold a wake"

    marker = sealed.root / ".wake-pilot%2Forchestrator.lock"
    marker.write_text("fixture turn in progress")
    row = sealed.sweep(expect=3)["rows"][0]
    assert (row["state"], row["error"]) == (
        "refused", "a wake is already in progress for this endpoint; inspect the lock before retrying")
    assert marker.exists()


@posix_only
def test_durable_never_wakes_root_messages_native_threads_and_wakes_codex_cli(sealed):
    sealed.add_role("pilot/root", "codex-cli", session="root-session")
    sealed.add_role("pilot/lane/review", "codex", session="native-review")
    worker = sealed.add_role("pilot/lane/f2", "codex-cli", session=str(uuid.uuid4()), cwd=str(sealed.source))
    sender = {"from": "pilot/orchestrator", "host": "claude-code", "session": sealed.orchestrator["session"],
              "binding_generation": 1, "type": "info", "body": "Look."}
    for identifier, to in (("for-root", "pilot/root"), ("for-review", "pilot/lane/review"), ("for-f2", "pilot/lane/f2")):
        invoke(sealed.root, "publish", {**sender, "message_id": identifier, "to": to})

    result = sealed.sweep("--durable", expect=3)

    states = {row["endpoint"]: row["state"] for row in result["rows"]}
    assert states == {"pilot/lane/review": "message_thread", "pilot/lane/f2": "read"}
    assert result["root_queue"] == [{"initiative": "pilot", "endpoint": "pilot/root", "unread_count": 1, "open_jobs": 0}]
    launched = sealed.launches()
    assert [(row["endpoint"], row["program"]) for row in launched] == [("pilot/lane/f2", "codex")]
    assert worker["session"] in launched[0]["argv"]


def mailbox_api(fleet):
    sys.path.insert(0, str(ROOT / "tools"))
    from hierarchy_mailbox import Mailbox

    return Mailbox(fleet.root)


def publish_many(fleet, identifiers):
    """In-process publishes, because one CLI process per message makes a 101-message fixture slow."""
    mailbox = mailbox_api(fleet)
    binding = invoke(fleet.root, "status")["bindings"]["pilot/front-door"]
    for identifier in identifiers:
        mailbox.publish({"message_id": identifier, "from": "pilot/front-door", "to": "pilot/orchestrator",
                         "host": binding["host"], "session": binding["session"],
                         "binding_generation": binding["generation"], "type": "info", "body": "UNTRUSTED-BODY"})


def mark_read(fleet, message_ids):
    binding = invoke(fleet.root, "status")["bindings"]["pilot/orchestrator"]
    mailbox_api(fleet).record_read(str(fleet.base / "delivery"), {
        "from": "pilot/orchestrator", "host": binding["host"], "session": binding["session"],
        "binding_generation": binding["generation"]}, message_ids)


@posix_only
def test_durable_new_mail_behind_more_than_100_ignored_messages_wakes_once(sealed):
    sealed.plan({"pilot/orchestrator": {"ignore": True}})
    publish_many(sealed, ["old-%03d" % index for index in range(101)])
    assert [row["state"] for row in sealed.sweep("--durable", expect=3)["rows"]] == ["woken_unread"]
    # The wake receipt names only the oldest 100; the 101st was in that turn's inbox all the same.
    assert sealed.sweep("--durable", expect=3)["rows"] == [held_row(sealed, "ignored_mail", unread_count=101)]

    sealed.send("pilot/front-door", "pilot/orchestrator", "fresh")
    woken = sealed.sweep("--durable", expect=3)
    after = sealed.sweep("--durable", expect=3)

    assert [row["state"] for row in woken["rows"]] == ["woken_unread"]
    assert after["rows"] == [held_row(sealed, "ignored_mail", unread_count=102)]
    assert len(sealed.launches()) == 2


@posix_only
def test_durable_new_mail_after_three_failed_starts_wakes(sealed):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    for at in (ago(3000), ago(2000), ago(1000)):
        failed_start(sealed, ["hello"], at=at)
    sealed.send("pilot/front-door", "pilot/orchestrator", "again")

    result = sealed.sweep("--durable")

    assert [(row["state"], row["read"]) for row in result["rows"]] == [("read", ["hello", "again"])]
    assert len(sealed.launches()) == 1


@posix_only
def test_durable_failed_starts_for_mail_since_read_do_not_count(sealed):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    for at in (ago(3000), ago(2000), ago(1000)):
        failed_start(sealed, ["hello"], at=at)
    mark_read(sealed, ["hello"])
    sealed.send("pilot/front-door", "pilot/orchestrator", "again")

    result = sealed.sweep("--durable")

    assert [(row["state"], row["read"]) for row in result["rows"]] == [("read", ["again"])]
    assert len(sealed.launches()) == 1


@posix_only
def test_durable_rereads_receipts_so_a_turn_given_after_the_snapshot_is_not_repeated(sealed, monkeypatch, capsys):
    sealed.plan({"pilot/orchestrator": {"ignore": True}})
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    for key, value in sealed.env().items():
        monkeypatch.setenv(key, value)
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_sweep

    measure = hierarchy_sweep.measure

    def turn_given_meanwhile(*args, **kwargs):
        # Runs after the round's snapshot and before the wake: another sweep gives this endpoint its turn here.
        failed_start(sealed, ["hello"], state="started")
        return measure(*args, **kwargs)

    monkeypatch.setattr(hierarchy_sweep, "measure", turn_given_meanwhile)
    code = hierarchy_sweep.main(["--store", str(sealed.workspace.store), "--durable"])
    result = json.loads(capsys.readouterr().out)

    assert code == 3
    assert result["rows"] == [held_row(sealed, "ignored_mail")]
    assert sealed.launches() == []


def durable_in_process(sealed, monkeypatch, capsys, meanwhile):
    """One durable sweep in this process; `meanwhile` runs once after the round's snapshot, before the wake."""
    for key, value in sealed.env().items():
        monkeypatch.setenv(key, value)
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_sweep

    measure, done = hierarchy_sweep.measure, []

    def changed_meanwhile(*args, **kwargs):
        if not done:
            done.append(meanwhile())
        return measure(*args, **kwargs)

    monkeypatch.setattr(hierarchy_sweep, "measure", changed_meanwhile)
    code = hierarchy_sweep.main(["--store", str(sealed.workspace.store), "--durable"])
    return code, json.loads(capsys.readouterr().out)


@posix_only
def test_durable_a_handoff_after_the_snapshot_is_reported_and_not_woken_on_the_old_binding(sealed, monkeypatch, capsys):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")

    code, result = durable_in_process(sealed, monkeypatch, capsys, lambda: hand_off(sealed))

    assert code == 3
    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "state": "binding_changed",
                               "unread_count": 1}]
    assert sealed.launches() == []
    assert not (sealed.base / "delivery" / "wakes").exists()
    # The next pass judges the successor binding on its own; the fake host cannot read for a successor that
    # has not acknowledged its handoff, so the turn starts and leaves the mail unread.
    successor = invoke(sealed.root, "status")["bindings"]["pilot/orchestrator"]["session"]
    after = sealed.sweep("--durable", expect=3)
    assert [(row["state"], row["wake_exit"]) for row in after["rows"]] == [("woken_unread", 3)]
    assert [successor in row["argv"] for row in sealed.launches()] == [True]


@posix_only
def test_durable_mail_read_after_the_snapshot_is_not_held_by_old_failed_starts(sealed, monkeypatch, capsys):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")
    for at in (ago(3000), ago(2000), ago(1000)):
        failed_start(sealed, ["hello"], at=at)

    code, result = durable_in_process(sealed, monkeypatch, capsys, lambda: mark_read(sealed, ["hello"]))

    assert code == 0
    assert [row["state"] for row in result["rows"]] == ["nothing_unread"]
    assert sealed.launches() == []


@posix_only
def test_durable_a_binding_gone_after_the_snapshot_is_no_profile(sealed, monkeypatch, capsys):
    sealed.send("pilot/front-door", "pilot/orchestrator", "hello")

    code, result = durable_in_process(sealed, monkeypatch, capsys,
                                      lambda: shutil.rmtree(sealed.root / "bindings" / "pilot" / "orchestrator"))

    assert result["rows"] == [{"initiative": "pilot", "endpoint": "pilot/orchestrator", "state": "no_profile",
                               "unread_count": 1}]
    assert code == 3
    assert sealed.launches() == []


@posix_only
@pytest.mark.parametrize("flags", [(), ("--durable",), ("--dry-run",)])
def test_a_skipped_endpoint_is_reported_with_its_mail_and_never_woken(fleet, flags):
    fleet.send("pilot/orchestrator", "pilot/front-door", "for-front-door")
    fleet.send("pilot/front-door", "pilot/orchestrator", "for-orchestrator")

    result = fleet.sweep("--skip", "pilot/orchestrator", "--skip", "pilot/lane/absent", *flags, expect=3)

    rows = {row["endpoint"]: row for row in result["rows"]}
    assert rows["pilot/orchestrator"] == {"initiative": "pilot", "endpoint": "pilot/orchestrator", "state": "skipped",
                                          "unread_count": 1}
    assert rows["pilot/front-door"]["state"] == ("would_wake" if flags == ("--dry-run",) else "read")
    assert {"initiative": "pilot", "endpoint": "pilot/orchestrator", "unread_count": 1} in result["still_unread"]
    assert [row["endpoint"] for row in fleet.launches()] == ([] if flags == ("--dry-run",) else ["pilot/front-door"])


def test_a_malformed_skip_endpoint_is_refused_before_anything_runs(fleet):
    fleet.send("pilot/front-door", "pilot/orchestrator", "hello")
    assert fleet.sweep("--skip", "orchestrator", expect=2) == {"error": "invalid endpoint"}
    assert fleet.launches() == []


# -- silent_role and stalled_dispatch: judged from a role's finished turn, from mailbox files alone ---------------------

TEAM = ("pilot/front-door", "pilot/orchestrator", "pilot/router", "pilot/decider", "pilot/lane/f2", "pilot/lane/review")
EVIDENCE = {"source_revision": "b" * 40, "source_tree": "c" * 40,
            "checks": [{"check": "fixture", "outcome": "pass", "reference": "fixture"}]}


@pytest.fixture
def team(tmp_path):
    """Every role the two holds judge, each bound to a fake host, and ROOT, so every route can carry mail."""
    built = SealedFleet(tmp_path)
    provision("init", built.init_request(roles=["router", "decider"]))
    for endpoint in TEAM:
        built.add_role(endpoint, cwd=str(tmp_path))
    built.add_role("pilot/root", "codex-cli", session="root-session")
    return built


@pytest.fixture
def clock(monkeypatch):
    """Stamps this process's mailbox writes `seconds` ago to establish read and publication order."""
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_mailbox

    return lambda seconds: monkeypatch.setattr(hierarchy_mailbox, "timestamp", lambda: ago(seconds))


def moment(value):
    return datetime.fromisoformat(value[:-1] + "+00:00")


def post(fleet, sender, recipient, identifier, kind="info", **extra):
    """In process, so the clock fixture sets its created_at."""
    mailbox = mailbox_api(fleet)
    binding = mailbox.current_binding(sender)
    return mailbox.publish({"message_id": identifier, "from": sender, "to": recipient, "host": binding["host"],
                            "session": binding["session"], "binding_generation": binding["generation"], "type": kind,
                            "body": "UNTRUSTED-BODY", **extra})["message"]


def dispatch(fleet, lane, identifier):
    brief = fleet.base / (identifier + ".md")
    brief.write_bytes(b"Do the work.\n")
    return post(fleet, "pilot/orchestrator", lane, identifier, "dispatch",
                brief={"path": str(brief), "sha256": hashlib.sha256(b"Do the work.\n").hexdigest()})


def reviewer(fleet, lane):
    return mailbox_api(fleet).endpoint(lane).get("kind") == "reviewer"


def accept(fleet, lane, identifier):
    """A writing lane's acceptance names its worktree; the pinned source checkout stands in for one."""
    extra = {}
    if not reviewer(fleet, lane):
        extra["readiness"] = {
            "worktree": str(fleet.source), "branch": "develop", "base_revision": git(fleet.source, "rev-parse", "HEAD"),
            "lease_ref": "refs/aegis/lanes/f2", "lease_oid": "a" * 40, "lease_expires_at": "2099-01-01T00:00:00Z",
            "owned_paths": ["src/**"], "scan_workspace": str(fleet.source), "scan_evidence": "not_run: fixture",
            "enforcement_tier": "advisory", "hook_evidence": "not_observed: fixture"}
    return post(fleet, lane, "pilot/orchestrator", identifier + "-accepted", "ack", acknowledgment="accepted",
                in_reply_to=identifier, **extra)


def answer(fleet, lane, identifier):
    if reviewer(fleet, lane):
        return post(fleet, lane, "pilot/orchestrator", identifier + "-answer", "review", in_reply_to=identifier,
                    result=EVIDENCE)
    return post(fleet, lane, "pilot/orchestrator", identifier + "-answer", "result", in_reply_to=identifier,
                result={**EVIDENCE, "lane_check": "not_run: fixture"})


def turn_starts(fleet, endpoint, read=(), carried=None):
    """A wake's start receipt for the endpoint's unread mail (or the `carried` IDs), as hierarchy_wake writes it, then
    the reads the adapter records during the turn. Returns the start receipt; turn_ends writes its finish."""
    import hierarchy_mailbox

    mailbox = mailbox_api(fleet)
    binding = mailbox.current_binding(endpoint)
    delivery = str(fleet.base / "delivery")
    unread = mailbox.endpoint_delivery(delivery, endpoint, mailbox.messages())[1]["unread"]
    started = {"endpoint": endpoint, "host": binding["host"], "session": binding["session"],
               "generation": binding["generation"], "message_ids": unread if carried is None else list(carried),
               "wake_id": "wake-" + uuid.uuid4().hex, "state": "started", "at": hierarchy_mailbox.timestamp()}
    mailbox.write_delivery_receipt(delivery, "wakes", started)
    if read:
        reads(fleet, endpoint, read)
    return started


def reads(fleet, endpoint, identifiers):
    """The adapter's read receipt for the endpoint's current binding, stamped now."""
    mailbox = mailbox_api(fleet)
    binding = mailbox.current_binding(endpoint)
    mailbox.record_read(str(fleet.base / "delivery"), {"from": endpoint, "host": binding["host"],
                                                       "session": binding["session"],
                                                       "binding_generation": binding["generation"]}, list(identifiers))


def turn_ends(fleet, started, state="exited"):
    import hierarchy_mailbox

    finished = {**started, "state": state, "exit_code": 0 if state == "exited" else None,
                "timed_out": state == "timed_out", "at": hierarchy_mailbox.timestamp()}
    mailbox_api(fleet).write_delivery_receipt(str(fleet.base / "delivery"), "wakes", finished)
    return finished


@posix_only
def test_an_orchestrator_that_reads_a_route_and_publishes_nothing_is_a_silent_role(team):
    post(team, "pilot/router", "pilot/orchestrator", "route-1")

    result = team.sweep("--durable")

    [woken] = result["rows"]
    [row] = result["silent_roles"]
    assert {key: row[key] for key in ("initiative", "endpoint", "wake_id", "ended", "exit_code", "read")} == {
        "initiative": "pilot", "endpoint": "pilot/orchestrator", "wake_id": woken["wake_id"], "ended": "exited",
        "exit_code": 0, "read": [{"message_id": "route-1", "type": "info", "from": "pilot/router"}]}
    assert moment(row["started_at"]) <= moment(row["finished_at"])
    assert moment(row["started_at"]) <= moment(row["silent_since"]) <= moment(row["finished_at"])
    assert result["stalled_dispatches"] == []


@posix_only
def test_a_lane_that_reads_its_dispatch_and_publishes_nothing_is_a_silent_role(team):
    dispatch(team, "pilot/lane/f2", "work-1")

    result = team.sweep("--durable")

    assert [(row["endpoint"], row["read"]) for row in result["silent_roles"]] == [
        ("pilot/lane/f2", [{"message_id": "work-1", "type": "dispatch", "from": "pilot/orchestrator"}])]


@posix_only
def test_a_role_that_publishes_in_its_turn_is_not_silent(team):
    team.plan({"pilot/orchestrator": {"send": [{"message_id": "ask", "to": "pilot/front-door", "type": "info",
                                                "body": "On it."}]}})
    post(team, "pilot/router", "pilot/orchestrator", "route-1")

    result = team.sweep("--durable", expect=3)

    assert [(row["endpoint"], row["state"]) for row in result["rows"]] == [("pilot/orchestrator", "read")]
    assert result["silent_roles"] == []


@posix_only
@pytest.mark.parametrize("endpoint, silent", [("pilot/decider", True), ("pilot/router", False)])
def test_a_decider_that_reads_an_orchestrator_note_and_publishes_nothing_is_silent_but_the_router_is_exempt(
        team, endpoint, silent):
    post(team, "pilot/orchestrator", endpoint, "note-1")

    result = team.sweep("--durable")

    assert [(row["endpoint"], row["read"]) for row in result["rows"]] == [(endpoint, ["note-1"])]
    expected = [(endpoint, [{"message_id": "note-1", "type": "info", "from": "pilot/orchestrator"}])] if silent else []
    assert [(row["endpoint"], row["read"]) for row in result["silent_roles"]] == expected


@posix_only
def test_a_turn_still_running_or_with_no_finish_receipt_is_never_silent(team):
    dispatch(team, "pilot/lane/f2", "work-1")
    started = turn_starts(team, "pilot/lane/f2", read=["work-1"])

    assert team.sweep()["silent_roles"] == [], "no finish receipt: the turn may still be running"

    turn_ends(team, started)
    marker = team.root / ".wake-pilot%2Flane%2Ff2.lock"
    marker.write_text("fixture turn in progress")
    assert team.sweep()["silent_roles"] == [], "a held wake marker: a turn may still be running"

    marker.unlink()
    assert [row["wake_id"] for row in team.sweep()["silent_roles"]] == [started["wake_id"]]


@posix_only
def test_a_wake_that_carried_only_receipts_and_acknowledgments_is_not_silent_but_one_that_read_a_review_is(team, clock):
    # The Orchestrator's own mail predates the reads, so only the allow-list decides.
    clock(600)
    dispatch(team, "pilot/lane/review", "review-1")
    packet = team.base / "packet.md"
    packet.write_bytes(b"Run it.\n")
    post(team, "pilot/orchestrator", "pilot/root", "job-1", "job_request",
         brief={"path": str(packet), "sha256": hashlib.sha256(b"Run it.\n").hexdigest()})
    clock(590)
    turn_ends(team, turn_starts(team, "pilot/lane/review", read=["review-1"]))
    accept(team, "pilot/lane/review", "review-1")
    clock(580)
    post(team, "pilot/root", "pilot/orchestrator", "job-1-started", "job_receipt", in_reply_to="job-1",
         receipt={"state": "started"})
    clock(0)

    receipts = team.sweep("--durable", expect=3)

    assert [(row["endpoint"], row["read"]) for row in receipts["rows"]] == [
        ("pilot/orchestrator", ["review-1-accepted", "job-1-started"])]
    assert receipts["silent_roles"] == []

    answer(team, "pilot/lane/review", "review-1")
    reviewed = team.sweep("--durable", expect=3)

    assert [(row["endpoint"], row["read"]) for row in reviewed["silent_roles"]] == [
        ("pilot/orchestrator", [{"message_id": "review-1-answer", "type": "review", "from": "pilot/lane/review"}])]


@posix_only
@pytest.mark.parametrize("clear", ["publish", "wake"])
def test_only_a_later_publish_clears_a_silent_role(team, clear):
    post(team, "pilot/router", "pilot/orchestrator", "route-1")
    assert [row["endpoint"] for row in team.sweep("--durable")["silent_roles"]] == ["pilot/orchestrator"]

    if clear == "publish":
        post(team, "pilot/orchestrator", "pilot/front-door", "answer")
        result = team.sweep("--dry-run", expect=3)
    else:
        # A receipt-only turn does not answer the earlier routed work.
        post(team, "pilot/root", "pilot/orchestrator", "root-note")
        result = team.sweep("--durable")
        assert [(row["endpoint"], row["read"]) for row in result["rows"]] == [("pilot/orchestrator", ["root-note"])]

    assert [row["endpoint"] for row in result["silent_roles"]] == ([] if clear == "publish" else ["pilot/orchestrator"])


@posix_only
def test_a_background_turn_that_read_its_work_before_its_start_receipt_is_still_a_silent_role(team, clock):
    """A background wake records `started` only once its launcher returns, so its turn can read before that receipt."""
    lane = "pilot/lane/f2"
    clock(600)
    dispatch(team, lane, "work-1")
    clock(590)
    reads(team, lane, ["work-1"])
    clock(580)
    started = turn_starts(team, lane, carried=["work-1"])
    clock(570)
    turn_ends(team, started)
    clock(0)

    result = team.sweep()

    assert [(row["endpoint"], row["wake_id"], row["read"]) for row in result["silent_roles"]] == [
        (lane, started["wake_id"], [{"message_id": "work-1", "type": "dispatch", "from": "pilot/orchestrator"}])]


@posix_only
def test_a_background_turn_that_published_after_its_early_read_is_not_silent(team, clock):
    """A publish after the owed read answers it even when the wake start receipt is recorded later."""
    lane = "pilot/lane/f2"
    clock(600)
    dispatch(team, lane, "work-1")
    clock(590)
    reads(team, lane, ["work-1"])
    clock(588)
    accept(team, lane, "work-1")
    clock(580)
    turn_ends(team, turn_starts(team, lane, carried=["work-1"]))
    clock(0)

    assert team.sweep("--dry-run", expect=3)["silent_roles"] == []


@posix_only
def test_a_previous_unanswered_read_survives_the_next_receipt_only_wake(team, clock):
    lane = "pilot/lane/f2"
    clock(600)
    dispatch(team, lane, "work-1")
    clock(590)
    turn_ends(team, turn_starts(team, lane, read=["work-1"]))
    clock(580)
    # Not work a lane owes an answer to, so the next turn that reads only this is not silent.
    post(team, "pilot/orchestrator", lane, "note-1")
    clock(570)
    later = turn_starts(team, lane, read=["note-1"])
    clock(560)
    turn_ends(team, later)
    clock(0)

    assert [row["read"] for row in team.sweep()["silent_roles"]] == [
        [{"message_id": "work-1", "type": "dispatch", "from": "pilot/orchestrator"}]]


@posix_only
@pytest.mark.parametrize("lane", ["pilot/lane/f2", "pilot/lane/review"])
def test_a_lane_that_accepted_and_ended_its_turn_without_an_answer_is_stalled_until_it_answers(team, lane):
    dispatch(team, lane, "work-1")
    started = turn_starts(team, lane, read=["work-1"])
    accepted = accept(team, lane, "work-1")
    finished = turn_ends(team, started)

    # The Orchestrator's copy of the ack is unread, so a dry run leaves it for the assertion.
    result = team.sweep("--dry-run", expect=3)

    assert result["stalled_dispatches"] == [{
        "initiative": "pilot", "endpoint": lane, "wake_id": started["wake_id"], "finished_at": finished["at"],
        "dispatches": [{"dispatch": "work-1", "accepted": "work-1-accepted", "accepted_at": accepted["created_at"]}]}]
    assert result["silent_roles"] == [], "the acceptance was a publish"

    answer(team, lane, "work-1")
    assert team.sweep("--dry-run", expect=3)["stalled_dispatches"] == []


@posix_only
@pytest.mark.parametrize("then", ["mail_pending", "turn_running"])
def test_a_lane_with_mail_pending_a_turn_running_or_no_wake_since_it_accepted_is_not_stalled(team, then):
    lane = "pilot/lane/f2"
    dispatch(team, lane, "work-1")
    started = turn_starts(team, lane, read=["work-1"])
    if then != "accepted_after_its_last_wake":
        accept(team, lane, "work-1")
    turn_ends(team, started)
    if then == "accepted_after_its_last_wake":
        accept(team, lane, "work-1")
    elif then == "mail_pending":
        post(team, "pilot/orchestrator", lane, "follow-up")
    else:
        (team.root / ".wake-pilot%2Flane%2Ff2.lock").write_text("fixture turn in progress")

    assert team.sweep("--dry-run", expect=3)["stalled_dispatches"] == []


@posix_only
@pytest.mark.parametrize("has_old_wake", [False, True])
def test_an_accepted_dispatch_is_stalled_without_a_subsequent_wake_receipt(team, has_old_wake):
    lane = "pilot/lane/f2"
    dispatch(team, lane, "work-1")
    if has_old_wake:
        turn_ends(team, turn_starts(team, lane, read=["work-1"]))
    else:
        reads(team, lane, ["work-1"])
    accept(team, lane, "work-1")
    [row] = team.sweep("--dry-run", expect=3)["stalled_dispatches"]
    assert row["endpoint"] == lane
    assert row["dispatches"][0]["dispatch"] == "work-1"
    if not has_old_wake:
        assert row["wake_id"] is None and row["finished_at"] is None


@posix_only
@pytest.mark.parametrize("first_was_work", [False, True])
def test_a_publish_before_an_owed_read_does_not_answer_that_read(team, clock, first_was_work):
    endpoint = "pilot/orchestrator"
    clock(600)
    post(team, "pilot/router" if first_was_work else "pilot/root", endpoint, "first")
    clock(590)
    started = turn_starts(team, endpoint, read=["first"])
    post(team, endpoint, "pilot/root", "earlier-publish")
    clock(589)
    post(team, "pilot/router", endpoint, "next-work")
    clock(588)
    reads(team, endpoint, ["next-work"])
    clock(587)
    turn_ends(team, started)
    clock(0)
    [row] = team.sweep("--dry-run", expect=3)["silent_roles"]
    assert row["read"] == [{"message_id": "next-work", "type": "info", "from": "pilot/router"}]
    assert moment(row["silent_since"]) > moment(started["at"])
