"""Stop owns a host program naming the session, never a diagnostic naming the same UUID."""
import os
import json
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_launcher import (Launch, REVIEW, R2_STOP_TIMEOUT_SECONDS, R2Processes, R2Custody, R2CleanupError,
                                                       r2_map_present, R2Facade,
                                                       R2CleanupUnknown, R2_ACTOR_BOOTSTRAP, launcher_module,
                                                       r2_kernel_process, native_wait_fields, wait_until)
from tests.integration.test_hierarchy_launcher_hosts import Hosts
from tests.integration.test_hierarchy_mailbox import ROOT, git
from tests.integration.test_hierarchy_provision import worker_source_seed


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="these process argv tests need Linux")


def r33_retained_orphan(case, capsys):
    session = str(uuid.uuid4())
    case.bind("codex-cli", session)
    family = case.spawn(["codex", "exec", "resume", session], tree=True, ignore=True,
                        middle_argv=["python3", "intermediary.py"], worker_argv=["python3", "worker.py"])
    host, middle, worker = family["H"], family["M"], family["W"]
    module, captured = case.module(False), []
    census = module.process_census
    def cohort(session):
        rows = census(session)
        members = {child.pid for child in family.values()}
        rows = module.ProcessCensus([row for row in rows if row.pid in members], rows.argv_boundaries,
                                   {pid: row for pid, row in rows.unavailable.items() if pid in members})
        if not captured:
            captured.append(next(row for row in rows if row.pid == worker.pid))
        return rows
    def unreadable_worker(path, raw):
        if captured and str(path) == "/proc/%d/cmdline" % worker.pid:
            raise PermissionError("modelled worker loses command evidence after the initial census")
        return raw
    module.process_census = cohort
    case.projection.path_view(module, unreadable_worker)
    code, answer = case.stop(module, capsys, 0)
    assert code == 3 and worker.pid in answer["unresolved_pids"]
    assert host.wait(timeout=5) == -signal.SIGKILL
    wait_until(lambda: middle.poll() == "CONFIRMED_EXIT")
    assert worker.poll() is None and all(pid != worker.pid for pid, _ in case.projection.events)
    launches = module.Launches(str(case.launch.base))
    assert not (launches.folder(REVIEW) / ".running-wake").exists()
    path = launches.folder(REVIEW) / ".stop-custody" / "state.json"
    saved = json.loads(path.read_text())
    entry = next(entry for entry in saved["entries"] if entry["pid"] == worker.pid)
    assert saved["active"] and entry["snapshot"] is not None and not entry["resolved"]
    return worker, path, saved


@pytest.mark.parametrize("mutation", ["changed-birth", "birthless-esrch"])
def test_r33_terminal_journal_claim_cannot_release_a_live_orphan(r2_case, capsys, mutation):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for
    worker, path, saved = r33_retained_orphan(r2_case, capsys)
    entry = next(entry for entry in saved["entries"] if entry["pid"] == worker.pid)
    entry["resolved"] = "matching_birth_zombie"
    if mutation == "changed-birth":
        entry["snapshot"]["start_time"] = str(int(entry["snapshot"]["start_time"]) - 1)
    else:
        entry.update(snapshot=None, partial={}, attempted=False, resolved="qualified_namespace_ESRCH")
    saved.update(active=False, groups=[])
    path.write_text(json.dumps(saved))
    before, effects, binding = path.read_bytes(), list(r2_case.projection.events), r2_case.launch.binding()
    module = r2_case.module(False)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed", "terminal journal released a live orphan"
    assert "resolved stop custody lacks physical exit proof" in answer["error"]
    assert "manual reconciliation" in answer["error"]
    assert path.read_bytes() == before and worker.poll() is None and r2_case.projection.events == effects
    control = handoff_module()
    control.hierarchy_launcher = module
    result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
    assert "manual reconciliation" in result["error"]
    assert r2_case.launch.binding() == binding and worker.poll() is None
    assert path.read_bytes() == before and r2_case.projection.events == effects
    slot = next(slot for slot, owned in r2_case.custody.entries.items() if owned["pid"] == worker.pid)
    r2_case.custody.kill_owned(slot)
    wait_until(lambda: worker.poll() == "CONFIRMED_EXIT")
    assert r2_case.stop(r2_case.module(False), capsys, 0)[0] == 0
    control.hierarchy_launcher = r2_case.module(False)
    assert run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 0)["entries"][0]["generation"] == 2


@pytest.mark.parametrize("entry_kind", ["snapshot", "partial"])
@pytest.mark.parametrize("physical", ["absent", "zombie", "exit-observed"])
def test_r33_terminal_custody_requires_current_honest_exit_proof(r2_case, capsys, entry_kind, physical):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    entry = saved["entries"][0]
    if entry_kind == "partial":
        facts = entry["snapshot"]
        entry.update(snapshot=None, attempted=False, partial=dict(start_time=facts["start_time"],
            uid=facts["uid"], euid=facts["euid"], coherent_birth=True), resolved="matching_partial_birth_zombie")
    else:
        entry["resolved"] = "matching_birth_zombie"
    saved.update(active=False, groups=[])
    path.write_text(json.dumps(saved))
    before, effects = path.read_bytes(), list(r2_case.projection.events)
    r2_case.configs[0].with_suffix(".exit").touch()
    if physical == "absent":
        assert held.wait(timeout=5) == 0
    else:
        wait_until(lambda: r2_kernel_process(held.pid)["state"].startswith("Z"))
    module = r2_case.module(False)
    observed = []
    if physical == "exit-observed":
        def unreadable(path, raw):
            if str(path) == "/proc/%d/cmdline" % held.pid:
                observed.append(True)
                raise PermissionError("modelled unreadable command on a real exited original instance")
            return raw
        r2_case.projection.path_view(module, unreadable)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "not_running"
    assert path.read_bytes() == before and r2_case.projection.events == effects
    assert observed or physical != "exit-observed"
    control = handoff_module()
    control.hierarchy_launcher = module
    assert run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 0)["entries"][0]["generation"] == 2
    assert held.wait(timeout=5) == 0


@pytest.mark.parametrize("mutation", ["changed-birth", "birthless-esrch"])
@pytest.mark.parametrize("recheck", ["restore", "unproven"])
def test_r33_terminal_claim_changed_during_recovery_keeps_prior_attempts(r2_case, capsys, monkeypatch,
                                                                      mutation, recheck):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    module, reads, changed = r2_case.module(False), [], []
    if recheck == "unproven":
        monkeypatch.setattr(module, "process_census", lambda session: module.ProcessCensus([], "unproven"))
    opening = module.os.open
    def opened(name, flags, *args, **kwargs):
        if name == "state.json" and not flags & (os.O_WRONLY | os.O_RDWR):
            reads.append(True)
            if len(reads) == 2:
                entry = saved["entries"][0]
                saved.update(active=False, groups=[])
                if mutation == "changed-birth":
                    entry["snapshot"]["start_time"] = str(int(entry["snapshot"]["start_time"]) - 1)
                    entry["resolved"] = "matching_birth_zombie"
                else:
                    entry.update(snapshot=None, partial={}, attempted=False, resolved="qualified_namespace_ESRCH")
                path.write_text(json.dumps(saved))
                changed.append(path.read_bytes())
        return opening(name, flags, *args, **kwargs)
    monkeypatch.setattr(module.os, "open", opened)
    effects = list(r2_case.projection.events)
    code, answer = r2_case.stop(module, capsys, 0)
    assert changed and code == 3 and answer["state"] == "stop_failed"
    assert answer["pids"] == [held.pid], "a later journal edit erased the attempts already read at admission"
    assert "manual reconciliation" in answer["error"]
    assert path.read_bytes() == changed[0] and held.poll() is None and r2_case.projection.events == effects


@pytest.mark.parametrize("fault", ["unknown", "blocked"])
@pytest.mark.parametrize("recovered", [False, True])
def test_r32_argon_exact_unverified_root_never_authorizes_worker(r2_case, capsys, fault, recovered):
    """MODELLED Argon PIDs/OS view only; no syscall can deliver a signal to these numeric inputs."""
    session = "11111111-1111-4111-8111-111111111111"
    r2_case.bind("codex-cli", session)
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    argv = ("codex", "exec", "resume", session)
    host = module.ProcessSnapshot(410001, 410001, "S", os.geteuid(), "200",
                                   b"\0".join(word.encode() for word in argv) + b"\0", argv, 1, os.geteuid())
    worker = module.ProcessSnapshot(410002, 410001, "S", os.geteuid(), "300",
                                     b"worker\0", ("worker",), 410001, os.geteuid())
    snapshot = (module.StopCustody.encode(module.process_identity(host._replace(start_time="100"))._asdict())
                if fault == "blocked" else None)
    module.publish_wake_record(launches, REVIEW, dict(schema="aegis.hierarchy-running-wake/v3", binding=known,
        wake_id="wake-" + uuid.uuid4().hex, driver_pid=os.getpid(), host_pid=host.pid, snapshot=snapshot,
        pid_namespace=module.current_pid_namespace()))
    if recovered:
        root = dict(pid=host.pid, snapshot=None, partial=snapshot or {}, attempted=False,
                    blocked=fault == "blocked", identity_lost=fault == "blocked", resolved=None)
        child = dict(pid=worker.pid, snapshot=module.StopCustody.encode(worker._asdict()), partial={},
                     attempted=True, blocked=False, identity_lost=False, resolved=None)
        with module.StopCustody(launches, REVIEW, known) as custody:
            custody.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            custody.path.write_text(json.dumps(dict(schema="aegis.hierarchy-stop-custody/v2", binding=known,
                boot=module.StopCustody.boot(), pid_namespace=module.current_pid_namespace(), active=True,
                entries=[root, child], groups=[host.pgid], coverage=None)))
            custody.path.chmod(0o600)
    module.ancestors = lambda: set()  # MODELLED census has no caller ancestors, irrespective of real PID reuse.
    module.process_census = lambda session: module.ProcessCensus([host, worker], "proven")
    module.read_process = lambda pid, *args: module.ProcessObservation("PRESENT", pid,
                                                                        {host.pid: host, worker.pid: worker}[pid])
    signals = []
    def kill(pid, number):
        if number:
            signals.append((pid, number))  # Record only: never call the real kill with modelled PIDs.
    module.os.kill = kill
    module.os.killpg = kill
    code, answer = r2_case.stop(module, capsys, 0)
    assert not signals, "unverified root authorized a modelled worker signal"
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["error"] == ("stop owning chain is unverified; preserve custody, stop the host and descendants "
        "manually, and have the owner reconcile this endpoint before retrying")
    assert answer["pids"] == ([worker.pid] if recovered else [])
    path = launches.folder(REVIEW) / ".stop-custody" / "state.json"
    journal = json.loads(path.read_text())
    root = next(entry for entry in journal["entries"] if entry["pid"] == host.pid)
    assert journal["active"] and root["snapshot"] is None and root["blocked"] is (fault == "blocked")
    assert launches.binding(REVIEW)["session"] == session


@pytest.mark.parametrize("fault", ["unknown", "blocked"])
def test_r32_physical_descendants_stay_live_below_unverified_root(r2_case, capsys, fault):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    family = r2_case.spawn(["codex", "exec", "resume", session], tree=True, ignore=True)
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    host = family["H"]
    row = module.read_process(host.pid).snapshot
    original = row._replace(start_time=str(int(row.start_time) + 1))
    snapshot = module.StopCustody.encode(module.process_identity(original)._asdict()) if fault == "blocked" else None
    record = dict(schema="aegis.hierarchy-running-wake/v3", binding=known, wake_id="wake-" + uuid.uuid4().hex,
                  driver_pid=os.getpid(), host_pid=host.pid, snapshot=snapshot,
                  pid_namespace=module.current_pid_namespace())
    module.publish_wake_record(launches, REVIEW, record)
    for _ in range(2):
        code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
        assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
        assert answer["error"] == ("stop owning chain is unverified; preserve custody, stop the host and descendants "
            "manually, and have the owner reconcile this endpoint before retrying")
        assert not r2_case.projection.events and all(child.poll() is None for child in family.values())
        assert module.read_running_wake(launches.base, REVIEW) == record
        journal = json.loads((launches.folder(REVIEW) / ".stop-custody" / "state.json").read_text())
        assert journal["active"] and any(entry["pid"] == host.pid and entry["snapshot"] is None
                                          for entry in journal["entries"])


@pytest.mark.parametrize("fault", ["unknown", "blocked"])
def test_r32_intermediate_ancestor_cannot_authorize_a_later_worker(r2_case, capsys, fault):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True, ignore=True)
    host, middle, worker = family["H"], family["M"], family["W"]
    module, changed = r2_case.module(False), []
    if fault == "unknown":
        def missing(path, raw):
            if str(path) == "/proc/%d/status" % middle.pid and not changed:
                changed.append(True)
                return b"\n".join(line for line in raw.splitlines() if not line.startswith(b"Uid:"))
            return raw
        r2_case.projection.path_view(module, missing)
    else:
        census = module.process_census
        def initially_missing_worker(session):
            rows = census(session)
            return module.ProcessCensus([row for row in rows if row.pid != worker.pid or changed],
                                         rows.argv_boundaries,
                                         {pid: row for pid, row in rows.unavailable.items() if pid != worker.pid})
        module.process_census = initially_missing_worker
        def changed_once(pid, count, row):
            if pid == middle.pid and count == 2:
                changed.append(True)
                return row._replace(start_time=str(int(row.start_time) + 1))
            return row
        r2_case.projection.after_present.append(changed_once)
    code, answer = r2_case.stop(module, capsys, 0)
    assert changed and code == 3 and answer["state"] == "stop_failed"
    assert answer["error"] == ("stop owning chain is unverified; preserve custody, stop the host and descendants "
        "manually, and have the owner reconcile this endpoint before retrying")
    assert middle.poll() is None and worker.poll() is None
    assert all(pid == host.pid for pid, _ in r2_case.projection.events)
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    journal = json.loads(path.read_text())
    entry = next(entry for entry in journal["entries"] if entry["pid"] == middle.pid)
    assert journal["active"] and entry["blocked"] is (fault == "blocked")
    assert (entry["snapshot"] is None) is (fault == "unknown")


@pytest.mark.parametrize("publication", [False, True])
@pytest.mark.parametrize("unread,dry_run", [(False, False), (False, True), (True, True), (True, False)])
def test_r32_no_namespace_preserves_no_launch_resume_results(r2_case, capsys, monkeypatch, unread, dry_run,
                                                            publication):
    from types import SimpleNamespace

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    if unread:
        r2_case.launch.publish_to(REVIEW, "r32-unread")
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    binding = launches.binding(REVIEW)
    assert not (launches.base / "host-plan.json").exists()
    loading, running, operations, probes = module.load_wake, module.subprocess.run, [], []
    def unavailable():
        probes.append(True)
        return None
    def forbidden(*args, **kwargs):
        operations.append(args)
        pytest.fail("unqualified resume performed a process operation")
    def loaded(launches):
        wake = loading(launches)
        wake.subprocess = R2Facade(wake.subprocess, run=forbidden, Popen=forbidden)
        return wake
    def external(command, **options):
        if "_resume-wake" in command:
            code, answer = module.admitted_wake(module.Launches(str(launches.base)), REVIEW,
                options["pass_fds"][0], str(r2_case.launch.source / "tools/hierarchy_wake.py"), dry_run,
                command[command.index("--admission-namespace") + 1])
            return SimpleNamespace(returncode=code, stdout=json.dumps(answer))
        return running(command, **options)
    monkeypatch.setattr(module, "pid_namespace_probe", unavailable)
    monkeypatch.setattr(module, "running_wake_publication_capable", lambda: publication)
    monkeypatch.setattr(module, "load_wake", loaded)
    module.subprocess = R2Facade(module.subprocess, run=external)
    argv = ["--base", str(launches.base), "resume", "--endpoint", REVIEW]
    code = module.main(argv + (["--dry-run"] if dry_run else []))
    answer = json.loads(capsys.readouterr().out)
    if unread and not dry_run:
        assert code == 2 and answer["state"] == "refused"
        assert answer["error"] == (module.PID_NAMESPACE_REFUSAL if publication else
                                    "running wake atomic publication unsupported on this platform")
    else:
        assert code == 0 and answer["state"] == "resumed"
        assert answer["wake"] == dict(state="dry_run" if unread else "nothing_unread",
                                      wake_id=None, exit_code=None, timed_out=None)
        assert answer["wake_exit_code"] == 0 and answer["dry_run"] is dry_run
        admission = module.read_resume_admission(launches.base, REVIEW, launches.paths(REVIEW)[-1].stem)
        assert admission["admission_attempted"] is False
    assert not operations and launches.binding(REVIEW) == binding
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert not launches.mailbox.wake_marker(REVIEW).exists()
    assert not (launches.folder(REVIEW) / ".stop-custody").exists()
    assert not r2_case.launch.host_log.exists()


@pytest.mark.parametrize("error", ["ENFILE", "EMFILE", "ENOMEM"])
@pytest.mark.parametrize("stage", ["root", "ancestor", "escalation"])
@pytest.mark.skipif(not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"),
                    reason="pidfd APIs unavailable")
def test_r32_transient_pidfd_failure_keeps_custody_without_numeric_delivery(r2_case, capsys, monkeypatch,
                                                                          error, stage):
    import errno
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], ignore=True, tree=stage == "ancestor")
    host, target = (family["H"], family["M"]) if stage == "ancestor" else (family, family)
    module = r2_case.module()
    # Use the real fixture's instance-safe pidfd path when it is not the injected failure.
    opening = module.os.pidfd_open
    failed, descriptors = [], []
    def opened(pid):
        if stage == "escalation" and not r2_case.projection.events:
            raise OSError(errno.ENOSYS, "modelled kernel without pidfds at the first TERM")
        if pid == target.pid:
            failed.append(pid)
            raise OSError(getattr(errno, error), "UNTRUSTED\nresource failure")
        descriptor = opening(pid)
        descriptors.append(descriptor)
        return descriptor
    monkeypatch.setattr(module.os, "pidfd_open", opened)
    code, answer = r2_case.stop(module, capsys, 0)
    assert failed and code == 3 and answer["state"] == "stop_failed"
    assert answer["error"] == ("stop could not obtain a safe process handle; preserve custody, restore "
        "pidfd availability and retry stop, or stop the host manually and have the owner reconcile this endpoint")
    expected = [(host.pid, signal.SIGTERM)] if stage == "escalation" else []
    assert r2_case.projection.events == expected
    assert answer["pids"] == ([host.pid] if stage == "escalation" else [])
    assert host.poll() is None and target.poll() is None
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    journal = json.loads(path.read_text())
    assert journal["active"] and any(entry["pid"] == target.pid and not entry["resolved"]
                                      for entry in journal["entries"])
    for descriptor in descriptors:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    if stage == "root":
        monkeypatch.setattr(module.os, "pidfd_open", opening)
        assert r2_case.stop(module, capsys, 0)[0] == 0
        assert host.wait(timeout=5) == -signal.SIGKILL
        assert not json.loads(path.read_text())["active"]


@pytest.mark.parametrize("missing", ["open", "send"])
@pytest.mark.skipif(not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"),
                    reason="pidfd APIs unavailable")
def test_r32_numeric_delivery_requires_established_pidfd_absence(r2_case, capsys, missing):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    actor = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module()
    class WithoutPidfd(R2Facade):
        def __getattr__(self, name):
            if name == ("pidfd_open" if missing == "open" else "pidfd_send_signal"):
                raise AttributeError(name)
            return super().__getattr__(name)
    if missing == "open":
        module.os = WithoutPidfd(module.os)
    else:
        module.signal = WithoutPidfd(module.signal)
    code, answer = r2_case.stop(module, capsys, 0)
    if missing == "open":
        assert code == 0 and answer["pids"] == [actor.pid]
        assert actor.wait(timeout=5) == -signal.SIGTERM
    else:
        assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
        assert actor.poll() is None and r2_case.projection.events == []
        assert answer["error"] == ("stop could not obtain a safe process handle; preserve custody, restore "
            "pidfd availability and retry stop, or stop the host manually and have the owner reconcile this endpoint")


@pytest.mark.parametrize("error", ["ENFILE", "EMFILE", "ENOMEM"])
@pytest.mark.skipif(not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"),
                    reason="pidfd APIs unavailable")
def test_r32_pidfd_delivery_errors_keep_fixed_refusal_and_custody(r2_case, capsys, monkeypatch, error):
    import errno
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    actor = r2_case.spawn(["claude", "--resume", session])
    module, calls = r2_case.module(), []
    def denied(descriptor, number):
        calls.append((descriptor, number))
        raise OSError(getattr(errno, error), "UNTRUSTED\nresource failure")
    monkeypatch.setattr(module.signal, "pidfd_send_signal", denied)
    code, answer = r2_case.stop(module, capsys, 0)
    assert calls and code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [actor.pid]
    assert answer["error"] == ("stop could not obtain a safe process handle; preserve custody, restore "
        "pidfd availability and retry stop, or stop the host manually and have the owner reconcile this endpoint")
    assert actor.poll() is None and r2_case.projection.events == []
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert json.loads(path.read_text())["active"]


@pytest.mark.parametrize("retained", ["empty", "live", "running", "custody", "both"])
def test_r32_no_namespace_refuses_every_stop_state(r2_case, capsys, monkeypatch, retained):
    if retained in ("custody", "both"):
        actor, _, _ = r7_pending_attempt(r2_case, capsys)
    else:
        session = str(uuid.uuid4())
        r2_case.bind("codex-cli", session)
        actor = r2_case.spawn(["codex", "exec", "resume", session]) if retained != "empty" else None
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    binding = launches.binding(REVIEW)
    if retained in ("running", "both"):
        module.write_running_wake(launches, REVIEW, module.binding_identity(binding),
                                  "wake-" + uuid.uuid4().hex, actor.pid)
    folder = launches.folder(REVIEW)
    evidence = {path: path.read_bytes() if path.exists() else None for path in
                (folder / ".running-wake", folder / ".stop-custody" / "state.json")}
    effects = list(r2_case.projection.events)
    monkeypatch.setattr(module, "pid_namespace_probe", lambda: None)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["error"] == module.PID_NAMESPACE_REFUSAL
    assert answer["pids"] == ([actor.pid] if retained in ("custody", "both") else [])
    assert r2_case.projection.events == effects and launches.binding(REVIEW) == binding
    assert actor is None or actor.poll() is None
    assert all((path.read_bytes() if path.exists() else None) == before for path, before in evidence.items())


def test_r31_probe_rejects_ancestor_procfs_even_with_the_same_numeric_pid(r2_case):
    module = r2_case.module(False)
    opening, reading, status, served = module.os.open, module.os.read, [], []
    def capture(path, *args, **kwargs):
        descriptor = opening(path, *args, **kwargs)
        if path == "status":
            status.append(descriptor)
        return descriptor
    def read(descriptor, limit):
        if descriptor in status:
            if served:
                return b""
            served.append(True)
            return ("Name: fixture\nNSpid:\t%d\t%d\n" % (os.getpid(), os.getpid())).encode("ascii")
        return reading(descriptor, limit)
    module.os = R2Facade(module.os, open=capture, read=read)
    assert module.pid_namespace_probe() is None
    assert served


def r31_namespace_switch(module, monkeypatch):
    original = module.pid_namespace_probe()
    assert original is not None
    changed = []
    def probe():
        return {**original, "inode": original["inode"] + bool(changed)}
    monkeypatch.setattr(module, "pid_namespace_probe", probe)
    return changed


@pytest.mark.parametrize("site", ["checkpoint", pytest.param("pidfd", marks=pytest.mark.skipif(
    not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"), reason="pidfd APIs unavailable"))])
def test_r31_late_namespace_loss_refuses_before_signal(r2_case, capsys, monkeypatch, site):
    import errno
    actor, path, _ = r7_pending_attempt(r2_case, capsys)
    module = r2_case.module(site == "pidfd")
    changed = r31_namespace_switch(module, monkeypatch)
    before = list(r2_case.projection.events)
    if site == "checkpoint":
        save = module.StopCustody.save
        def saved(self, *args, **kwargs):
            result = save(self, *args, **kwargs)
            changed.append(True)
            return result
        monkeypatch.setattr(module.StopCustody, "save", saved)
    else:
        def opened(*args, **kwargs):
            changed.append(True)
            raise OSError(errno.ESRCH, "modelled namespace changed at pidfd open")
        module.os.pidfd_open = opened
    code, answer = r2_case.stop(module, capsys, 0)
    assert changed and code == 3 and answer["state"] == "stop_failed"
    assert answer["error"] == module.PID_NAMESPACE_REFUSAL
    assert json.loads(path.read_text())["active"] and actor.poll() is None
    assert r2_case.projection.events == before


@pytest.mark.parametrize("site", ["group", "process"])
def test_r31_syscall_esrch_after_namespace_loss_is_not_exit_evidence(r2_case, monkeypatch, site):
    import errno
    module = r2_case.module(False)
    changed = r31_namespace_switch(module, monkeypatch)
    def absent(pid, number):
        assert number == 0
        changed.append(True)
        raise ProcessLookupError(errno.ESRCH, "modelled absence in another namespace")
    if site == "group":
        module.os.killpg = absent
        with pytest.raises(ValueError, match="^" + module.PID_NAMESPACE_REFUSAL + "$"):
            module.process_group_exited(400001, module.current_pid_namespace())
    else:
        module.os.kill = absent
        result = module.process_existence(400001, "modelled metadata unavailable")
        assert result.kind == "UNAVAILABLE" and result.proof == "pid_namespace_unavailable"
    assert changed


def test_r31_new_records_keep_origin_through_same_namespace_retirement(r2_case, capsys):
    actor, path, _ = r7_pending_attempt(r2_case, capsys)
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    origin = module.current_pid_namespace()
    assert origin is not None and json.loads(path.read_text())["pid_namespace"] == origin
    assert origin["boot"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    record = module.write_running_wake(launches, REVIEW, module.binding_identity(launches.binding(REVIEW)),
                                       "wake-" + uuid.uuid4().hex, actor.pid)
    assert record["schema"] == "aegis.hierarchy-running-wake/v3" and record["pid_namespace"] == origin
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert actor.wait(timeout=5) == 0
    assert r2_case.stop(module, capsys, 0)[0] == 0
    saved = json.loads(path.read_text())
    assert saved["pid_namespace"] == origin and not saved["active"]
    assert module.read_running_wake(launches.base, REVIEW) is None


@pytest.mark.parametrize("fault", ["process", "ns", "identity", "boot"])
def test_r31_namespace_probe_closes_every_descriptor_on_failure(r2_case, monkeypatch, fault):
    import errno
    module = r2_case.module(False)
    opening, stating, reading, opened, names = module.os.open, module.os.stat, module.os.read, [], {}
    def capture(path, *args, **kwargs):
        if str(path) == (str(os.getpid()) if fault == "process" else "ns" if fault == "ns" else "never"):
            raise OSError(errno.EIO, "modelled procfs open failure")
        descriptor = opening(path, *args, **kwargs)
        opened.append(descriptor)
        names[descriptor] = path
        return descriptor
    def stat(path, *args, **kwargs):
        if fault == "identity" and path == "pid":
            raise OSError(errno.EIO, "modelled namespace stat failure")
        return stating(path, *args, **kwargs)
    def read(descriptor, limit):
        if fault == "boot" and names.get(descriptor) == "boot_id":
            raise OSError(errno.EIO, "modelled boot read failure")
        return reading(descriptor, limit)
    module.os = R2Facade(module.os, open=capture, stat=stat, read=read)
    assert module.pid_namespace_probe() is None and opened
    for descriptor in opened:
        with pytest.raises(OSError) as error:
            os.fstat(descriptor)
        assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("record_kind", ["custody", "running"])
@pytest.mark.parametrize("fault", ["different", "unreadable", "procfs", "unqualified", "boot"])
def test_r31_namespace_refusal_preserves_live_custody_and_consumers(r2_case, capsys, monkeypatch, record_kind, fault):
    import errno
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    held, custody_path, saved = r7_pending_attempt(r2_case, capsys)
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    if record_kind == "running":
        module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, held.pid)
    target = custody_path if record_kind == "custody" else launches.folder(REVIEW) / ".running-wake"
    if fault == "unqualified":
        data = json.loads(target.read_text())
        data.pop("pid_namespace", None)
        target.write_text(json.dumps(data))
    before, binding, effects = custody_path.read_bytes(), launches.binding(REVIEW), list(r2_case.projection.events)
    running = (launches.folder(REVIEW) / ".running-wake")
    running_bytes = running.read_bytes() if running.exists() else None
    namespace = os.stat("/proc/self/ns/pid")
    probe = dict(module.pid_namespace_probe())
    assert (probe["device"], probe["inode"], probe["procfs_pid"]) == (namespace.st_dev, namespace.st_ino, os.getpid())
    if fault == "different":
        probe["inode"] += 1
    elif fault == "procfs":
        probe["procfs_pid"] += 1
    elif fault == "boot":
        probe["boot"] = "00000000-0000-0000-0000-000000000000"
    monkeypatch.setattr(module, "pid_namespace_probe", lambda: None if fault == "unreadable" else probe)
    # MODELLED B's syscall/proc view: P and G are absent there although the original A child is live.
    module.process_census = lambda session: module.ProcessCensus([], "proven")
    module.read_process = lambda pid, *args: module.ProcessObservation("CONFIRMED_ABSENT", pid,
                                                       proof="qualified_namespace_ESRCH")
    def absent(group, number):
        assert number == 0, "namespace mismatch must never signal a group"
        raise ProcessLookupError(errno.ESRCH, "modelled foreign namespace group absence")
    module.os.killpg = absent
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed", "foreign namespace falsely discharged the live writer"
    assert answer["pids"] == [held.pid], "namespace refusal must retain prior attempt accounting"
    assert answer["error"] == ("stop unsupported without matching PID namespace and caller procfs view; "
        "preserve custody, stop the host manually in its original PID namespace, and have the owner "
        "reconcile this endpoint before retrying")
    assert custody_path.read_bytes() == before and json.loads(before)["active"]
    assert r2_case.projection.events == effects and held.poll() is None
    assert (running.read_bytes() if running.exists() else None) == running_bytes
    control = handoff_module()
    control.hierarchy_launcher = module
    run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
    assert launches.binding(REVIEW) == binding and held.poll() is None
    probe_scope, plan, cleanup = r23_cleanup_scope(r2_case, module)
    try:
        assert cleanup.main(["cleanup", "--probe-root", str(probe_scope.root)]) == 3
        result = json.loads(capsys.readouterr().out)["cleanup"]
        assert not result["worktree_removed"] and Path(plan["worktree"]).is_dir()
        assert launches.binding(REVIEW) == binding and custody_path.read_bytes() == before
        assert r2_case.projection.events == effects and held.poll() is None
    finally:
        probe_scope.close()


@pytest.mark.parametrize("version", [1, 2, 3])
@pytest.mark.parametrize("alive", [False, True])
def test_r31_unqualified_running_wake_is_readable_but_never_retired(r2_case, capsys, version, alive):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    actor = r2_case.spawn(None)
    if not alive:
        r2_case.configs[-1].with_suffix(".exit").touch()
        assert actor.wait(timeout=5) == 0
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    record = dict(schema="aegis.hierarchy-running-wake/v%d" % version,
                  binding=module.binding_identity(launches.binding(REVIEW)), wake_id="wake-" + uuid.uuid4().hex,
                  driver_pid=os.getpid(), host_pid=None if version == 2 else actor.pid, snapshot=None)
    module.publish_wake_record(launches, REVIEW, record)
    path = launches.folder(REVIEW) / ".running-wake"
    before = path.read_bytes()
    assert module.read_running_wake(launches.base, REVIEW) == record
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["error"] == ("stop unsupported without matching PID namespace and caller procfs view; "
        "preserve custody, stop the host manually in its original PID namespace, and have the owner "
        "reconcile this endpoint before retrying")
    assert path.read_bytes() == before and not r2_case.projection.events
    assert (actor.poll() is None) is alive


@pytest.mark.parametrize("lookup", ["relative", "empty", "child-env", "missing"])
def test_r30_resume_uses_the_real_spawns_cwd_and_path(r2_case, capsys, monkeypatch, lookup):
    import shutil
    from types import SimpleNamespace
    from tests.conftest import symlink_or_skip

    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    r2_case.launch.publish_to(REVIEW, "r30-real-path-lookup")
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    assert not (launches.base / "host-plan.json").exists()
    support = r2_case.launch.tmp / "r30-support"
    support.mkdir()
    for name in ("git", "ps"):
        program = shutil.which(name)
        assert program is not None
        symlink_or_skip(program, support / name)
    assert shutil.which("codex", path=str(support)) is None
    cwd = r2_case.launch.tmp / "r30-child"
    cwd.mkdir()
    directory = cwd if lookup == "empty" else cwd / "bin"
    directory.mkdir(exist_ok=True)
    executable = directory / "codex"
    ready, finish = cwd / "executed.json", cwd / "finish"
    if lookup != "missing":
        executable.write_text("#!" + sys.executable + "\n" + '''import json,os,runpy,sys,time
from pathlib import Path
configuration=json.loads(Path(os.environ["R2_LEGACY_CONFIG"]).read_text())
runpy.run_path(configuration["helper"])["r2_legacy_child_gate"](configuration,os.environ["R2_LEGACY_SLOT"])
Path(os.environ["R30_READY"]).write_text(json.dumps({"pid":os.getpid(),"cwd":os.getcwd(),"executable":str(Path(sys.argv[0]).resolve())}))
deadline=time.monotonic()+10
while not Path(os.environ["R30_FINISH"]).exists():
    if time.monotonic()>=deadline: raise RuntimeError("fixture parent did not release the completed executable")
    time.sleep(0.01)
''')
        executable.chmod(0o700)
    path = ("" if lookup == "empty" else "bin") + os.pathsep + str(support)
    monkeypatch.setenv("PATH", str(support) if lookup == "child-env" else path)
    _, profile_path = module.bound_session(launches, REVIEW, launches.new_id(), "resume")
    profile = json.loads(profile_path.read_text())
    profile.update(cwd=str(cwd), argv=["codex", "exec", "resume", session], prompt_via="argv")
    profile_path.write_text(json.dumps(profile))
    actors, attempted, released, identities = [], [], [], []
    loading, publishing, reading = module.load_wake, module.publish_wake_record, module.read_process
    native = launcher_module().read_process
    slot = "actor0-path"
    config = (r2_case.make_config({slot: {"kind": "H", "parent": None, "child": None}})
              if lookup != "missing" else None)
    def loaded(launches):
        wake = loading(launches)
        def popen(argv, **options):
            attempted.append(list(argv))
            assert argv[:-1] == profile["argv"] and options["cwd"] == str(cwd)
            environment = {**r2_case.env, "PATH": path, "R30_READY": str(ready), "R30_FINISH": str(finish)}
            if lookup == "missing":
                # Actual exec failure: no fixture creation permit or child may be manufactured.
                return subprocess.Popen(argv, **options, env=environment)
            environment.update(R2_LEGACY_CONFIG=config["config"], R2_LEGACY_SLOT=slot)
            process = r2_case.custody.launch(config, slot, environment, argv=argv, cwd=options["cwd"],
                stdin=options["stdin"], stdout=options["stdout"], stderr=options["stderr"])
            r2_case.children.append(process)
            actors.append(process)
            r2_case.custody.await_event(slot, "hello")
            r2_case.projection.pending(process)
            return process
        wake.subprocess = R2Facade(subprocess, Popen=popen)
        class Paths(type(Path())):
            @classmethod
            def home(cls):
                return r2_case.home
        wake.Path = Paths
        return wake
    def observe(pid, *args):
        return native(pid, *args) if actors and pid == actors[0].pid and not released else reading(pid, *args)
    def publish(launches, endpoint, record, **options):
        result = publishing(launches, endpoint, record, **options)
        if record["host_pid"] is not None:
            identities.append(record)
            r2_case.custody.release(slot)
            r2_case.custody.await_event(slot, "running")
            wait_until(ready.exists)
            r2_case.projection.ready(actors[0], profile["argv"])
            released.append(True)
            finish.touch()
        return result
    monkeypatch.setattr(module, "load_wake", loaded)
    monkeypatch.setattr(module, "read_process", observe)
    monkeypatch.setattr(module, "publish_wake_record", publish)
    running = module.subprocess.run
    def external(command, **options):
        if "_resume-wake" in command:
            code, answer = module.admitted_wake(module.Launches(str(launches.base)), REVIEW,
                options["pass_fds"][0], str(r2_case.launch.source / "tools/hierarchy_wake.py"), False,
                command[command.index("--admission-namespace") + 1])
            return SimpleNamespace(returncode=code, stdout=json.dumps(answer))
        return running(command, **options)
    module.subprocess = R2Facade(module.subprocess, run=external)
    assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW]) == 3
    answer = json.loads(capsys.readouterr().out)
    assert attempted, "the real spawn was blocked by executable preflight"
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert not launches.mailbox.wake_marker(REVIEW).exists()
    assert not module.unresolved_stop_custody(str(launches.base), REVIEW)
    assert not (launches.folder(REVIEW) / ".stop-custody").exists()
    admission = module.read_resume_admission(launches.base, REVIEW, launches.paths(REVIEW)[-1].stem)
    if lookup == "missing":
        assert answer["wake"]["state"] == "failed_to_start" and not actors and not identities
        assert admission["admission_attempted"] is False and admission["failure"] == "host spawn failed"
    else:
        assert answer["wake"]["state"] == "woken_unread" and answer["wake"]["exit_code"] == 0
        assert len(actors) == 1 and actors[0].wait(timeout=5) == 0 and len(identities) == 1
        assert identities[0]["snapshot"] is not None and identities[0]["host_pid"] == actors[0].pid
        assert json.loads(ready.read_text()) == dict(pid=actors[0].pid,cwd=str(cwd),executable=str(executable))
        assert admission["admission_attempted"] is True and "failure" not in admission
        assert module.process_group_exited(actors[0].pid)


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("log", ["stdout", "stderr"])
@pytest.mark.parametrize("outcome", ["owned", "wrapper", "settled"])
def test_r29_log_close_after_creation_keeps_the_admitted_child(r2_case, capsys, monkeypatch, host, log, outcome):
    import errno

    r2_case.bind(host, str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r29-post-creation-log-close")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    loading, faults, abandoned, descriptors = module.load_wake, [], [], []

    class Stream:
        def __init__(self, raw):
            self.raw = raw
            descriptors.append(raw.fileno())
        def __enter__(self):
            self.raw.__enter__()
            return self
        def __exit__(self, *args):
            self.raw.__exit__(*args)
            assert actors and actors[0].poll() is None
            faults.append(True)
            raise OSError(errno.EIO, "modelled private log-close payload")
        def __getattr__(self, name):
            return getattr(self.raw, name)

    def loaded(launches):
        wake = loading(launches)
        opening = open
        def opened(path, mode, *args, **kwargs):
            raw = opening(path, mode, *args, **kwargs)
            return Stream(raw) if mode == "xb" and Path(path).suffix == "." + log else raw
        wake.open = opened  # This invocation's producer namespace; never patch builtins.open.
        if outcome == "wrapper":
            def spawned(*args, **kwargs):
                actor = r2_case.spawn(["python3", "permitted-wrapper.py"])
                actors.append(actor)
                return actor
            wake.subprocess.Popen = spawned
        def abandon(process):
            abandoned.append(process.pid)
            if outcome == "settled":
                r2_case.configs[-1].with_suffix(".exit").touch()
                assert process.wait(timeout=5) == 0
                return
            raise PermissionError(errno.EPERM, "modelled child cannot yet be abandoned")
        wake.abandon_turn = abandon
        return wake
    monkeypatch.setattr(module, "load_wake", loaded)
    launches = module.Launches(str(r2_case.launch.base))
    code = module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW])
    answer = json.loads(capsys.readouterr().out)
    assert faults == [True] and actors and code == 3
    assert "modelled private" not in json.dumps(answer)
    resume_path = launches.paths(REVIEW)[-1]
    admission = module.read_resume_admission(launches.base, REVIEW, resume_path.stem)
    assert admission["admission_attempted"] is True and "failure" not in admission
    assert abandoned == [actors[0].pid]
    assert not launches.mailbox.wake_marker(REVIEW).exists()
    for descriptor in descriptors:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    running = module.read_running_wake(launches.base, REVIEW)
    if outcome == "settled":
        assert running is None and actors[0].returncode == 0
        assert answer["wake"]["state"] == "failed_to_start"
        assert module.process_group_exited(actors[0].pid)
        return
    assert answer["wake"]["state"] == "stop_unconfirmed" and actors[0].poll() is None
    assert running is not None and running["host_pid"] == actors[0].pid
    snapshot = module.StopCustody.decode(running["snapshot"])
    current = module.read_process(actors[0].pid).snapshot
    assert snapshot == module.process_identity(current)._asdict()
    stopped, receipt = r2_case.stop(module, capsys, 0)
    if outcome == "owned":
        assert stopped == 0 and receipt["state"] == "stopped" and receipt["pids"] == [actors[0].pid]
        assert actors[0].wait(timeout=5) == -signal.SIGTERM
    else:
        assert stopped == 3 and receipt["state"] == "stop_failed" and receipt["pids"] == []
        assert receipt["unresolved_pids"] == [actors[0].pid] and actors[0].poll() is None
        assert module.read_running_wake(launches.base, REVIEW) == running
        assert not r2_case.projection.events
        r2_case.configs[-1].with_suffix(".exit").touch()
        assert actors[0].wait(timeout=5) == 0
        assert r2_case.stop(module, capsys, 0)[0] == 0
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert module.process_group_exited(actors[0].pid)


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("failure", ["os", "value"])
def test_r29_popen_failure_still_retires_only_the_no_child_admission(r2_case, capsys, monkeypatch, host, failure):
    import errno

    r2_case.bind(host, str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r29-no-child-spawn-failure")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    loading, attempted = module.load_wake, []
    def loaded(launches):
        wake = loading(launches)
        def failed(*args, **kwargs):
            attempted.append(True)
            if failure == "value":
                raise ValueError("embedded null byte")
            raise OSError(errno.EIO, "modelled private Popen payload")
        wake.subprocess.Popen = failed
        return wake
    monkeypatch.setattr(module, "load_wake", loaded)
    launches = module.Launches(str(r2_case.launch.base))
    code = module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW])
    answer = json.loads(capsys.readouterr().out)
    assert code == (3 if failure == "os" else 2) and attempted == [True] and not actors
    assert answer["wake"]["state"] == ("failed_to_start" if failure == "os" else None)
    if failure == "value":
        assert answer["error"] == "embedded null byte"
    assert "modelled private" not in json.dumps(answer)
    admission = module.read_resume_admission(launches.base, REVIEW, launches.paths(REVIEW)[-1].stem)
    assert admission["failure"] == "host spawn failed"
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert not launches.mailbox.wake_marker(REVIEW).exists() and not r2_case.projection.events


CHILD = """
import os, time
with open(os.environ["STOP_OWNERSHIP_READY"], "w") as ready:
    ready.write("ready")
# The admitted gate's private EOF watchdog owns lifetime; elapsed test setup must not end a held process.
import signal
while True:
    signal.pause()
"""


def r28_exchange_binding_edge(case, edge):
    import shutil

    path = case.launch.root / "bindings"
    if edge == "endpoint":
        path = path / REVIEW
    original = case.launch.tmp / ("r28-detached-" + uuid.uuid4().hex)
    path.rename(original)
    shutil.copytree(original, path)
    return original


@pytest.mark.parametrize("edge", ["endpoint", "ancestor"])
def test_r28_start_revalidates_namespace_immediately_before_spawn(r2_case, capsys, edge):
    import errno

    module = r2_case.module(False)
    request = r2_case.launch.start_request(cwd=str(r2_case.launch.source))
    setting, changed, entered = module.signal.signal, [], []
    def signal_handler(number, handler):
        result = setting(number, handler)
        if number == signal.SIGTERM and isinstance(handler, module.Deferred) and not changed:
            changed.append(r28_exchange_binding_edge(r2_case, edge))
        return result
    def forbidden(*args, **kwargs):
        entered.append(True)
        raise OSError(errno.ENOEXEC, os.strerror(errno.ENOEXEC))
    module.signal.signal = signal_handler
    module.subprocess = R2Facade(module.subprocess, Popen=forbidden)
    code = module.main(["--base", str(r2_case.launch.base), "start", "--request", str(request)])
    answer = json.loads(capsys.readouterr().out)
    assert changed and not entered, "a detached endpoint fence admitted host creation"
    assert code == 2 and answer["error"] == "endpoint namespace changed; preserve custody and retry"
    assert r2_case.launch.binding() is None


@pytest.mark.parametrize("edge", ["endpoint", "ancestor"])
def test_r28_start_revalidates_namespace_at_the_actual_bind_boundary(r2_case, capsys, edge):
    from types import FunctionType

    module = r2_case.module(False)
    session = str(uuid.uuid4())
    producer, changed, executed = module.add_role, [], []
    mailbox = producer.__globals__["Mailbox"]
    class Mailboxes(mailbox):
        def bindings(self, endpoint):
            history = super().bindings(endpoint)
            if endpoint == REVIEW and (self.root / ".write.lock").exists() and not changed:
                changed.append(r28_exchange_binding_edge(r2_case, edge))
            return history
    # Private function namespace, not a patch of the shared producer module or its Mailbox class.
    module.add_role = FunctionType(producer.__code__, {**producer.__globals__, "Mailbox": Mailboxes},
        producer.__name__, producer.__defaults__, producer.__closure__)
    event = json.dumps({"type": "thread.started", "thread_id": session})
    command = [sys.executable, "-c", "print(%r,flush=True)" % event]
    def create(argv, **options):
        actor = r2_case.spawn_exec(command, None, command, cwd=options["cwd"],
            stdin=options["stdin"], stdout=options["stdout"], stderr=options["stderr"])
        executed.append(actor)
        return actor
    module.subprocess = R2Facade(module.subprocess, Popen=create)
    request = r2_case.launch.start_request(cwd=str(r2_case.launch.source))
    code = module.main(["--base", str(r2_case.launch.base), "start", "--request", str(request)])
    answer = json.loads(capsys.readouterr().out)
    assert executed and executed[0].wait(timeout=5) == 0 and changed
    assert r2_case.launch.binding() is None, "the start bound after its endpoint namespace changed"
    assert code == 2 and answer["error"] == "endpoint namespace changed; preserve custody and retry"


@pytest.mark.parametrize("fault", ["oversize", "non-ascii", "malformed", "boolean", "integer-token", "ancestor"])
def test_r28_worker_namespace_manifest_refuses_before_host_creation(r2_case, capsys, monkeypatch, fault):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r28-namespace-manifest")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    running, altered, parsed = module.subprocess.run, [], []
    opening, opened = module.os.open, []
    def open_path(*args, **kwargs):
        descriptor = opening(*args, **kwargs)
        opened.append(descriptor)
        return descriptor
    module.os = R2Facade(module.os, open=open_path)
    loading = module.json.loads
    module.json = R2Facade(module.json, loads=lambda *args, **kwargs: (parsed.append(True), loading(*args, **kwargs))[1])
    def external(command, **options):
        if "_resume-wake" in command:
            command = list(command)
            position = command.index("--admission-namespace") + 1
            if fault == "ancestor":
                path = r2_case.launch.root / "bindings"
                original = r2_case.launch.tmp / "r28-moved-ancestor"
                path.rename(original)
                (path / REVIEW).parent.mkdir(parents=True)
                (original / REVIEW).rename(path / REVIEW)  # Preserve the locked endpoint inode itself.
            else:
                original_manifest = command[position]
                command[position] = {"oversize": " " * 32769, "non-ascii": "\u2603", "malformed": "{",
                    "boolean": "[[true,0]]", "integer-token": "[" + "9" * 129 + "]"}[fault]
                if fault == "boolean":
                    # Keep the correct depth so this reaches the scalar-type guard.
                    values = json.loads(original_manifest)
                    values[0][0] = True
                    command[position] = json.dumps(values)
            altered.append(True)
            if fault in ("oversize", "non-ascii"):
                parsed.clear()
        return running(command, **options)
    module.subprocess = R2Facade(module.subprocess, run=external)
    code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW])
    if fault in ("oversize", "non-ascii"):
        assert not parsed, "invalid manifest reached JSON parsing"
    answer = json.loads(capsys.readouterr().out)
    assert altered and not actors and not r2_case.projection.events
    assert code == 2 and answer["error"] == "endpoint namespace changed; preserve custody and retry"
    assert opened
    for descriptor in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == 9


@pytest.mark.parametrize("edge", ["endpoint", "ancestor"])
def test_r28_stop_revalidates_namespace_after_checkpoint_and_before_signal(r2_case, capsys, edge):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    held = r2_case.spawn(["claude", "--resume", r2_case.launch.binding()["session"]])
    module = r2_case.module(False)
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody/state.json"
    reading, changed = module.read_process, []
    def read(pid, *args):
        value = reading(pid, *args)
        if pid == held.pid and not changed and journal.exists():
            entries = json.loads(journal.read_text())["entries"]
            if any(row["pid"] == pid and row["attempted"] for row in entries):
                changed.append(r28_exchange_binding_edge(r2_case, edge))
        return value
    module.read_process = read
    code, answer = r2_case.stop(module, capsys, 0)
    assert changed and held.poll() is None and not r2_case.projection.events
    assert code == 2 and answer["error"] == "endpoint namespace changed; preserve custody and retry"
    assert json.loads(journal.read_text())["active"]


@pytest.mark.parametrize("edge", ["endpoint", "ancestor"])
def test_r28_resume_revalidates_namespace_after_intent_before_host_spawn(r2_case, capsys, monkeypatch, edge):
    import errno

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r28-fenced-resume")
    module = r2_case.module(False)
    r22_wake_processes(r2_case, module, monkeypatch)
    loading, publishing, changed, entered = module.load_wake, module.publish_wake_record, [], []
    def loaded(launches):
        wake = loading(launches)
        def forbidden(*args, **kwargs):
            entered.append(True)
            raise OSError(errno.ENOEXEC, os.strerror(errno.ENOEXEC))
        wake.subprocess.Popen = forbidden
        return wake
    def published(launches, endpoint, record, **options):
        result = publishing(launches, endpoint, record, **options)
        if record["host_pid"] is None and not changed:
            changed.append(r28_exchange_binding_edge(r2_case, edge))
        return result
    module.load_wake, module.publish_wake_record = loaded, published
    code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW])
    answer = json.loads(capsys.readouterr().out)
    assert changed and not entered, "a detached wake admission created a host"
    assert code == 2 and answer["error"] == "endpoint namespace changed; preserve custody and retry"
    assert not r2_case.projection.events


@pytest.mark.parametrize("edge", ["endpoint", "ancestor"])
def test_r28_handoff_revalidates_namespace_between_draft_and_bind(r2_case, capsys, edge):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    control = handoff_module()
    control.hierarchy_launcher = module
    mailbox, changed, bound = control.Mailbox, [], []
    class Mailboxes(mailbox):
        def draft_handoff(self, *args, **kwargs):
            draft = super().draft_handoff(*args, **kwargs)
            changed.append(r28_exchange_binding_edge(r2_case, edge))
            return draft
        def bind(self, *args, **kwargs):
            bound.append(True)
            return super().bind(*args, **kwargs)
    control.Mailbox = Mailboxes
    result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 3)
    assert changed and not bound, "handoff bound through a detached endpoint fence"
    assert result["entries"][0]["error"] == "endpoint namespace changed; preserve custody and retry"
    assert r2_case.launch.binding()["generation"] == 1


@pytest.mark.parametrize("edge", ["endpoint", "ancestor"])
def test_r28_replaced_unbound_cleanup_fence_never_deletes_a_live_starts_worktree(r2_case, capsys, edge):
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    import threading

    module = r2_case.module(False)
    probe, plan, control = r23_cleanup_scope(r2_case, module)
    worktree = Path(plan["worktree"])
    locking, acquired, spawned = control.cleanup_locks, threading.Event(), threading.Event()
    entries, observations, actors = [], [], []
    @contextmanager
    def locked(roles):
        with locking(roles) as scopes:
            entries.append(True)
            if len(entries) == 2:  # The final deletion fence, after initial inspection and fenced stop.
                acquired.set()
                assert spawned.wait(timeout=R2_STOP_TIMEOUT_SECONDS), "concurrent start did not reach its captured OS boundary"
            yield scopes
    control.cleanup_locks = locked
    runner = control.Runner(plan, 0, None, None, True)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(runner.cleanup)
        try:
            assert acquired.wait(timeout=R2_STOP_TIMEOUT_SECONDS)
            r28_exchange_binding_edge(r2_case, edge)
            def create(argv, **options):
                # MODELLED host entrypoint; the unbound child, cwd, lifetime and deletion are physical.
                assert options["cwd"] == str(worktree)
                slot = "actor0-r28-unbound"
                config = r2_case.make_config({slot: {"kind": "H", "parent": None, "child": None}})
                actor = r2_case.custody.launch(config, slot, r2_case.env, cwd=options["cwd"])
                r2_case.admit(slot, actor, None)
                actors.append(actor)
                assert Path(os.readlink("/proc/%d/cwd" % actor.pid)) == worktree
                spawned.set()
                receipt = pending.result(timeout=R2_STOP_TIMEOUT_SECONDS)
                observations.append((actor.poll(), worktree.is_dir(), receipt))
                r2_case.custody.kill_owned(slot)
                actor.wait(timeout=5)
                return actor
            module.subprocess = R2Facade(module.subprocess, Popen=create)
            request = r2_case.launch.start_request(cwd=str(worktree))
            assert module.main(["--base", str(r2_case.launch.base), "start", "--request", str(request)]) == 3
            capsys.readouterr()
            assert actors and observations and observations[0][0] is None
            assert observations[0][1], "cleanup deleted the worktree while the unbound host was alive"
            receipt = observations[0][2]
            assert not receipt["worktree_removed"] and receipt["auth_removed"]
            assert any("namespace changed" in row["reason"] for row in receipt["unresolved_custody"])
        finally:
            spawned.set()
            for actor in actors:
                if actor.poll() is None:
                    slot = next(slot for slot, row in r2_case.custody.entries.items() if row["pid"] == actor.pid)
                    r2_case.custody.kill_owned(slot)
                    actor.wait(timeout=5)
            pending.result(timeout=R2_STOP_TIMEOUT_SECONDS)
            probe.close()


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("boundary", ["after-term", "namespace-check"])
@pytest.mark.parametrize("pidfds", [False, pytest.param(True, marks=pytest.mark.skipif(
    not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"), reason="pidfd signalling is unavailable"))])
def test_r28_host_exec_to_nonhost_helper_loses_signal_authority_but_keeps_custody(r2_case, capsys, host, pidfds, boundary):
    session = str(uuid.uuid4())
    r2_case.bind(host, session)
    ready, host_ready, exiting = (r2_case.launch.tmp / name for name in ("r28-helper-ready", "r28-host-ready", "r28-helper-exit"))
    helper = r2_case.launch.tmp / "r28-nonhost.py"
    trigger = r2_case.launch.tmp / "r28-exec-trigger"
    helper.write_text("import os,signal,time\nfrom pathlib import Path\n"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN)\nPath(%r).touch()\n"
        "while not Path(%r).exists(): time.sleep(.01)\n" % (str(ready), str(exiting)))
    body = ("import os,signal,time\nfrom pathlib import Path\n"
        "def changed(number,frame): os.execv(%r,%r)\n"
        "signal.signal(signal.SIGTERM,%s)\nPath(%r).touch()\n" %
        (sys.executable, [sys.executable, str(helper)],
         "changed" if boundary == "after-term" else "signal.SIG_IGN", str(host_ready)))
    body += ("while True: signal.pause()\n" if boundary == "after-term" else
             "while not Path(%r).exists(): time.sleep(.01)\nchanged(None,None)\n" % str(trigger))
    logical = ["claude", "--resume", session] if host == "claude-code" else ["codex", "exec", "resume", session]
    held = r2_case.spawn_legacy([sys.executable], logical, body, {})
    wait_until(host_ready.exists)
    before = r2_kernel_process(held.pid)
    module = r2_case.module(pidfds)
    refused_kills, handles = [], {}
    killing = module.os.kill
    def kill(pid, number):
        if pid == held.pid and number == signal.SIGKILL:
            refused_kills.append(pid)
            raise PermissionError("modelled forbidden KILL observer")
        return killing(pid, number)
    module.os.kill = kill
    if pidfds:
        opening, sending = module.os.pidfd_open, module.signal.pidfd_send_signal
        def opened(pid, *args):
            descriptor = opening(pid, *args)
            handles[descriptor] = pid
            return descriptor
        def sent(descriptor, number, *args):
            if handles.get(descriptor) == held.pid and number == signal.SIGKILL:
                refused_kills.append(held.pid)
                raise PermissionError("modelled forbidden KILL observer")
            return sending(descriptor, number, *args)
        module.os.pidfd_open, module.signal.pidfd_send_signal = opened, sent
    reading, native = module.read_process, launcher_module().read_process
    def observed(pid, *args):
        # Actual exec ends the original argv projection; the new physical helper is negative evidence.
        if pid == held.pid and ready.exists():
            value = native(pid, *args)
            # The independently loaded reader's record classes differ; preserve every native field.
            return module.ProcessObservation(*value)._replace(
                snapshot=module.ProcessSnapshot(*value.snapshot) if value.snapshot is not None else None)
        return reading(pid, *args)
    module.read_process = observed
    term_seen, statting = [], module.os.stat
    def after_term(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            term_seen.append(True)
            if boundary == "after-term":
                wait_until(ready.exists)
    def stat(name, *args, **kwargs):
        if boundary == "namespace-check" and term_seen and name == "/" and not ready.exists():
            trigger.touch()  # Actual exec during the final namespace check, after the first argv check.
            wait_until(ready.exists)
        return statting(name, *args, **kwargs)
    module.os.stat = stat
    r2_case.projection.after_signal.append(after_term)
    try:
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 3 and answer["state"] == "stop_failed" and answer["unresolved_pids"] == [held.pid]
        assert not refused_kills, "a changed nonhost command line received a KILL attempt"
        assert held.poll() is None and r2_case.projection.events == [(held.pid, signal.SIGTERM)]
        current = r2_kernel_process(held.pid)
        assert all(current[key] == before[key] for key in ("pid", "birth", "uid", "euid"))
        assert current["raw"] != before["raw"] and b"--resume" not in current["raw"]
        assert any(row.get("signal_refusal") == "signal_command_line_not_authorized" for row in answer["unresolved"]), answer["unresolved"]
        path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody/state.json"
        entry = next(row for row in json.loads(path.read_text())["entries"] if row["pid"] == held.pid)
        assert entry["resolved"] is None and not entry["identity_lost"]
        again, receipt = r2_case.stop(module, capsys, 0)
        assert again == 3 and receipt["unresolved_pids"] == [held.pid]
        assert held.poll() is None and r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    finally:
        exiting.touch()
        held.wait(timeout=5)
    # The original child is now reaped; a new observer uses the admitted numeric exit proof.
    assert r2_case.stop(r2_case.module(False), capsys, 0)[0] == 0


@pytest.mark.parametrize("field", ["uid", "euid"])
def test_r27_partial_zombie_with_replacement_uid_cannot_commit_original_exit(r2_case, capsys, field):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    actor = r2_case.spawn(None)
    r2_case.projection.group_reaping = False
    physical = r2_kernel_process(actor.pid)
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    partial = dict(pid=actor.pid, start_time=physical["birth"], uid=physical["uid"], euid=physical["euid"],
                   pgid=physical["pgid"], ppid=physical["ppid"], coherent_birth=True)
    state = dict(candidates={actor.pid: None}, initial_unavailable={actor.pid: partial}, blocked=set(),
                 identity_lost=set(), resolved={}, owned_groups={physical["pgid"]})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(state, set())  # Existing negative group custody grants no signal authority.
    slot = next(s for s,e in r2_case.custody.entries.items() if e["pid"] == actor.pid)
    r2_case.custody.kill_owned(slot)
    wait_until(lambda: r2_kernel_process(actor.pid)["state"].startswith("Z"))
    reading, witnessed = module.read_process, []
    def replacement(pid, *args):
        observation = reading(pid, *args)
        if pid == actor.pid and observation.kind == "PRESENT":
            assert observation.snapshot.state.startswith("Z")
            witnessed.append(True)
            return r2_map_present(observation, lambda row: row._replace(**{field: getattr(row, field) + 1}))
        return observation
    module.read_process = replacement
    try:
        assert r2_case.stop(module, capsys, 0)[0] == 3 and witnessed
    finally:
        assert actor.wait(timeout=5) == -signal.SIGKILL
    assert r2_case.stop(r2_case.module(False), capsys, 0)[0] == 3
    saved = json.loads(custody.path.read_text())
    assert saved["active"] and saved["entries"][0]["identity_lost"] and saved["entries"][0]["resolved"] is None
    assert not r2_case.projection.events


def test_r27_identity_limit_refusal_is_recorded_before_any_signal(r2_case, capsys, monkeypatch):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    session = r2_case.launch.binding()["session"]
    actors = [r2_case.spawn(["codex", "exec", "resume", session]) for _ in range(2)]
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    before = set(launches.paths(REVIEW))
    monkeypatch.setattr(module, "MAX_RECORDS", 1)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 2 and not r2_case.projection.events and all(p.poll() is None for p in actors)
    added = set(launches.paths(REVIEW)) - before
    assert len(added) == 1 and answer.get("state") == "refused"
    assert answer["error"] == "process census exceeds identity limit"
    assert all(answer[key] == value for key, value in known.items())
    assert json.loads(added.pop().read_text()) == answer


@pytest.mark.parametrize("pidfds", [False, pytest.param(True, marks=pytest.mark.skipif(
    not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"), reason="pidfd signalling is unavailable"))])
def test_r27_descendant_exec_metadata_before_term_keeps_instance(r2_case, capsys, pidfds):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, middle, worker = (family[k] for k in ("H", "M", "W"))
    module, changed = r2_case.module(pidfds), []
    census = module.process_census
    def captured(session):
        rows = census(session)
        changed.append(True)
        return rows
    def exec_metadata(pid, count, row):
        if changed and pid == worker.pid:
            # MODELLED post-census exec metadata; PID/birth/UIDs and every actual signal stay physical.
            return row._replace(cmdline=row.cmdline + b"exec-transition\0")
        return row
    def settled(pid, number):
        if pid == middle.pid and number == signal.SIGTERM:
            wait_until(lambda: middle.poll() is not None)
    module.process_census = captured
    r2_case.projection.after_present.append(exec_metadata)
    r2_case.projection.after_signal.append(settled)
    code, answer = r2_case.stop(module, capsys, 0)
    # R28 separates the retained instance from command authority: this changed nonhost remains held.
    assert changed and code == 3 and answer["state"] == "stop_failed"
    assert answer["pids"] == sorted([host.pid, middle.pid]) and worker.pid in answer["unresolved_pids"]
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)
    assert worker.poll() is None and host.wait(timeout=5) == -signal.SIGKILL
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody/state.json"
    entry = next(row for row in json.loads(path.read_text())["entries"] if row["pid"] == worker.pid)
    assert entry["resolved"] is None and not entry["identity_lost"]
    assert any(row.get("signal_refusal") == "signal_command_line_not_authorized" for row in answer["unresolved"])


@pytest.mark.parametrize("field", ["uid", "euid"])
def test_r27_filtered_partial_uid_witness_survives_later_absence(r2_case, capsys, field):
    actor, path, _ = r7_pending_attempt(r2_case, capsys)
    physical = r2_kernel_process(actor.pid)
    module, witnessed = r2_case.module(False), []
    reading = module.read_process
    def observation(pid, *args):
        if pid == actor.pid and not witnessed:
            witnessed.append(True)
            r2_case.configs[0].with_suffix(".exit").touch()
            assert actor.wait(timeout=5) == 0
            return module.ProcessObservation("UNAVAILABLE", pid, reason="modelled partial replacement UID",
                partial={"pid": pid, "coherent_birth": True, "start_time": physical["birth"], field: physical[field] + 1})
        return reading(pid, *args)
    module.read_process = observation
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(module, capsys, 0)
    assert witnessed and code == 3 and actor.pid in answer["unresolved_pids"]
    entry = next(e for e in json.loads(path.read_text())["entries"] if e["pid"] == actor.pid)
    assert entry["identity_lost"] and entry["blocked"] and json.loads(path.read_text())["active"]
    assert r2_case.projection.events == before


@pytest.mark.parametrize("host", ["codex-cli", "claude-code"])
@pytest.mark.parametrize("wrapper", ["env", "shebang"])
def test_r27_real_producer_wrapper_exec_keeps_its_admitted_instance(r2_case, capsys, monkeypatch, host, wrapper):
    import shutil
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace
    import threading

    session = str(uuid.uuid4())
    r2_case.bind(host, session)
    r2_case.launch.publish_to(REVIEW, "r27-real-wrapper-exec")
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    _, profile_path = module.bound_session(launches, REVIEW, launches.new_id(), "resume")
    slot = "actor0-wrapper"
    config = r2_case.make_config({slot: {"kind": "H", "parent": None, "child": None}})
    ready = r2_case.launch.tmp / "real-host-ready"
    leaf = r2_case.launch.tmp / "real-host.py"
    leaf.write_text("import os,json,signal\nfrom pathlib import Path\n"
                    "Path(%r).write_text(json.dumps({'pid':os.getpid(),'wrapper':os.environ.get('R27_WRAPPER')}))\n"
                    "while True: signal.pause()\n" % str(ready))
    program = r2_case.launch.tmp / "host-wrapper"
    program.write_text("#!/usr/bin/env python3\nimport os,json,runpy\nfrom pathlib import Path\n"
        "configuration=json.loads(Path(os.environ['R2_LEGACY_CONFIG']).read_text())\n"
        "runpy.run_path(configuration['helper'])['r2_legacy_child_gate'](configuration,os.environ['R2_LEGACY_SLOT'])\n"
        "os.execv(%r,%r)\n" % (sys.executable, [sys.executable, str(leaf), "--resume", session]))
    program.chmod(0o700)
    profile = json.loads(profile_path.read_text())
    env_program = shutil.which("env")
    assert env_program is not None
    profile["argv"] = ([env_program, "R27_WRAPPER=1", str(program)] if wrapper == "env" else [str(program)]) + ["--resume", session]
    profile["prompt_via"] = "argv"
    profile_path.write_text(json.dumps(profile))
    actors, admitted, original, released, created = [], [], [], [], threading.Event()
    loading, publishing, reading = module.load_wake, module.publish_wake_record, module.read_process
    native = launcher_module().read_process
    logical = ["claude", "--resume", session] if host == "claude-code" else ["codex", "exec", "resume", session]
    def load(launches):
        wake = loading(launches)
        def popen(argv, **options):
            assert argv[:-1] == profile["argv"]
            process = r2_case.custody.launch(config, slot,
                {**r2_case.env, "R2_LEGACY_CONFIG": config["config"], "R2_LEGACY_SLOT": slot},
                argv=argv, cwd=options["cwd"], stdin=options["stdin"], stdout=options["stdout"], stderr=options["stderr"])
            r2_case.children.append(process)
            actors.append(process)
            r2_case.custody.await_event(slot, "hello")
            r2_case.projection.pending(process)
            original.append(r2_kernel_process(process.pid))
            return process
        wake.subprocess = R2Facade(subprocess, Popen=popen)
        class Paths(type(Path())):
            @classmethod
            def home(cls):
                return r2_case.home
        wake.Path = Paths
        return wake
    def observe(pid, *args):
        # Admission witnesses the real pre-exec process; only the later declared host argv is MODELLED.
        return native(pid, *args) if actors and pid == actors[0].pid and not released else reading(pid, *args)
    def publish(launches, endpoint, record, **options):
        result = publishing(launches, endpoint, record, **options)
        if record["host_pid"] is not None:
            admitted.append(record)
            r2_case.custody.release(slot)
            r2_case.custody.await_event(slot, "running")
            wait_until(ready.exists)
            r2_case.projection.ready(actors[0], logical)
            released.append(True)
            created.set()
        return result
    monkeypatch.setattr(module, "load_wake", load)
    monkeypatch.setattr(module, "read_process", observe)
    monkeypatch.setattr(module, "publish_wake_record", publish)
    running = module.subprocess.run
    def external(command, **options):
        if "_resume-wake" in command:
            code, answer = module.admitted_wake(module.Launches(str(launches.base)), REVIEW,
                options["pass_fds"][0], str(r2_case.launch.source / "tools/hierarchy_wake.py"), False,
                command[command.index("--admission-namespace") + 1])
            return SimpleNamespace(returncode=code, stdout=json.dumps(answer))
        return running(command, **options)
    module.subprocess = R2Facade(module.subprocess, run=external)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(module.resume, launches, REVIEW, False)
        try:
            assert created.wait(timeout=10), "real producer did not publish and exec its captured host"
            def admission_is_free():
                try:
                    with module.stop_endpoint_lock(launches.mailbox.root, REVIEW):
                        return True
                except ValueError as exc:
                    assert "busy" in str(exc)
                    return False
            wait_until(admission_is_free)
            current = r2_kernel_process(actors[0].pid)
            assert current["birth"] == original[0]["birth"] and current["raw"] != original[0]["raw"]
            assert json.loads(ready.read_text())["pid"] == actors[0].pid
            if wrapper == "env":
                assert json.loads(ready.read_text())["wrapper"] == "1"
            # Acquisition in the real stop waits only for admission's final explicit unlock.
            code, answer = r2_case.stop(module, capsys, 0)
            assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [actors[0].pid]
            assert actors[0].wait(timeout=5) == -signal.SIGTERM
        finally:
            if actors and actors[0].poll() is None:
                r2_case.custody.kill_owned(slot)
                actors[0].wait(timeout=5)
        assert pending.result(timeout=R2_STOP_TIMEOUT_SECONDS)[0] == 3
    facts = module.StopCustody.decode(admitted[0]["snapshot"])
    assert facts == dict(pid=actors[0].pid, start_time=original[0]["birth"],
                         uid=original[0]["uid"], euid=original[0]["euid"])
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert module.process_group_exited(actors[0].pid)


@pytest.mark.parametrize("field", ["birth", "uid", "euid"])
def test_r27_replacement_identity_latches_birth_and_each_uid(r2_case, capsys, field):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    actor = r2_case.spawn(["codex", "exec", "resume", r2_case.launch.binding()["session"]])
    module, changed = r2_case.module(False), []
    census = module.process_census
    def captured(session):
        result = census(session)
        changed.append(True)
        return result
    module.process_census = captured
    def replacement(pid, count, row):
        if changed and pid == actor.pid:
            return row._replace(**({"start_time": row.start_time + "1"} if field == "birth" else {field: getattr(row, field) + 1}))
        return row
    r2_case.projection.after_present.append(replacement)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and actor.pid in answer["unresolved_pids"] and not r2_case.projection.events
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody/state.json"
    entry = next(e for e in json.loads(path.read_text())["entries"] if e["pid"] == actor.pid)
    assert entry["identity_lost"] is True and entry["blocked"] is True
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert actor.wait(timeout=5) == 0
    assert r2_case.stop(r2_case.module(False), capsys, 0)[0] == 3
    assert json.loads(path.read_text())["active"] is True


@pytest.mark.parametrize("field", ["LEAK-FIELD", "L" * 1024], ids=["short", "long"])
def test_r27_unknown_profile_fields_keep_the_diagnostic_without_echoing_input(r2_case, capsys, monkeypatch, field):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    r22_wake_processes(r2_case, module, monkeypatch)
    launches = module.Launches(str(r2_case.launch.base))
    _, path = module.bound_session(launches, REVIEW, launches.new_id(), "resume")
    profile = json.loads(path.read_text())
    profile[field] = "LEAK-VALUE"
    path.write_text(json.dumps(profile))
    assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert answer["error"] == "unexpected fields: [redacted]"
    assert field not in json.dumps(answer) and "LEAK-VALUE" not in json.dumps(answer)
    assert module.read_running_wake(launches.base, REVIEW) is None


@pytest.mark.parametrize("comparison_base", ["baf2e2d7", "419e6d11"])
@pytest.mark.parametrize("site", ["missing-cwd", "profile-schema", "invalid-json", "cwd-relative", "oversize",
    "duplicate-cwd", "nonfinite", "deep-json", "type-cwd", "driver", "outcome", "spawn", "spawn-value"])
def test_r27_no_plan_failure_keeps_legacy_output_and_record_bytes(r2_case, capsys, monkeypatch, comparison_base, site):
    import errno
    from types import SimpleNamespace

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r27-legacy-failure")
    module = r2_case.module(False)
    r22_wake_processes(r2_case, module, monkeypatch)
    launches = module.Launches(str(r2_case.launch.base))
    known, profile_path = module.bound_session(launches, REVIEW, launches.new_id(), "resume")
    assert not (launches.base / "host-plan.json").exists()
    monkeypatch.setattr(module, "timestamp", lambda: "2026-11-11T06:00:00.000000Z")
    before = set(launches.paths(REVIEW))
    expected_error = {"missing-cwd": "missing fields: cwd", "profile-schema": "unsupported wake profile schema",
                      "driver": "[Errno 8] Exec format error", "outcome": "[Errno 5] Input/output error",
                      "spawn-value": "embedded null byte", "invalid-json": "Expecting value: line 1 column 11 (char 10)"}.get(site)
    if site in ("missing-cwd", "profile-schema"):
        profile = json.loads(profile_path.read_text())
        if site == "missing-cwd":
            profile.pop("cwd")
        else:
            profile["schema"] = "not-the-profile-schema"
        profile_path.write_text(json.dumps(profile))
    elif site == "invalid-json":
        profile_path.write_text('{"schema":')
    elif site in ("cwd-relative", "oversize", "duplicate-cwd", "nonfinite", "deep-json", "type-cwd"):
        profile = json.loads(profile_path.read_text())
        if site == "cwd-relative":
            profile["cwd"] = "relative"
        elif site == "type-cwd":
            profile["cwd"] = []
        raw_profile = json.dumps(profile)
        raw_profile = {"oversize": " " * 262145, "duplicate-cwd": raw_profile[:-1] + ', "cwd": ' +
            json.dumps(profile["cwd"]) + "}", "nonfinite": "NaN", "deep-json": "[" * 5000 + "]" * 5000}.get(site, raw_profile)
        profile_path.write_text(raw_profile)
        # The unchanged, pinned producer is the legacy validator oracle. The historical parent
        # catches its CLI JSON/code2, or code1/no JSON for TypeError; no git history is needed here.
        producer = module.load_wake(launches)
        if site == "type-cwd":
            with pytest.raises(TypeError):
                producer.load_profile(profile_path, REVIEW, launches.binding(REVIEW))
            expected_error = "the wake tool exited 1"
        else:
            with pytest.raises((ValueError, RecursionError)) as refused:
                producer.load_profile(profile_path, REVIEW, launches.binding(REVIEW))
            expected_error = str(refused.value)
    elif site == "driver":
        def failed(*args, **kwargs):
            raise OSError(errno.ENOEXEC, os.strerror(errno.ENOEXEC))
        module.subprocess.run = failed
    elif site == "outcome":
        module.subprocess.run = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, '{"state":"nothing_unread"}')
        recording = module.Launches.record
        def failed(self, endpoint, identifier, action, state, **details):
            if action == "resume":
                raise OSError(errno.EIO, os.strerror(errno.EIO))
            return recording(self, endpoint, identifier, action, state, **details)
        monkeypatch.setattr(module.Launches, "record", failed)
    else:
        loading = module.load_wake
        def loaded(launches):
            wake = loading(launches)
            wake.uuid = R2Facade(uuid, uuid4=lambda: SimpleNamespace(hex="a" * 32))
            def failed(*args, **kwargs):
                if site == "spawn-value":
                    raise ValueError("embedded null byte")
                raise OSError(errno.EIO, os.strerror(errno.EIO))
            wake.subprocess.Popen = failed
            return wake
        monkeypatch.setattr(module, "load_wake", loaded)
    code = module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW])
    raw = capsys.readouterr().out.encode()
    added = set(launches.paths(REVIEW)) - before
    if site == "outcome":
        expected = {"error": expected_error}
        assert code == 2 and not added
    else:
        expected = dict(schema=module.SCHEMA, at="2026-11-11T06:00:00.000000Z", action="resume",
                        state="resumed_unread" if site == "spawn" else "refused", endpoint=REVIEW, **known)
        if site != "driver":
            expected.update(dry_run=False, wake=dict(wake_id="wake-" + "a" * 32 if site == "spawn" else None,
                state="failed_to_start" if site == "spawn" else None, exit_code=None,
                timed_out=False if site == "spawn" else None),
                wake_exit_code=3 if site == "spawn" else 1 if site == "type-cwd" else 2)
        if expected_error is not None:
            expected["error"] = expected_error
        assert code == (3 if site == "spawn" else 2) and len(added) == 1
        assert added.pop().read_bytes() == (json.dumps(expected, sort_keys=True) + "\n").encode(), comparison_base
    assert raw == (json.dumps(expected, sort_keys=True) + "\n").encode(), comparison_base
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert not launches.mailbox.wake_marker(REVIEW).exists()


@pytest.mark.parametrize("view", ["empty", "unavailable"])
def test_r27_unlinked_unreadable_instance_does_not_claim_its_long_lived_group(r2_case, capsys, view):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    actor = r2_case.spawn(None, new_session=False)
    module = r2_case.module(False)
    physical = r2_kernel_process(actor.pid)
    assert physical["pgid"] == os.getpgrp()
    def unreadable(path, raw):
        if str(path) == "/proc/%d/cmdline" % actor.pid:
            if view == "unavailable":
                raise PermissionError("modelled unrelated instance cmdline unreadable")
            return b""
        return raw
    r2_case.projection.path_view(module, unreadable)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["unresolved_pids"] == [actor.pid] and actor.poll() is None
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody/state.json"
    saved = json.loads(path.read_text())
    assert os.getpgrp() not in saved.get("groups", [])
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert actor.wait(timeout=5) == 0
    assert r2_case.stop(r2_case.module(False), capsys, 0)[0] == 0
    assert json.loads(path.read_text())["active"] is False
    os.killpg(os.getpgrp(), 0)  # The unrelated caller group still exists after successful discharge.


@pytest.mark.parametrize("entry", ["resume", "_resume-wake"])
def test_r27_in_flight_resume_offers_stop_only_to_end_the_turn(r2_case, capsys, entry):
    from contextlib import nullcontext

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    record = dict(schema="aegis.hierarchy-running-wake/v2", binding=module.binding_identity(launches.binding(REVIEW)),
                  wake_id="wake-" + uuid.uuid4().hex, driver_pid=os.getpid(), host_pid=None, snapshot=None)
    module.publish_wake_record(launches, REVIEW, record)
    lock = module.stop_endpoint_lock(launches.mailbox.root, REVIEW) if entry == "_resume-wake" else nullcontext(None)
    with lock as admission:
        words = (["--admission-fd", str(admission), "--admission-namespace", admission.manifest(), "--wake-source",
                  str(r2_case.launch.source / "tools/hierarchy_wake.py")] if entry == "_resume-wake" else [])
        assert module.main(["--base", str(launches.base), entry, "--endpoint", REVIEW, *words]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert answer["error"] == "a turn is in flight; wait for it to finish, or run stop to end it"
    assert module.read_running_wake(launches.base, REVIEW) == record


@pytest.mark.parametrize("host", ["codex-cli", "claude-code"])
def test_r26_captured_resume_requires_no_installed_host_cli(r2_case, capsys, monkeypatch, host):
    import shutil
    from tests.conftest import symlink_or_skip

    r2_case.bind(host, str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r26-no-installed-host")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    programs = r2_case.launch.tmp / "support-bin"
    programs.mkdir()
    for name in ("git", "ps"):
        program = shutil.which(name)
        assert program is not None
        symlink_or_skip(program, programs / name)
    monkeypatch.setenv("PATH", str(programs))
    assert shutil.which("codex") is None and shutil.which("claude") is None
    spawning = r2_case.spawn
    def exits(*args, **kwargs):
        actor = spawning(*args, **kwargs)
        r2_case.configs[-1].with_suffix(".exit").touch()
        return actor
    monkeypatch.setattr(r2_case, "spawn", exits)
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW]) == 3
    answer = json.loads(capsys.readouterr().out)
    assert answer["state"] == "resumed_unread" and answer["wake"]["state"] == "woken_unread"
    assert len(actors) == 1 and actors[0].wait(timeout=5) == 0
    assert module.read_running_wake(r2_case.launch.base, REVIEW) is None
    assert module.process_group_exited(actors[0].pid)


@pytest.mark.parametrize("probe", ["live", "permission", "io"])
def test_r25_empty_census_never_discharges_a_retained_group(r2_case, capsys, probe):
    """MODELLED enumeration misses a birth; kernel group lifetime remains real."""
    import errno

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    actor = r2_case.spawn(None)
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, actor.pid)
    # This is the finite census's blind spot, not exit evidence. No logical owner is exposed,
    # so the actual actor must receive no signal, even though its group remains an obligation.
    module.process_census = lambda session: module.ProcessCensus([], "proven")
    probes = []
    def kernel(group, number):
        assert group == actor.pid and number == 0
        probes.append(group)
        if probe == "permission":
            raise PermissionError(errno.EPERM, "modelled group probe denied")
        if probe == "io":
            raise OSError(errno.EIO, "modelled group probe unavailable")
        return os.killpg(group, number)
    module.os.killpg = kernel
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["unresolved_groups"] == [actor.pid] and probes
    assert actor.poll() is None and not r2_case.projection.events
    with module.StopCustody(launches, REVIEW, known, create=False) as custody:
        assert custody.read()[0]["active"] is True
    # An independent invocation must retain group scope even with no discovered PID.
    actor.send_signal(signal.SIGTERM)
    assert actor.wait(timeout=5) == -signal.SIGTERM
    module.os.killpg = os.killpg
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "not_running"
    assert module.read_running_wake(launches.base, REVIEW) is None


def test_r25_wake_retirement_requires_kernel_group_absence(r2_case):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    actor = r2_case.spawn(None)
    module = r2_case.module(False)
    module.process_census = lambda session: module.ProcessCensus([], "proven")
    module.os.killpg = os.killpg
    record = dict(schema="aegis.hierarchy-running-wake/v3", pid_namespace=module.current_pid_namespace(),
                  host_pid=actor.pid, binding=r2_case.launch.binding())
    assert module.running_wake_group_exited(record) is False
    actor.send_signal(signal.SIGTERM)
    assert actor.wait(timeout=5) == -signal.SIGTERM
    assert module.running_wake_group_exited(record) is True


@pytest.mark.parametrize("probe", ["native", "permission", "io"])
def test_r25_fork_and_exit_between_final_enumeration_and_inspection(r2_case, capsys, probe):
    """Actual C forks D after the final PID list is taken. A separate reaper witnesses both exits."""
    import select
    import errno
    from contextlib import ExitStack
    from tests.integration.test_hierarchy_launcher import R2OwnedChild

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    with ExitStack() as descriptors:
        release_read, release_write = os.pipe()
        for descriptor in (release_read, release_write):
            descriptors.callback(os.close, descriptor)
        reaped_read, reaped_write = os.pipe()
        for descriptor in (reaped_read, reaped_write):
            descriptors.callback(os.close, descriptor)
        nodes = {"gap-H": dict(kind="H", parent=None, child="gap-C"),
                 "gap-C": dict(kind="M", parent="gap-H", child="gap-D"),
                 "gap-D": dict(kind="W", parent="gap-C", child=None)}
        config = r2_case.make_config(nodes, fork_gap=dict(root="gap-H", forker="gap-C", leaf="gap-D",
                                                        release_read=release_read, reaped_write=reaped_write))
        config["inherited"] += [release_read, reaped_write]
        Path(config["config"]).write_text(json.dumps(config))
        root = r2_case.custody.launch(config, "gap-H", r2_case.env)
        r2_case.admit("gap-H", root, None)
        r2_case.custody.await_event("gap-C", "hello")
        forker = R2OwnedChild(r2_case.custody, "gap-C")
        r2_case.projection.pending(forker)
        r2_case.projection.ready(forker, None)  # C is still gated; D has not been created.
        module = r2_case.module(False)
        launches = module.Launches(str(r2_case.launch.base))
        known = module.binding_identity(launches.binding(REVIEW))
        record = dict(schema="aegis.hierarchy-running-wake/v3", pid_namespace=module.current_pid_namespace(),
                      binding=known, wake_id="wake-" + uuid.uuid4().hex,
                      driver_pid=os.getpid(), host_pid=forker.pid, snapshot=None)
        module.publish_wake_record(launches, REVIEW, record)
        def group_probe(group, number):
            assert group == forker.pid and number == 0
            if probe == "permission":
                raise PermissionError(errno.EPERM, "modelled group evidence denied")
            if probe == "io":
                raise OSError(errno.EIO, "modelled group evidence unavailable")
            return os.killpg(group, number)
        module.os.killpg = group_probe
        physical_path, lists, born = module.Path, [], []
        class FinalCensusPath(type(physical_path())):
            def iterdir(path):
                names = list(super().iterdir())
                if str(path) == "/proc":
                    lists.append([p.name for p in names])
                    if len(lists) == 2:
                        r2_case.custody.release("gap-C")
                        r2_case.custody.await_event("gap-C", "running")
                        r2_case.custody.await_event("gap-D", "hello")
                        leaf = R2OwnedChild(r2_case.custody, "gap-D")
                        r2_case.admit("gap-D", leaf, None)
                        physical = r2_kernel_process(leaf.pid)
                        assert physical["pgid"] == forker.pid and physical["ppid"] == forker.pid
                        assert str(leaf.pid) not in lists[-1]
                        born.append(leaf)
                        os.write(release_write, b"X")
                        assert select.select([reaped_read], [], [], 5)[0]
                        assert os.read(reaped_read, 1) == b"C"  # Native wait for C completed before inspection.
                yield from names
        module.Path = FinalCensusPath
        code, answer = r2_case.stop(module, capsys, 0)
        assert born and code == 3 and answer["state"] == "stop_failed"
        assert answer["unresolved_groups"] == [forker.pid]
        assert born[0].poll() is None and not r2_case.projection.events
        assert module.read_running_wake(launches.base, REVIEW) == record
        r2_case.custody.kill_owned("gap-D")
        assert select.select([reaped_read], [], [], 5)[0]
        proof = json.loads(os.read(reaped_read, 4096))
        assert proof["pid"] == born[0].pid and os.WIFSIGNALED(proof["status"])
        if probe != "native":
            code, answer = r2_case.stop(module, capsys, 0)
            assert code == 3 and answer["unresolved_groups"] == [forker.pid]
        module.os.killpg = os.killpg
        assert r2_case.stop(module, capsys, 0)[0] == 0
        assert module.read_running_wake(launches.base, REVIEW) is None


def test_r25_fork_gap_pipe_allocation_failure_closes_prior_descriptors(r2_case, capsys, monkeypatch):
    import errno

    real_os, opened, calls = os, [], []
    def failed():
        calls.append(True)
        if len(calls) == 2:
            raise OSError(errno.EMFILE, "modelled second pipe allocation denied")
        pair = real_os.pipe()
        opened.extend((fd, (real_os.fstat(fd).st_dev, real_os.fstat(fd).st_ino)) for fd in pair)
        return pair
    # Only this test module's reference changes; pytest and its tmp_path cleanup keep the real OS.
    monkeypatch.setattr(sys.modules[__name__], "os", R2Facade(real_os, pipe=failed))
    def still_owned(fd, identity):
        try:
            info = real_os.fstat(fd)
        except OSError as exc:
            assert exc.errno == errno.EBADF
            return False
        return (info.st_dev, info.st_ino) == identity
    try:
        with pytest.raises(OSError, match="modelled second pipe allocation denied"):
            test_r25_fork_and_exit_between_final_enumeration_and_inspection(r2_case, capsys, "native")
        assert len(opened) == 2 and len(calls) == 2
        assert not any(still_owned(fd, identity) for fd, identity in opened)
    finally:
        for fd, identity in opened:
            if still_owned(fd, identity):
                real_os.close(fd)


@pytest.mark.parametrize("comparison_base", ["baf2e2d7", "563a1912"])
@pytest.mark.parametrize("dry_run", [False, True])
def test_r25_no_plan_resume_keeps_historical_bytes(r2_case, capsys, monkeypatch, comparison_base, dry_run):
    """Both reviewed bases have this identical literal shape; no test needs Git history."""
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    assert not (launches.base / "host-plan.json").exists()
    at = ["2026-11-10T01:00:00.000000Z"]
    monkeypatch.setattr(module, "timestamp", lambda: at[0])
    def outcome(command, **options):
        assert "_resume-wake" in command
        at[0] = "2026-11-10T01:01:00.000000Z"
        return subprocess.CompletedProcess(command, 0, json.dumps({"state": "dry_run" if dry_run else "nothing_unread"}))
    module.subprocess.run = outcome
    words = ["--base", str(launches.base), "resume", "--endpoint", REVIEW] + (["--dry-run"] if dry_run else [])
    assert module.main(words) == 0
    raw = capsys.readouterr().out
    expected = dict(schema=module.SCHEMA, at=at[0], action="resume", state="resumed", endpoint=REVIEW,
                    **module.binding_identity(launches.binding(REVIEW)), dry_run=dry_run,
                    wake=dict(wake_id=None, state="dry_run" if dry_run else "nothing_unread", exit_code=None,
                              timed_out=None), wake_exit_code=0)
    expected_bytes = (json.dumps(expected, sort_keys=True) + "\n").encode()
    assert raw.encode() == expected_bytes, comparison_base
    path = launches.paths(REVIEW)[-1]
    assert path.read_bytes() == expected_bytes, comparison_base
    sidecar = module.read_resume_admission(launches.base, REVIEW, path.stem)
    assert sidecar["at"] == "2026-11-10T01:00:00.000000Z"
    assert sidecar["admission_attempted"] is (not dry_run)


@pytest.mark.parametrize("fault", ["cwd", "executable", "spawn"])
def test_r25_spawn_failure_is_retryable(r2_case, capsys, monkeypatch, fault):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r25-failed-host-spawn")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    loading, attempted = module.load_wake, []
    def loaded(launches):
        wake = loading(launches)
        def failed(*args, **kwargs):
            attempted.append(True)
            raise OSError(2, "modelled secret host-spawn payload")
        if fault == "executable":
            def missing(*args, **kwargs):
                attempted.append(True)
                return subprocess.Popen(*args, **kwargs)
            wake.subprocess.Popen = missing
        else:
            wake.start_turn = failed
        if fault == "cwd":
            read_profile = wake.load_profile
            def removed(*args):
                profile = read_profile(*args)
                Path(profile["cwd"]).rmdir()  # Real disappearance after the pinned producer's validation.
                return profile
            wake.load_profile = removed
        return wake
    monkeypatch.setattr(module, "load_wake", loaded)
    launches = module.Launches(str(r2_case.launch.base))
    profile_path = module.bound_session(launches, REVIEW, launches.new_id(), "resume")[1]
    original = profile_path.read_text()
    if fault == "cwd":
        profile = json.loads(original)
        profile["cwd"] = str(r2_case.launch.tmp / "missing-r25-cwd")
        Path(profile["cwd"]).mkdir()
        profile_path.write_text(json.dumps(profile))
    elif fault == "executable":
        profile = json.loads(original)
        profile["argv"][0] = str(r2_case.launch.tmp / "r30-missing-executable")
        profile_path.write_text(json.dumps(profile))
    assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW]) == 3
    answer = json.loads(capsys.readouterr().out)
    assert answer["wake"]["state"] == "failed_to_start" and not actors
    assert bool(attempted) is (fault != "cwd")
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert r2_case.stop(module, capsys, 0)[0] == 0
    receipts = [json.loads(p.read_text()) for p in (launches.base / "delivery/wakes").rglob("*.json")]
    assert any(r.get("state") == "failed_to_start" for r in receipts)
    resume_path = [p for p in launches.paths(REVIEW) if json.loads(p.read_text())["action"] == "resume"][-1]
    assert module.read_resume_admission(launches.base, REVIEW, resume_path.stem)["failure"] == "host spawn failed"
    profile_path.write_text(original)
    monkeypatch.setattr(module, "load_wake", loading)
    # Retry the public entry with no unread mail: its producer runs normally and admits no new child.
    assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW, "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "resumed"


@pytest.mark.parametrize("case", ["start-busy", "start-custody", "resume-busy", "resume-custody",
                                  "resume-pending", "resume-limit", "stop-busy", "stop-custody-read"])
def test_r25_every_resolved_refusal_has_one_record(r2_case, capsys, monkeypatch, case):
    from contextlib import nullcontext

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    before = set(launches.paths(REVIEW))
    if "custody" in case:
        folder = launches.folder(REVIEW) / ".stop-custody"
        folder.mkdir(parents=True, mode=0o700)
        (folder / "state.json").write_text("invalid")
        (folder / "state.json").chmod(0o600)
    if case == "resume-pending":
        module.publish_wake_record(launches, REVIEW, dict(schema="aegis.hierarchy-running-wake/v2", binding=known,
            wake_id="wake-" + uuid.uuid4().hex, driver_pid=os.getpid(), host_pid=None, snapshot=None))
    if case == "resume-limit":
        paths, calls = module.Launches.paths, []
        def capped(self, endpoint):
            calls.append(True)
            return paths(self, endpoint) if len(calls) == 1 else [None] * module.MAX_RECORDS
        monkeypatch.setattr(module.Launches, "paths", capped)
    if case == "stop-custody-read":
        module.process_census = lambda session: module.ProcessCensus([], "unproven")
    action = case.split("-")[0]
    words = (["start", "--request", str(r2_case.launch.start_request())] if action == "start" else
             [action, "--endpoint", REVIEW])
    lock = module.stop_endpoint_lock(launches.mailbox.root, REVIEW) if case.endswith("busy") else nullcontext()
    with lock:
        assert module.main(["--base", str(launches.base), *words]) == 2
    answer = json.loads(capsys.readouterr().out)
    if case == "resume-limit":
        monkeypatch.setattr(module.Launches, "paths", paths)
    added = set(launches.paths(REVIEW)) - before
    assert len(added) == 1
    assert json.loads(added.pop().read_text()) == answer
    assert answer["state"] == "refused" and answer["action"] == action
    assert all(answer[key] == value for key, value in known.items())
    reason = "busy" if case.endswith("busy") else "in flight" if case.endswith("pending") else "limit" if case.endswith("limit") else "stop custody"
    assert reason in answer["error"]


@pytest.mark.parametrize("original", ["partial", "snapshot"])
@pytest.mark.parametrize("replacement_view", ["unavailable", "zombie", "foreign", "settled-empty"])
def test_r25_argon_replacement_birth_survives_filtering_and_recovery(r2_case, capsys, original, replacement_view):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    survivor = r2_case.spawn(None)
    replacement = r2_case.spawn(None)
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    current = module.read_process(replacement.pid).snapshot
    # MODELLED historical B1 versus this independently captured physical B2. G has a real live member.
    old = current._replace(start_time="100", pgid=survivor.pid, argv=("codex", "exec", "resume", session))
    partial = dict(start_time="100", coherent_birth=True, pgid=survivor.pid)
    observed = dict(candidates={replacement.pid: old if original == "snapshot" else None},
                    initial_unavailable={replacement.pid: partial}, blocked=set(), identity_lost=set(), resolved={},
                    owned_groups={survivor.pid})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(observed, set())
    reading, census, first, exited = module.read_process, module.process_census, [], []
    def exit_replacement():
        if not exited:
            replacement.send_signal(signal.SIGTERM)
            assert replacement.wait(timeout=5) == -signal.SIGTERM
            exited.append(True)
    def sampled(pid, *args, **kwargs):
        observation = reading(pid, *args, **kwargs)
        if pid != replacement.pid or exited:
            return observation
        if replacement_view == "settled-empty" and first:
            exit_replacement()
            return reading(pid, *args, **kwargs)
        first.append(True)
        row = observation.snapshot
        if replacement_view in ("zombie", "settled-empty"):
            return module.ProcessObservation("PRESENT", pid, row._replace(
                state="Z" if replacement_view == "zombie" else "R", cmdline=b"", argv=()))
        facts = dict(start_time=row.start_time, coherent_birth=True, pgid=row.pgid,
                     uid=row.uid + (1 if replacement_view == "foreign" else 0), euid=row.euid)
        return module.ProcessObservation("UNAVAILABLE", pid, reason="modelled replacement metadata unavailable", partial=facts)
    module.read_process = sampled
    def discovered(session):
        result = census(session)
        exit_replacement()  # B2 disappears before recovery polls P again.
        return result
    module.process_census = discovered
    code, answer = r2_case.stop(module, capsys, 0)
    assert first and exited and code == 3 and answer["state"] == "stop_failed"
    with module.StopCustody(launches, REVIEW, known, create=False) as custody:
        saved = custody.read()[0]
    entry = next(e for e in saved["entries"] if e["pid"] == replacement.pid)
    assert entry["identity_lost"] is True and entry["resolved"] is None
    assert answer["unresolved_groups"] == [survivor.pid]
    survivor.send_signal(signal.SIGTERM)
    assert survivor.wait(timeout=5) == -signal.SIGTERM
    # Even later ESRCH for P AND G cannot undo a witnessed loss of the original identity.
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and "original process identity lost" in answer["error"]
    assert not r2_case.projection.events


def test_r25_birthless_resolution_blocks_an_occupied_owned_pid(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    replacement = r2_case.spawn(["codex", "exec", "resume", session])
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    old = dict(candidates={replacement.pid: None}, initial_unavailable={}, blocked=set(), identity_lost=set(),
               resolved={replacement.pid: "qualified_namespace_ESRCH"})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(old, set(), active=True)
    before = custody.path.read_bytes()
    code, answer = r2_case.stop(module, capsys, 1)
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
    assert "manual reconciliation" in answer["error"]
    assert replacement.poll() is None and not r2_case.projection.events
    assert custody.path.read_bytes() == before


def test_r25_recovered_group_budget_is_checked_before_admission(r2_case, monkeypatch):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = module.binding_identity(launches.binding(REVIEW))
    # MODELLED negative-only group obligations. No process or signal authority is fabricated.
    saved = dict(candidates={}, initial_unavailable={}, blocked=set(), identity_lost=set(), resolved={},
                 owned_groups={400001})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(saved, set())
        before = custody.path.read_bytes()
        allocations = []
        class CountedGroups(set):
            def add(self, item):
                super().add(item)
                allocations.append(len(self))
            def update(self, items):
                super().update(items)
                allocations.append(len(self))
        groups = CountedGroups({400002})
        observed = dict(candidates={}, initial_unavailable={}, blocked=set(), identity_lost=set(), resolved={},
                        unresolved={}, handles={}, census={}, argv_boundaries="proven", owned_groups=groups)
        monkeypatch.setattr(module, "MAX_RECORDS", 1)
        with pytest.raises(ValueError, match="^stop custody exceeds group limit$"):
            custody.restore(observed, set())
        assert groups == {400002} and not allocations
        assert custody.path.read_bytes() == before
    assert not r2_case.projection.events


def test_r25_an_owned_host_sharing_the_callers_group_keeps_group_custody(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    actor = r2_case.spawn(["codex", "exec", "resume", session], new_session=False)
    group = r2_kernel_process(actor.pid)["pgid"]
    assert group == os.getpgrp() and group > 0
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert actor.wait(timeout=5) == -signal.SIGTERM
    # The invoker keeps this actual group nonempty after the owned instance has exited.
    assert code == 3 and answer["state"] == "stop_failed" and answer["unresolved_groups"] == [group]
    assert answer["pids"] == [actor.pid]
    assert r2_case.projection.events == [(actor.pid, signal.SIGTERM)]


def test_r25_unreaped_zombie_keeps_group_custody(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    actor = r2_case.spawn(["codex", "exec", "resume", session])
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    module.write_running_wake(launches, REVIEW, module.binding_identity(launches.binding(REVIEW)),
                              "wake-" + uuid.uuid4().hex, actor.pid)
    r2_case.projection.group_reaping = False
    actor.send_signal(signal.SIGTERM)
    wait_until(lambda: os.waitid(os.P_PID, actor.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["unresolved_groups"] == [actor.pid]
    assert module.read_running_wake(launches.base, REVIEW) is not None
    assert actor.wait(timeout=5) == -signal.SIGTERM
    assert r2_case.stop(module, capsys, 0)[0] == 0


@pytest.mark.parametrize("mislabeled", [False, True])
def test_r25_only_kernel_esrch_discharges_group(r2_case, mislabeled):
    import errno
    module = r2_case.module(False)
    def probe(group, number):
        assert group == 400001 and number == 0
        raise ProcessLookupError(errno.EIO if mislabeled else errno.ESRCH, "modelled kernel errno")
    module.os.killpg = probe
    assert module.process_group_exited(400001) is (not mislabeled)


@pytest.mark.parametrize("operation", ["read", "write"])
def test_r25_admission_metadata_refuses_unsupported_descriptors(r2_case, monkeypatch, operation):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    identifier = launches.new_id()
    monkeypatch.setattr(module, "launch_descriptor_capable", lambda: False)
    with pytest.raises(ValueError, match="^resume admission descriptors unsupported on this platform$"):
        if operation == "read":
            module.read_resume_admission(launches.base, REVIEW, identifier)
        else:
            module.write_resume_admission(launches, REVIEW, identifier,
                module.binding_identity(launches.binding(REVIEW)), module.timestamp(), False)


def test_r25_failed_spawn_retirement_names_failure_and_exact_recovery(r2_case, capsys, monkeypatch):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r25-spawn-and-retirement-failure")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    loading, unlinking, faults = module.load_wake, module.os.unlink, []
    def loaded(launches):
        wake = loading(launches)
        def failed(*args, **kwargs):
            raise OSError(2, "modelled host spawn failed")
        wake.start_turn = failed
        return wake
    monkeypatch.setattr(module, "load_wake", loaded)
    def denied(name, *args, **kwargs):
        if name == ".running-wake":
            faults.append(True)
            raise PermissionError("modelled admission retirement denied")
        return unlinking(name, *args, **kwargs)
    module.os.unlink = denied
    launches = module.Launches(str(r2_case.launch.base))
    try:
        assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW]) == 3
        answer = json.loads(capsys.readouterr().out)
        assert answer["wake"]["state"] == "stop_unconfirmed" and faults == [True] and not actors
        path = launches.paths(REVIEW)[-1]
        assert module.read_resume_admission(launches.base, REVIEW, path.stem)["failure"] == "host spawn failed"
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 3 and answer["error"] == ("wake admission identity is unavailable; " +
                                                module.running_wake_recovery(launches.base, REVIEW))
        assert ".running-wake" in answer["error"] and "mv -i --" in answer["error"]
    finally:
        module.os.unlink = unlinking
        module.clear_running_wake(launches.base, REVIEW, module.read_running_wake(launches.base, REVIEW))


@pytest.mark.parametrize("reply", ["driver-error", "contradictory-noop", "explicit-noop"])
def test_r25_handoff_uses_private_admission_when_public_resume_is_refused(r2_case, capsys, reply):
    import errno
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    def driver(command, **options):
        assert "_resume-wake" in command
        if reply == "driver-error":
            raise OSError(errno.ENOEXEC, "modelled opaque driver failure")
        answer = dict(state="nothing_unread", _admission_attempted=reply != "explicit-noop")
        return subprocess.CompletedProcess(command, 2, json.dumps(answer))
    module.subprocess.run = driver
    launches = module.Launches(str(r2_case.launch.base))
    assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert "admission_attempted" not in answer
    path = launches.paths(REVIEW)[-1]
    assert module.read_resume_admission(launches.base, REVIEW, path.stem)["admission_attempted"] is (reply != "explicit-noop")
    control = handoff_module()
    control.hierarchy_launcher = module
    expected = 0 if reply == "explicit-noop" else 2
    result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, expected)
    if expected:
        assert "latest launch status is refused (resume)" in result["error"]
    assert not r2_case.projection.events


@pytest.mark.parametrize("surface", ["admission", "launch-read", "custody-read", "custody-write"])
@pytest.mark.parametrize("failure", [OSError, ValueError], ids=["io", "value"])
def test_r23_fdopen_failure_closes_every_transferred_descriptor(r2_case, capsys, monkeypatch, surface, failure):
    import errno

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    actors, held = [], None
    if surface == "admission":
        r2_case.launch.publish_to(REVIEW, "r23-fdopen-failure")
        actors = r22_wake_processes(r2_case, module, monkeypatch)
    elif surface == "launch-read":
        assert r2_case.stop(module, capsys, 0)[0] == 0
    else:
        held = r2_case.spawn(["codex", "exec", "resume", r2_case.launch.binding()["session"]])
        if surface == "custody-read":
            assert r2_case.stop(module, capsys, 0)[0] == 0
            assert held.wait(timeout=5) == -signal.SIGTERM
    before = list(r2_case.projection.events)
    opening, transferred = module.os.fdopen, []
    def failed(fd, mode, *args, **kwargs):
        path = Path(os.readlink("/proc/self/fd/%d" % fd))
        selected = ((surface == "admission" and path.name.startswith(".running-wake-")) or
                    (surface == "launch-read" and mode == "rb" and path.parent.name == module.quoted(REVIEW)) or
                    (surface == "custody-read" and mode == "rb" and path.name == "state.json" and
                     path.parent.name == ".stop-custody") or
                    (surface == "custody-write" and mode == "wb" and path.parent.name == ".stop-custody"))
        if selected:
            info = os.fstat(fd)
            transferred.append((fd, (info.st_dev, info.st_ino)))
            if failure is OSError:
                raise OSError(errno.EIO, "modelled fdopen construction failure")
            raise ValueError("modelled fdopen construction failure")
        return opening(fd, mode, *args, **kwargs)
    module.os.fdopen = failed
    def still_owns(fd, identity):
        try:
            info = os.fstat(fd)
        except OSError as exc:
            assert exc.errno == errno.EBADF
            return False
        return (info.st_dev, info.st_ino) == identity
    try:
        if surface == "admission":
            code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW])
            answer = json.loads(capsys.readouterr().out)
            assert code == 3 and answer["wake"]["state"] == "failed_to_start" and not actors
            launches = module.Launches(str(r2_case.launch.base))
            assert not list(launches.folder(REVIEW).glob(".running-wake*"))
            assert not launches.mailbox.wake_marker(REVIEW).exists()
        elif surface == "launch-read":
            code = module.main(["--base", str(r2_case.launch.base), "status", "--endpoint", REVIEW])
            answer = json.loads(capsys.readouterr().out)
            assert code == 0 and answer["endpoints"][REVIEW]["state"] == "unknown"
        else:
            code, answer = r2_case.stop(module, capsys, 0)
            assert code == 2 and answer["state"] == "refused" and "stop custody unavailable" in answer["error"]
            assert surface != "custody-write" or held.poll() is None
        assert transferred and r2_case.projection.events == before
        assert not any(still_owns(fd, identity) for fd, identity in transferred)
    finally:
        # RED must close its own leaked descriptor without ever closing a reused numeric FD.
        for fd, identity in transferred:
            if still_owns(fd, identity):
                os.close(fd)


@pytest.mark.parametrize("order", ["id-first", "fork-first"])
@pytest.mark.parametrize("surface", ["stop", "handoff"])
def test_r23_fork_selected_session_cannot_escape_stop_or_handoff(r2_case, capsys, order, surface):
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    source = r2_case.launch.tmp / "source.jsonl"
    source.write_text("{}\n")
    arguments = (["--session-id", session, "--fork-session", "--resume", str(source)] if order == "id-first" else
                 ["--fork-session", "--resume", str(source), "--session-id", session])
    held = r2_case.spawn(["claude", *arguments])
    if surface == "stop":
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        control = handoff_module()
        control.hierarchy_launcher = module
        spec = spec_for(r2_case.launch)
        before = mailbox_files(r2_case.launch.base)
        answer = run_main(control, r2_case.launch, spec, capsys, 2)
        assert "live process remains" in answer["error"] and str(held.pid) in answer["error"]
        assert mailbox_files(r2_case.launch.base) == before and held.poll() is None
        assert not r2_case.projection.events


@pytest.mark.parametrize("origin", ["admission-null", "incoherent-census"])
@pytest.mark.parametrize("surface", ["stop", "resume", "start", "handoff"])
def test_r23_birthless_terminal_claim_requires_reconciliation_on_reuse(r2_case, capsys, origin, surface):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    held = r2_case.spawn(["python3", "unrelated-reused-pid.py"])
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    partial = {} if origin == "admission-null" else {"coherent_birth": False, "start_time": "1"}
    # MODELLED historical ESRCH and numeric reuse; the present unrelated occupant is physically owned.
    # A writable terminal claim grants no release while that PID is occupied, even after honest reuse.
    observed = dict(candidates={held.pid: None}, initial_unavailable={held.pid: partial}, blocked=set(),
                    identity_lost=set(), resolved={held.pid: "qualified_namespace_ESRCH"})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(observed, set(), active=False)
    before = custody.path.read_bytes()
    binding = launches.binding(REVIEW)
    if surface == "stop":
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
    elif surface == "resume":
        assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW, "--dry-run"]) == 2
        answer = json.loads(capsys.readouterr().out)
        assert answer["state"] == "refused"
    elif surface == "start":
        path = r2_case.launch.start_request()
        assert module.main(["--base", str(launches.base), "start", "--request", str(path)]) == 2
        answer = json.loads(capsys.readouterr().out)
        assert answer["state"] == "refused"
    else:
        control = handoff_module()
        control.hierarchy_launcher = module
        answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
    assert "manual reconciliation" in answer["error"]
    assert launches.binding(REVIEW) == binding
    assert held.poll() is None and not r2_case.projection.events and custody.path.read_bytes() == before


def r23_cleanup_scope(case, module):
    import contextlib
    import io
    from tests.integration.test_hierarchy_native_probe import Probe

    folder = case.launch.tmp / "r23-cleanup-probe"
    folder.mkdir()
    probe = Probe(folder)
    plan = probe.plan([{"role": "implementer"}])
    plan["roles"][0].update(base=str(case.launch.base), endpoint=REVIEW)
    (probe.root / "probe.json").write_text(json.dumps(plan))
    (probe.codex_home / "auth.json").write_text("test-owned disposable credential")
    control = r16_cleanup_control(probe, module)
    runner = control.Runner
    class ScopedRunner(runner):
        def launcher(self, base, *words):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = module.main(["--base", base, *words])
            return code, json.loads(output.getvalue())
    control.Runner = ScopedRunner
    return probe, plan, control


@pytest.mark.parametrize("fault", ["before-stop", "after-stop", "symlink", "inspection", "unsupported", "namespace", "identity"])
def test_r23_cleanup_holds_pending_mailbox_admission(r2_case, capsys, monkeypatch, fault):
    import shutil
    from tests.conftest import symlink_or_skip

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    marker = launches.mailbox.wake_marker(REVIEW)
    # MODELLED OS boundary: this test admits no host. Other xdist actors are outside this empty cohort.
    module.process_census = lambda session: module.ProcessCensus([], "proven")
    probe, plan, control = r23_cleanup_scope(r2_case, module)
    changed, identity_fds = [], []
    base = r2_case.launch.base
    original, replacement = base.with_name(base.name + "-r23-old"), base.with_name(base.name + "-r23-new")
    try:
        def claim():
            with control.writer_lock(launches.mailbox.root):
                module.load_wake(launches).claim_wake(launches.mailbox, REVIEW)
        if fault in ("before-stop", "inspection"):
            claim()
        elif fault == "symlink":
            symlink_or_skip(base / "missing-marker-target", marker)
        elif fault == "after-stop":
            runner = control.Runner
            class LateClaim(runner):
                def launcher(self, *args):
                    result = super().launcher(*args)
                    assert result[0] == 0 and result[1]["wake_marker_present"] is False
                    claim()
                    return result
            control.Runner = LateClaim
        elif fault == "unsupported":
            monkeypatch.setattr(module, "mailbox_wake_inspection_capable", lambda: False)
        else:
            shutil.copytree(base, replacement)
            alternate = replacement / "mailbox" / marker.name
            alternate.write_text("waiting producer")
            alternate.chmod(0o600)
        statting = module.os.stat
        def inspected(name, *args, **kwargs):
            if name == marker.name and kwargs.get("dir_fd") is not None:
                if fault == "inspection":
                    changed.append(True)
                    raise PermissionError("modelled mailbox marker inspection denied")
                if fault == "namespace" and not changed:
                    base.rename(original)
                    replacement.rename(base)
                    changed.append(True)
            return statting(name, *args, **kwargs)
        module.os.stat = inspected
        fstatting = module.os.fstat
        def identified(fd):
            if fault == "identity" and Path(os.readlink("/proc/self/fd/%d" % fd)) == launches.mailbox.root:
                info = fstatting(fd)
                identity_fds.append((fd, info.st_dev, info.st_ino))
                raise OSError(5, "modelled descriptor identity read failed")
            return fstatting(fd)
        module.os.fstat = identified
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)["cleanup"]
        assert code == 3 and not answer["worktree_removed"] and Path(plan["worktree"]).is_dir()
        assert answer["auth_removed"] and not (probe.codex_home / "auth.json").exists()
        if fault == "identity":
            # R28's writer-root witness rejects this FD fault before marker inspection begins.
            assert any(row["reason"] == module.ENDPOINT_NAMESPACE_CHANGED for row in answer["unresolved_custody"])
        else:
            assert any("mailbox wake" in row["reason"] for row in answer["unresolved_custody"])
        if fault in ("inspection", "namespace"):
            assert changed
        if fault == "identity":
            assert identity_fds
            for fd, _, _ in identity_fds:
                with pytest.raises(OSError) as error:
                    os.fstat(fd)
                assert error.value.errno == 9
        assert not r2_case.projection.events
    finally:
        for fd, dev, ino in identity_fds:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (dev, ino):
                os.close(fd)
        if fault == "namespace" and changed:
            base.rename(replacement)
            original.rename(base)
        if marker.is_symlink() or marker.exists():
            marker.unlink()
        probe.close()


def test_r23_handoff_checks_a_dangling_marker_before_legacy_absence(r2_case, capsys):
    from tests.conftest import symlink_or_skip
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    marker = launches.mailbox.wake_marker(REVIEW)
    symlink_or_skip(r2_case.launch.tmp / "missing-wake-owner", marker)
    assert not launches.folder(REVIEW).exists()
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = spec_for(r2_case.launch)
    before = mailbox_files(r2_case.launch.base)
    answer = run_main(control, r2_case.launch, spec, capsys, 3)
    assert not answer["ok"] and "wake" in answer["entries"][0]["error"]
    assert mailbox_files(r2_case.launch.base) == before
    assert marker.is_symlink() and not r2_case.projection.events


@pytest.mark.parametrize("other_failure", [False, True], ids=["custody-only", "keep-unrelated-hold"])
def test_r23_cleanup_rechecks_custody_after_its_fenced_stop(r2_case, capsys, other_failure):
    from contextlib import contextmanager

    held, journal, _ = r7_pending_attempt(r2_case, capsys)
    module = r2_case.module(False)
    census = module.process_census
    def cohort(session):
        rows = census(session)
        return module.ProcessCensus([row for row in rows if row.pid == held.pid], rows.argv_boundaries,
                                    {pid: row for pid, row in rows.unavailable.items() if pid == held.pid})
    module.process_census = cohort  # MODELLED one-actor OS cohort; all fields and signals remain physical.
    probe, plan, control = r23_cleanup_scope(r2_case, module)
    locking, faults = control.cleanup_locks, []
    @contextmanager
    def busy_once(roles):
        if other_failure and not faults:
            faults.append(True)
            raise ValueError("modelled unrelated precheck lock busy")
        with locking(roles) as scopes:
            yield scopes
    control.cleanup_locks = busy_once
    try:
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)["cleanup"]
        assert held.wait(timeout=5) == -signal.SIGKILL
        assert not json.loads(journal.read_text())["active"]
        assert answer["auth_removed"] and answer["leftover_processes"] == []
        if other_failure:
            assert code == 3 and Path(plan["worktree"]).is_dir() and not answer["worktree_removed"]
            assert [row["reason"] for row in answer["unresolved_custody"]] == ["modelled unrelated precheck lock busy"]
        else:
            assert code == 0 and answer["worktree_removed"] and not Path(plan["worktree"]).exists()
            assert not answer.get("unresolved_custody")
            assert r2_case.launch.binding()["session"] in answer["found_running"]
    finally:
        probe.close()


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_r22_unidentified_admitted_wrapper_is_not_absence(r2_case, capsys, host):
    session = str(uuid.uuid4())
    r2_case.bind(host, session)
    held = r2_case.spawn(["sh", "wrapper-awaiting-exec.sh"])
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    read, missing = module.read_process, []
    def unavailable(pid, *args):
        if pid == held.pid and not missing:
            missing.append(True)
            return module.ProcessObservation("UNAVAILABLE", pid, reason="modelled pre-exec metadata unavailable")
        return read(pid, *args)
    module.read_process = unavailable
    record = module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, held.pid)
    assert missing and record["snapshot"] is None
    path = launches.folder(REVIEW) / ".running-wake"
    before = path.read_bytes()
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and held.pid in answer["unresolved_pids"]
    assert held.poll() is None and not r2_case.projection.events and path.read_bytes() == before
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "not_running" and not path.exists()


@pytest.mark.parametrize("visibility", ["permission-denied", "unsupported-probe"])
def test_r22_restricted_procfs_has_an_explicit_manual_refusal(r2_case, capsys, monkeypatch, visibility):
    import errno

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    held = r2_case.spawn(["python3", "foreign-reuse.py"])
    module = r2_case.module(False)
    current = module.read_process(held.pid).snapshot
    historical = current._replace(start_time=str(int(current.start_time) - 1))
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    observed = dict(candidates={held.pid: historical}, initial_unavailable={}, blocked=set(), identity_lost=set(),
                    resolved={held.pid: "qualified_namespace_ESRCH"})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(observed, set(), active=False)
    path, faults = custody.path, []
    before = path.read_bytes()
    if visibility == "permission-denied":
        def denied(path, raw):
            if str(path).startswith("/proc/%d/" % held.pid):
                faults.append(str(path))
                raise PermissionError(errno.EACCES, "modelled restricted procfs")
            return raw
        r2_case.projection.path_view(module, denied)
        killing = module.os.kill
        def denied_existence(pid, number):
            if pid == held.pid and number == 0:
                faults.append("kill-zero-EPERM")
                raise PermissionError(errno.EPERM, "modelled foreign PID visibility")
            return killing(pid, number)
        module.os.kill = denied_existence
    else:
        def unsupported(observation):
            faults.append(observation.kind)
            return False
        monkeypatch.setattr(module, "procfs_exit_evidence_supported", unsupported)
    r22_wake_processes(r2_case, module, monkeypatch)
    code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW, "--dry-run"])
    answer = json.loads(capsys.readouterr().out)
    assert code == 2 and faults
    assert "stop custody unsupported on hidepid/restricted procfs" in answer["error"]
    assert "manual reconciliation" in answer["error"] and str(path) in answer["error"]
    assert held.poll() is None and not r2_case.projection.events and path.read_bytes() == before


@pytest.mark.parametrize("change", ["exec-during-census", "setuid-descendant"])
@pytest.mark.parametrize("check", ["guidance", "exit-admission"])
def test_r22_blocked_same_birth_exits_or_explains_reconciliation(r2_case, capsys, monkeypatch, change, check):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module, changed = r2_case.module(False), []
    if change == "exec-during-census":
        trigger = r2_case.launch.tmp / "r22-exec-now"
        ready = r2_case.launch.tmp / "r22-exec-ready"
        exiting = r2_case.launch.tmp / "r22-exec-exit"
        script = r2_case.launch.tmp / "r22-replacement.py"
        script.write_text("import pathlib,sys,time\n"
                          "pathlib.Path(sys.argv[2]).touch()\n"
                          "deadline=time.monotonic()+30\n"
                          "while not pathlib.Path(sys.argv[1]).exists() and time.monotonic()<deadline: time.sleep(.01)\n")
        replacement = [sys.executable, str(script), str(exiting), str(ready)]
        body = ("import os,time\nfrom pathlib import Path\n"
                "deadline=time.monotonic()+10\n"
                "while not Path(%r).exists() and time.monotonic()<deadline: time.sleep(.01)\n"
                "os.execv(%r, %r)\n") % (str(trigger), sys.executable, replacement)
        held = r2_case.spawn_legacy([sys.executable], ["claude", "--resume", session], body, {})
        birth = r2_kernel_process(held.pid)["birth"]
        reading, physical = module.read_process, launcher_module().read_process
        def observed(pid, *args):
            # No receipt renewal: an actual exec invalidates the original raw cmdline. The fresh
            # physical reader supplies only negative drift evidence, never a logical host identity.
            return physical(pid, *args) if changed and pid == held.pid else reading(pid, *args)
        module.read_process = observed
        census = module.process_census
        def captured(bound):
            rows = census(bound)
            if not changed:
                assert any(row.pid == held.pid for row in rows)
                trigger.touch()
                wait_until(lambda: ready.exists())
                actual = r2_kernel_process(held.pid)
                assert actual["birth"] == birth
                assert actual["raw"] == b"\0".join(os.fsencode(word) for word in replacement) + b"\0"
                changed.append(True)
            return rows
        module.process_census = captured
    else:
        family = r2_case.spawn_group(["claude", "--resume", session])
        held = family["M"]
        exiting = r2_case.configs[-1].with_suffix(".exit")
        census = module.process_census
        def captured(bound):
            rows = census(bound)
            changed.append(True)
            return rows
        module.process_census = captured
        def foreign(pid, count, row):
            # Negative-only setuid observation after the original census, on an actual descendant.
            return row._replace(uid=row.uid + 1, euid=row.euid + 1) if changed and pid == held.pid else row
        r2_case.projection.after_present.append(foreign)

    code, answer = r2_case.stop(module, capsys, 0)
    assert changed and code == 3 and held.pid in answer["unresolved_pids"] and held.poll() is None
    assert all(pid != held.pid for pid, _ in r2_case.projection.events)
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    entry = next(row for row in json.loads(path.read_text())["entries"] if row["pid"] == held.pid)
    assert entry["blocked"] is (change == "setuid-descendant")
    assert entry["identity_lost"] is (change == "setuid-descendant")
    if check == "guidance":
        if change == "setuid-descendant":
            assert "manual reconciliation" in answer["error"] and str(path) in answer["error"]
        assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW, "--dry-run"]) == 2
        refusal = json.loads(capsys.readouterr().out)["error"]
        if change == "setuid-descendant":
            assert "manual reconciliation" in refusal and str(path) in refusal
        else:
            assert "stop custody unresolved" in refusal and "stop --endpoint " + REVIEW in refusal
    exiting.touch()
    if change == "exec-during-census":
        assert held.wait(timeout=5) == 0  # Reaped direct child supplies actual qualified ESRCH.
    else:
        wait_until(lambda: held.poll() == "CONFIRMED_EXIT")
        assert family["H"].wait(timeout=5) == -signal.SIGTERM
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    if change == "setuid-descendant":
        assert code == 3 and held.pid in answer["unresolved_pids"]
        assert module.unresolved_stop_custody(str(r2_case.launch.base), REVIEW)
        assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW, "--dry-run"]) == 2
        assert "manual reconciliation" in json.loads(capsys.readouterr().out)["error"]
        return
    assert code == 0 and not answer.get("unresolved_pids")
    assert not module.unresolved_stop_custody(str(r2_case.launch.base), REVIEW)
    r22_wake_processes(r2_case, module, monkeypatch)
    actors = len(r2_case.configs)
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW, "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "resumed"
    assert len(r2_case.configs) == actors


def r22_admitted_orphan(case, module, evidence):
    """Actual P/M/W topology, P's isolated group and physical exits; only host argv is MODELLED."""
    session = case.launch.binding()["session"]
    family = case.spawn(["codex", "exec", "resume", session], tree=True,
                        middle_argv=["python3", "intermediary.py"], worker_argv=["python3", "worker.py"])
    read = module.read_process
    if evidence == "null":
        module.read_process = lambda pid, *args: (module.ProcessObservation("UNAVAILABLE", pid,
            reason="modelled admission metadata unavailable") if pid == family["H"].pid else read(pid, *args))
    launches = module.Launches(str(case.launch.base))
    known = {key: case.launch.binding()[key] for key in ("host", "session", "generation")}
    record = module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, family["H"].pid)
    module.read_process = read
    assert (record["snapshot"] is None) == (evidence == "null")
    assert os.getpgid(family["W"].pid) == family["H"].pid

    def exit_roots():
        for label in ("H", "M"):
            slot = next(slot for slot, row in case.custody.entries.items() if row["pid"] == family[label].pid)
            case.custody.kill_owned(slot)
        assert family["H"].wait(timeout=5) == -signal.SIGKILL
        wait_until(lambda: family["M"].poll() == "CONFIRMED_EXIT")
        assert family["W"].poll() is None

    if evidence == "null":
        exit_roots()
    else:
        census, pending = module.process_census, [True]
        def after_census(bound):
            if not pending:
                return census(bound)
            pending.pop()
            module.read_process = lambda pid, *args: (module.ProcessObservation("UNAVAILABLE", pid,
                reason="modelled current host metadata unavailable") if pid == family["H"].pid else read(pid, *args))
            try:
                result = census(bound)
            finally:
                module.read_process = read
            assert family["H"].pid in result.unavailable
            exit_roots()
            return result
        module.process_census = after_census
    return family, launches.folder(REVIEW) / ".running-wake"


@pytest.mark.parametrize("evidence", ["null", "unavailable-census"])
def test_r22_admitted_group_survivor_remains_unresolved(r2_case, capsys, evidence):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    family, path = r22_admitted_orphan(r2_case, module, evidence)
    before = path.read_bytes()
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed"
    assert family["W"].pid in answer["unresolved_pids"] and family["W"].poll() is None
    assert not r2_case.projection.events and path.read_bytes() == before
    assert module.unresolved_stop_custody(str(r2_case.launch.base), REVIEW)
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW, "--dry-run"]) == 2
    assert "stop custody" in json.loads(capsys.readouterr().out)["error"]
    r2_case.configs[-1].with_suffix(".exit").touch()
    wait_until(lambda: family["W"].poll() == "CONFIRMED_EXIT")
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 0 and not answer.get("unresolved_pids") and not path.exists()
    assert not r2_case.projection.events


def test_r22_cleanup_holds_a_concurrently_admitted_orphan(r2_case, capsys):
    import contextlib
    import io
    from tests.integration.test_hierarchy_native_probe import Probe

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    folder = r2_case.launch.tmp / "r22-wake-probe"
    folder.mkdir()
    probe, concurrent = Probe(folder), []
    try:
        plan = probe.plan([{"role": "implementer"}])
        plan["roles"][0].update(base=str(r2_case.launch.base), endpoint=REVIEW)
        (probe.root / "probe.json").write_text(json.dumps(plan))
        auth = probe.codex_home / "auth.json"
        auth.write_text("test-owned disposable credential")
        control = r16_cleanup_control(probe, module)
        runner = control.Runner
        class ScopedRunner(runner):
            def launcher(self, base, *words):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = module.main(["--base", base, *words])
                assert code == 0
                concurrent.append(r22_admitted_orphan(r2_case, module, "null"))
                return code, json.loads(output.getvalue())
        control.Runner = ScopedRunner
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)["cleanup"]
        assert concurrent and code == 3 and not answer["worktree_removed"]
        assert Path(plan["worktree"]).is_dir() and answer["auth_removed"] and not auth.exists()
        assert any("cleanup wake still pending; preserve the worktree" in row["reason"]
                   for row in answer["unresolved_custody"])
        family, path = concurrent[0]
        assert family["W"].poll() is None and path.is_file() and not r2_case.projection.events
    finally:
        for family, _ in concurrent:
            r2_case.configs[-1].with_suffix(".exit").touch()
            wait_until(lambda: family["W"].poll() == "CONFIRMED_EXIT")
        probe.close()


@pytest.mark.parametrize("fault_scope", ["other-case", "this-case"])
def test_r23_census_cohort_preserves_its_own_unavailable_actors(r2_case, capsys, fault_scope):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    projection = r2_case.projection
    try:
        r2_case.projection = R2Processes(r2_case.launch.tmp / "r23-other-case-projection")
        noise = r2_case.spawn(["python3", "unrelated-case.py"])
    finally:
        r2_case.projection = projection
    held = r2_case.spawn(["codex", "exec", "resume", session])
    module = r2_case.module(False)
    reading = module.read_process
    target = noise.pid if fault_scope == "other-case" else held.pid
    def unavailable(pid, *args, **kwargs):
        if pid == target:
            return module.ProcessObservation("UNAVAILABLE", pid, reason="modelled unreadable actor",
                                             partial={"coherent_birth": False})
        return reading(pid, *args, **kwargs)
    module.read_process = unavailable
    code, answer = r2_case.stop(module, capsys, 0)
    if fault_scope == "other-case":
        assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM
        assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    else:
        assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
        assert answer["unresolved_pids"] == [held.pid] and held.poll() is None
        assert not r2_case.projection.events
    assert noise.poll() is None


def test_r23_census_does_not_hide_a_deleted_unverified_receipt(r2_case):
    session = str(uuid.uuid4())
    held = r2_case.spawn(["codex", "exec", "resume", session])
    module = r2_case.module(False)
    del r2_case.projection.receipts[str(held.pid)]
    with pytest.raises(RuntimeError, match="^R2 fixture: stale/unknown projection receipt; no native fallback$"):
        module.session_processes(session, set(), "codex-cli")
    assert held.poll() is None and not r2_case.projection.events


@pytest.mark.parametrize("visibility", ["readable", "empty"])
def test_r23_verified_projection_cannot_be_changed_to_native(r2_case, visibility):
    session = str(uuid.uuid4())
    held = r2_case.spawn(["codex", "exec", "resume", session])
    module = r2_case.module(False)
    module.read_process(held.pid)
    r2_case.projection.receipts[str(held.pid)]["argv"] = None
    if visibility == "empty":
        def empty(path, raw):
            return b"" if str(path) == "/proc/%d/cmdline" % held.pid else raw
        r2_case.projection.path_view(module, empty)
    with pytest.raises(RuntimeError, match="^R2 fixture: stale/unknown projection receipt; no native fallback$"):
        module.session_processes(session, set(), "codex-cli")
    assert held.poll() is None and not r2_case.projection.events


def test_r23_native_empty_observation_stays_negative_before_verification(r2_case, capsys):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    held = r2_case.spawn(None)
    module = r2_case.module(False)
    def empty(path, raw):
        return b"" if str(path) == "/proc/%d/cmdline" % held.pid else raw
    r2_case.projection.path_view(module, empty)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
    assert answer["unresolved_pids"] == [held.pid] and held.poll() is None
    assert not r2_case.projection.events


def test_r23_census_includes_new_ready_receipts_from_a_captured_child(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    receiving = r2_case.projection
    module = r2_case.module(False)
    sending = R2Processes(r2_case.launch.tmp / "r23-sending-projection")
    try:
        r2_case.projection = sending
        held = r2_case.spawn(["codex", "exec", "resume", session])
    finally:
        r2_case.projection = receiving
    # The same fixture physically owns this Popen before its unchanged READY receipt is transported.
    receiving.receipts.setdefault(str(held.pid), dict(sending.receipts[str(held.pid)]))
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM
    assert receiving.events == [(held.pid, signal.SIGTERM)] and not sending.events


@pytest.mark.parametrize("late_capture", [False, True])
def test_r24_probe_census_transports_captures_once_before_reading_them(r2_case, late_capture):
    from tests.integration.test_hierarchy_native_probe import ModelledProbeClient

    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    actors = []
    if not late_capture:
        actors = [r2_case.spawn(["codex", "exec", "resume", session]) for _ in range(2)]
    client = ModelledProbeClient({"receipt": str(r2_case.projection.path),
                                 "receipt_nonce": r2_case.projection.nonce})
    requests = []
    def broker(operation, **values):
        assert operation == "observe" and not values
        requests.append(operation)
        return {}
    client.request = broker  # Only the IPC boundary is modelled; receipts and every PID observation are real.
    module = client.reader()
    if late_capture:
        actors = [r2_case.spawn(["codex", "exec", "resume", session]) for _ in range(2)]
    requests.clear()
    found = module.session_processes(session, set(), "codex-cli")
    assert {pid for pid, _ in found} == {actor.pid for actor in actors}
    assert requests == ["observe"]
    assert all(actor.poll() is None for actor in actors) and not r2_case.projection.events


def test_r23_running_birth_survives_an_unavailable_census(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    held = r2_case.spawn(["python3", "unrelated-replacement.py"])
    module = r2_case.module(False)
    current = module.read_process(held.pid).snapshot
    original = current._replace(start_time=str(int(current.start_time) - 1))
    read = module.read_process
    # MODELLED historical T1 admission; the replacement's T2 and physical exit remain actual.
    module.read_process = lambda pid, *args: (module.ProcessObservation("PRESENT", pid, original)
                                            if pid == held.pid else read(pid, *args))
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, held.pid)
    module.read_process = read
    census, calls, replacement = module.process_census, [], []
    def unavailable(session):
        actual = census(session)
        calls.append(True)
        if len(calls) != 1:
            return actual
        missing = {**actual.unavailable, held.pid: module.ProcessObservation(
            "UNAVAILABLE", held.pid, reason="modelled initial census unavailable", partial={"coherent_birth": False})}
        return module.ProcessCensus([row for row in actual if row.pid != held.pid], "proven", missing)
    def replacement_then_absence(pid, *args):
        if pid == held.pid and calls:
            if replacement:
                r2_case.configs[-1].with_suffix(".exit").touch()
                assert held.wait(timeout=5) == 0
            else:
                replacement.append(True)
        return read(pid, *args)
    module.process_census = unavailable
    module.read_process = replacement_then_absence
    code, answer = r2_case.stop(module, capsys, 0)
    assert replacement and held.wait(timeout=5) == 0
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
    assert answer["error"] == module.custody_refusal(launches.base, REVIEW, "original process identity lost")
    assert not r2_case.projection.events and (launches.folder(REVIEW) / ".running-wake").is_file()
    saved = json.loads((launches.folder(REVIEW) / ".stop-custody/state.json").read_text())
    entry = next(row for row in saved["entries"] if row["pid"] == held.pid)
    assert saved["active"] and entry["snapshot"] is None
    assert entry["partial"] == dict(pid=held.pid, start_time=original.start_time, uid=original.uid,
                                    euid=original.euid, coherent_birth=True)
    assert entry["blocked"] and entry["identity_lost"] and entry["resolved"] is None and not entry["attempted"]


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_r23_resume_persists_admission_before_creating_the_host(r2_case, capsys, monkeypatch, host):
    import stat
    r2_case.bind(host, str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r23-before-spawn")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    history_before = r2_case.launch.records()
    loading, observations, synced = module.load_wake, [], []
    syncing = module.os.fsync
    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            synced.append(os.readlink("/proc/self/fd/%d" % fd))
        return syncing(fd)
    module.os.fsync = fsync
    def load(launches):
        wake = loading(launches)
        spawn = wake.subprocess.Popen
        def create(*args, **kwargs):
            record = module.read_running_wake(launches.base, REVIEW)
            records = [json.loads(path.read_text()) for path in launches.paths(REVIEW)]
            observations.append((record, records, tuple(synced)))
            child = spawn(*args, **kwargs)
            r2_case.configs[-1].with_suffix(".exit").touch()
            return child
        wake.subprocess.Popen = create
        return wake
    monkeypatch.setattr(module, "load_wake", load)
    code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW])
    answer = json.loads(capsys.readouterr().out)
    assert code == 3 and answer["state"] == "resumed_unread" and actors[0].wait(timeout=5) == 0
    admission, records, before_spawn_syncs = observations[0]
    assert admission is not None and admission["host_pid"] is None and admission["snapshot"] is None
    assert admission["binding"]["host"] == host and admission["wake_id"] == answer["wake"]["wake_id"]
    assert records == history_before
    assert {str(r2_case.launch.base), str(r2_case.launch.base / "launches")} <= set(before_spawn_syncs)
    assert not (module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".running-wake").exists()


@pytest.mark.parametrize("publication", ["write", "commit"])
def test_r23_failed_publication_and_abandonment_keep_the_unknown_group(r2_case, capsys, monkeypatch, publication):
    import errno
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r23-unsignalable-group")
    module = r2_case.module(False)
    r22_wake_processes(r2_case, module, monkeypatch)
    loading, families, denied, faults = module.load_wake, [], [], []
    def load(launches):
        wake = loading(launches)
        def spawned(*args, **kwargs):
            family = r2_case.spawn(["codex", "exec", "resume", r2_case.launch.binding()["session"]], tree=True,
                                  middle_argv=["python3", "middle.py"], worker_argv=["python3", "worker.py"])
            families.append(family)
            for label in ("H", "M"):
                slot = next(slot for slot, row in r2_case.custody.entries.items() if row["pid"] == family[label].pid)
                r2_case.custody.kill_owned(slot)
            assert family["H"].wait(timeout=5) == -signal.SIGKILL
            wait_until(lambda: family["M"].poll() == "CONFIRMED_EXIT")
            return family["H"]
        def killpg(group, number):
            denied.append(number)
            raise PermissionError("modelled unsignalable admitted group")
        wake.subprocess.Popen = spawned
        wake.os = R2Facade(os, killpg=killpg)
        return wake
    monkeypatch.setattr(module, "load_wake", load)
    opening = module.os.fdopen
    class Stream:
        def __init__(self, raw): self.raw = raw
        def __enter__(self): self.raw.__enter__(); return self
        def __exit__(self, *args): return self.raw.__exit__(*args)
        def __getattr__(self, name): return getattr(self.raw, name)
        def write(self, raw):
            if families and publication == "write":
                faults.append(True)
                raise OSError(errno.ENOSPC, "modelled post-spawn running publication full")
            return self.raw.write(raw)
    def fdopen(fd, mode, *args, **kwargs):
        name = Path(os.readlink("/proc/self/fd/%d" % fd)).name
        raw = opening(fd, mode, *args, **kwargs)
        return Stream(raw) if mode == "wb" and name.startswith(".running-wake") else raw
    module.os.fdopen = fdopen
    sync = module.os.fsync
    def fsync(fd):
        import stat
        if (publication == "commit" and families and not faults and stat.S_ISDIR(os.fstat(fd).st_mode) and
                os.readlink("/proc/self/fd/%d" % fd) == str(r2_case.launch.base / "launches" / module.quoted(REVIEW))):
            faults.append(True)
            raise OSError(errno.ENOSPC, "modelled post-promotion directory commit full")
        return sync(fd)
    module.os.fsync = fsync
    code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW])
    answer = json.loads(capsys.readouterr().out)
    assert faults and denied and families[0]["W"].poll() is None
    assert code == 3 and answer["wake"]["state"] == "stop_unconfirmed"
    launches = module.Launches(str(r2_case.launch.base))
    path = launches.folder(REVIEW) / ".running-wake"
    assert path.is_file()
    expected_pid = None if publication == "write" else families[0]["H"].pid
    assert module.read_running_wake(launches.base, REVIEW)["host_pid"] == expected_pid
    assert not launches.mailbox.wake_marker(REVIEW).exists()
    code, stopped = r2_case.stop(module, capsys, 0)
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == []
    assert publication != "write" or "admission" in stopped["error"]
    assert path.is_file() and not r2_case.projection.events
    control = handoff_module()
    control.hierarchy_launcher = module
    result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
    assert result["error"] == "stop evidence for " + REVIEW + ": a recorded wake is pending; run stop before handoff"
    assert families[0]["W"].poll() is None
    probe, plan, control = r23_cleanup_scope(r2_case, module)
    try:
        assert control.main(["cleanup", "--probe-root", str(probe.root)]) == 3
        cleanup = json.loads(capsys.readouterr().out)["cleanup"]
        assert cleanup["auth_removed"] and not cleanup["worktree_removed"] and Path(plan["worktree"]).is_dir()
        assert cleanup["unresolved_custody"] and families[0]["W"].poll() is None and not r2_case.projection.events
    finally:
        probe.close()


def test_r23_full_history_refuses_resume_before_spawning(r2_case, capsys, monkeypatch):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r23-history-limit")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    launches = module.Launches(str(r2_case.launch.base))
    monkeypatch.setattr(module, "MAX_RECORDS", len(launches.paths(REVIEW)))
    assert module.main(["--base", str(launches.base), "resume", "--endpoint", REVIEW]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert answer["error"] == "launch record limit reached for " + REVIEW
    assert not actors and module.read_running_wake(launches.base, REVIEW) is None


def test_r23_parent_outcome_failure_keeps_admission_until_a_later_stop(r2_case, capsys, monkeypatch):
    import errno
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    r2_case.launch.publish_to(REVIEW, "r23-outcome-commit-fails")
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    loading = module.load_wake
    def load(launches):
        wake = loading(launches)
        spawn = wake.subprocess.Popen
        def create(*args, **kwargs):
            child = spawn(*args, **kwargs)
            r2_case.configs[-1].with_suffix(".exit").touch()
            return child
        wake.subprocess.Popen = create
        return wake
    monkeypatch.setattr(module, "load_wake", load)
    writing, observations = module.Launches.write, []
    def failed(self, endpoint, identifier, record):
        if record["action"] == "resume" and record["state"] != "admitting":
            observations.append(module.read_running_wake(self.base, endpoint))
            raise OSError(errno.EIO, "modelled parent outcome commit failure")
        return writing(self, endpoint, identifier, record)
    monkeypatch.setattr(module.Launches, "write", failed)
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert observations and observations[0] is not None and actors[0].wait(timeout=5) == 0
    assert answer["error"] == "[Errno 5] Input/output error"
    assert "modelled parent outcome" not in json.dumps(answer)
    launches = module.Launches(str(r2_case.launch.base))
    assert module.read_running_wake(launches.base, REVIEW) == observations[0]
    assert not launches.mailbox.wake_marker(REVIEW).exists() and not r2_case.projection.events
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = spec_for(r2_case.launch)
    refused = run_main(control, r2_case.launch, spec, capsys, 2)
    assert refused["error"] == "stop evidence for " + REVIEW + ": a recorded wake is pending; run stop before handoff"
    monkeypatch.setattr(module.Launches, "write", writing)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    assert module.read_running_wake(launches.base, REVIEW) is None
    assert run_main(control, r2_case.launch, spec, capsys, 0)["entries"][0]["generation"] == 2


def test_r23_private_worker_checks_history_room_before_spawning(r2_case, capsys, monkeypatch):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r23-worker-limit")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    loading = module.load_wake
    def load(launches):
        wake = loading(launches)
        spawn = wake.subprocess.Popen
        def create(*args, **kwargs):
            child = spawn(*args, **kwargs)
            r2_case.configs[-1].with_suffix(".exit").touch()
            return child
        wake.subprocess.Popen = create
        return wake
    monkeypatch.setattr(module, "load_wake", load)
    launches = module.Launches(str(r2_case.launch.base))
    monkeypatch.setattr(module, "MAX_RECORDS", len(launches.paths(REVIEW)))
    with module.stop_endpoint_lock(launches.mailbox.root, REVIEW) as admission:
        code = module.main(["--base", str(launches.base), "_resume-wake", "--endpoint", REVIEW,
                            "--admission-fd", str(admission), "--admission-namespace", admission.manifest(), "--wake-source",
                            str(r2_case.launch.source / "tools/hierarchy_wake.py")])
    answer = json.loads(capsys.readouterr().out)
    assert code == 2 and answer["error"] == "launch record limit reached for " + REVIEW
    assert not actors and module.read_running_wake(launches.base, REVIEW) is None


def test_r23_no_unread_resume_records_that_no_child_was_admitted(r2_case, capsys, monkeypatch):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW]) == 0
    answer = json.loads(capsys.readouterr().out)
    assert answer["state"] == "resumed" and answer["wake"]["state"] == "nothing_unread"
    path = module.Launches(str(r2_case.launch.base)).paths(REVIEW)[-1]
    assert module.read_resume_admission(r2_case.launch.base, REVIEW, path.stem)["admission_attempted"] is False
    assert not actors and not r2_case.projection.events
    assert module.read_running_wake(r2_case.launch.base, REVIEW) is None


@pytest.mark.parametrize("fault", ["exec-with-path", "unknown-os", "value-payload"])
def test_r23_driver_refusal_preserves_errno_without_echoing_input(r2_case, capsys, fault):
    import errno

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    running = module.subprocess.run
    def failed(command, **options):
        if "_resume-wake" in command:
            if fault == "exec-with-path":
                raise OSError(errno.ENOEXEC, "modelled-sensitive-strerror", "modelled-sensitive-filename")
            if fault == "unknown-os":
                raise OSError("modelled-sensitive-os-payload")
            raise ValueError("modelled-sensitive-value-payload")
        return running(command, **options)
    module.subprocess.run = failed
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW]) == 2
    answer = json.loads(capsys.readouterr().out)
    expected = ("[Errno %d] %s" % (errno.ENOEXEC, os.strerror(errno.ENOEXEC)) if fault == "exec-with-path" else
                "resume driver failed; inspect admission evidence and run stop")
    assert answer["error"] == expected and answer["state"] == "refused"
    assert "modelled-sensitive" not in json.dumps(answer)
    assert module.read_running_wake(r2_case.launch.base, REVIEW) is None and not r2_case.projection.events


@pytest.mark.parametrize("failure", [OSError, ValueError], ids=["io", "validation"])
def test_r23_refused_resume_requires_a_later_stop(r2_case, capsys, monkeypatch, failure):
    import errno
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    r2_case.launch.publish_to(REVIEW, "r23-final-receipt-fails")
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    loading, faults = module.load_wake, []
    def load(launches):
        wake = loading(launches)
        mailbox, spawn = wake.Mailbox, wake.subprocess.Popen
        class FailedFinalReceipt(mailbox):
            def write_delivery_receipt(self, directory, kind, record):
                if kind == "wakes" and record["state"] == "exited":
                    faults.append(True)
                    if failure is OSError:
                        raise OSError(errno.EIO, "modelled final receipt storage failure")
                    raise ValueError("modelled final receipt validation payload")
                return super().write_delivery_receipt(directory, kind, record)
        def spawned(*args, **kwargs):
            child = spawn(*args, **kwargs)
            r2_case.configs[-1].with_suffix(".exit").touch()
            return child
        wake.Mailbox, wake.subprocess.Popen = FailedFinalReceipt, spawned
        return wake
    monkeypatch.setattr(module, "load_wake", load)
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert faults == [True] and answer["state"] == "refused" and actors[0].wait(timeout=5) == 0
    path = module.Launches(str(r2_case.launch.base)).paths(REVIEW)[-1]
    assert module.read_resume_admission(r2_case.launch.base, REVIEW, path.stem)["admission_attempted"] is True
    expected = ("[Errno 5] Input/output error" if failure is OSError else
                "wake execution failed; inspect its receipts and admission evidence")
    assert answer["error"] == expected and "modelled final receipt" not in json.dumps(answer)
    assert not (module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".running-wake").exists()
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = spec_for(r2_case.launch)
    refused = run_main(control, r2_case.launch, spec, capsys, 2)
    assert "latest launch status is refused (resume)" in refused["error"]
    # A contradictory false flag cannot overrule the receipt-failure evidence of an admitted wake.
    path = module.Launches(str(r2_case.launch.base)).paths(REVIEW)[-1]
    record = json.loads(path.read_text())
    record["admission_attempted"] = False
    path.write_text(json.dumps(record))
    refused = run_main(control, r2_case.launch, spec, capsys, 2)
    assert "latest launch status is refused (resume)" in refused["error"]
    assert r2_case.stop(module, capsys, 0)[0] == 0
    accepted = run_main(control, r2_case.launch, spec, capsys, 0)
    assert accepted["entries"][0]["generation"] == 2


def r22_wake_processes(case, module, monkeypatch):
    """Real producer and registered physical child at the external process boundary."""
    from types import SimpleNamespace

    actors = []
    binding = case.launch.binding()
    argv = (["claude", "--resume", binding["session"]] if binding["host"] == "claude-code" else
            ["codex", "exec", "resume", binding["session"]])
    def spawned(*args, **kwargs):
        actor = case.spawn(argv)
        actors.append(actor)
        return actor
    load = module.load_wake
    def loaded(launches):
        wake = load(launches)
        wake.subprocess = R2Facade(subprocess, Popen=spawned)
        class Paths(type(Path())):
            @classmethod
            def home(cls):
                return case.home
        wake.Path = Paths
        return wake
    monkeypatch.setattr(module, "load_wake", loaded)
    run = module.subprocess.run
    def external(command, **options):
        if "_resume-wake" in command:
            code, answer = module.admitted_wake(module.Launches(str(case.launch.base)), REVIEW,
                options["pass_fds"][0], str(case.launch.source / "tools/hierarchy_wake.py"), "--dry-run" in command,
                command[command.index("--admission-namespace") + 1])
            return SimpleNamespace(returncode=code, stdout=json.dumps(answer))
        return run(command, **options)
    module.subprocess = R2Facade(module.subprocess, run=external)
    return actors


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_r22_running_wake_enospc_cleans_publication_and_marker(r2_case, capsys, monkeypatch, host):
    import errno

    r2_case.bind(host, str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r22-enospc")
    module = r2_case.module(False)
    actors = r22_wake_processes(r2_case, module, monkeypatch)
    opened, faults = module.os.fdopen, []
    class Stream:
        def __init__(self, raw):
            self.raw = raw
        def __enter__(self):
            self.raw.__enter__()
            return self
        def __exit__(self, *args):
            return self.raw.__exit__(*args)
        def __getattr__(self, name):
            return getattr(self.raw, name)
        def write(self, value):
            if not actors:
                return self.raw.write(value)
            faults.append(True)
            raise OSError(errno.ENOSPC, "modelled running-wake storage full")
    def fdopen(fd, mode, *args, **kwargs):
        name = Path(os.readlink("/proc/self/fd/%d" % fd)).name
        raw = opened(fd, mode, *args, **kwargs)
        return Stream(raw) if mode == "wb" and name.startswith(".running-wake") else raw
    module.os.fdopen = fdopen
    code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW])
    answer = json.loads(capsys.readouterr().out)
    assert faults == [True] and actors and actors[0].wait(timeout=5) == -signal.SIGTERM
    assert code == 3 and answer["wake"]["state"] == "failed_to_start"
    launches = module.Launches(str(r2_case.launch.base))
    assert not list(launches.folder(REVIEW).glob(".running-wake*"))
    assert not launches.mailbox.wake_marker(REVIEW).exists()
    receipts = [json.loads(p.read_text()) for p in (r2_case.launch.base / "delivery" / "wakes").rglob("*.json")]
    assert any(r.get("state") == "failed_to_start" for r in receipts)


def test_r22_failed_group_cleanup_retains_the_running_wake(r2_case, capsys, monkeypatch):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    r2_case.launch.publish_to(REVIEW, "r22-group-cleanup")
    module = r2_case.module(False)
    r22_wake_processes(r2_case, module, monkeypatch)
    loading, families, denied = module.load_wake, [], []

    def load(launches):
        wake = loading(launches)
        def spawned(*args, **kwargs):
            family = r2_case.spawn(["codex", "exec", "resume", r2_case.launch.binding()["session"]], tree=True,
                                  middle_argv=["python3", "middle.py"], worker_argv=["python3", "worker.py"])
            families.append(family)
            for label in ("H", "M"):
                slot = next(slot for slot, row in r2_case.custody.entries.items() if row["pid"] == family[label].pid)
                r2_case.custody.kill_owned(slot)
            assert family["H"].wait(timeout=5) == -signal.SIGKILL
            wait_until(lambda: family["M"].poll() == "CONFIRMED_EXIT")
            return family["H"]
        def killpg(group, number):
            assert families and group == families[0]["H"].pid
            denied.append(number)
            raise PermissionError("modelled group cleanup denied")
        wake.subprocess.Popen = spawned
        wake.os = R2Facade(os, killpg=killpg)
        return wake
    monkeypatch.setattr(module, "load_wake", load)
    code = module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW])
    answer = json.loads(capsys.readouterr().out)
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".running-wake"
    assert families and denied and families[0]["W"].poll() is None
    assert path.is_file() and not r2_case.projection.events
    assert code == 3 and answer["wake"]["state"] == "stop_unconfirmed"
    assert module.main(["--base", str(r2_case.launch.base), "resume", "--endpoint", REVIEW, "--dry-run"]) == 2
    assert json.loads(capsys.readouterr().out)["error"] == (
        "a turn is in flight; wait for it to finish, or run stop to end it")


def test_r22_running_wake_read_failure_names_manual_recovery(r2_case, capsys):
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    folder = launches.make(REVIEW)
    path = folder / ".running-wake"
    path.write_text("{", encoding="utf-8")
    path.chmod(0o600)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 2 and str(path) in answer["error"]
    assert "manual" in answer["error"] and "archive" in answer["error"] and not r2_case.projection.events


def test_r21_cleanup_fences_an_unbound_start(r2_case, monkeypatch, capsys):
    import importlib.util
    from tests.integration.test_hierarchy_native_probe import PROBE

    module = r2_case.module(False)
    monkeypatch.setitem(sys.modules, "hierarchy_launcher", module)
    definition = importlib.util.spec_from_file_location("r21_probe", PROBE)
    control = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(control)
    request = r2_case.launch.start_request(cwd=str(r2_case.launch.source))
    entered = []
    def forbidden_creation(*args, **kwargs):
        entered.append(True)
        raise OSError(5, "modelled host creation forbidden during deletion")
    module.subprocess = R2Facade(module.subprocess, Popen=forbidden_creation)
    planned = [{"base": str(r2_case.launch.base), "endpoint": REVIEW}]
    with control.cleanup_locks(planned):
        code = module.main(["--base", str(r2_case.launch.base), "start", "--request", str(request)])
        answer = json.loads(capsys.readouterr().out)
        assert code == 2 and "endpoint is busy" in answer["error"] and not entered
    # The reverse ordering also refuses deletion while start owns admission.
    with module.stop_endpoint_lock(r2_case.launch.root, REVIEW, create=True):
        with pytest.raises(ValueError, match="endpoint is busy"):
            with control.cleanup_locks(planned):
                pytest.fail("cleanup crossed an active start fence")
    assert r2_case.launch.binding() is None


def test_r21_handoff_rechecks_a_missing_launch_directory(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    control = handoff_module()
    control.hierarchy_launcher = module
    folder = module.Launches(str(r2_case.launch.base)).folder(REVIEW)
    exists, injected = control.Path.exists if hasattr(control, "Path") else Path.exists, []
    # Race at the actual filesystem query, scoped to this consumer's Path reference.
    class Paths(type(folder)):
        def exists(self):
            if self == folder and not injected and (r2_case.launch.root / ".write.lock").exists():
                self.parent.mkdir(exist_ok=True)
                self.symlink_to(self.parent / "missing", target_is_directory=True)
                injected.append(True)
            return exists(self)
    checked = control.safe_path
    control.safe_path = lambda path: Paths(checked(path))
    result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 3)
    assert injected and "launch directory" in result["entries"][0]["error"]
    assert r2_case.launch.binding()["generation"] == 1


@pytest.mark.parametrize("unavailable", [False, True, "no-birth"],
                         ids=["empty-cmdline", "unreadable-status", "unreadable-birth"])
def test_r21_recovered_resolution_cannot_adopt_an_unavailable_reused_birth(r2_case, capsys, unavailable):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["python3", "worker.py"])
    module = r2_case.module(False)
    current = module.read_process(held.pid).snapshot
    # Argon's historical birth100 -> current birth200 input; current PID/birth/UID/liveness stay physical.
    historical = current._replace(start_time=str(int(current.start_time) - 1))
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    old = dict(candidates={held.pid: historical}, initial_unavailable={}, blocked=set(), identity_lost=set(),
               resolved={held.pid: "qualified_namespace_ESRCH"})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(old, {held.pid}, active=True)
    journal = launches.folder(REVIEW) / ".stop-custody/state.json"
    before = journal.read_bytes()
    reading, calls = module.read_process, []
    def observed(pid, *args):
        if pid != held.pid:
            return reading(pid, *args)
        calls.append(pid)
        if unavailable:
            facts = dict(pid=held.pid, start_time=current.start_time, coherent_birth=True,
                         uid=current.uid, euid=current.euid, pgid=current.pgid, ppid=current.ppid)
            if unavailable == "no-birth":
                facts.pop("start_time")
                facts["coherent_birth"] = False
            return module.ProcessObservation("UNAVAILABLE", pid, partial=facts, reason="modelled unreadable status")
        return module.ProcessObservation("PRESENT", pid, current._replace(cmdline=b"", argv=()))
    module.read_process = observed
    module.process_census = lambda session: pytest.fail("unproven terminal evidence reached fresh discovery")
    code, answer = r2_case.stop(module, capsys, 0)
    assert calls and code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [held.pid]
    assert "manual reconciliation" in answer["error"]
    assert held.poll() is None and not r2_case.projection.events
    assert journal.read_bytes() == before


def test_r21_mid_stop_retirement_commits_terminal_custody(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    before = module.read_process(held.pid).snapshot
    census, calls = module.process_census, []
    def observed(bound):
        actual = census(bound)
        calls.append(True)
        if len(calls) >= 3:
            # Negative-only OS reuse observation after the owned actor's confirmed physical exit.
            replacement = before._replace(start_time=str(int(before.start_time) + 1),
                                           pgid=os.getpgrp(), ppid=os.getpid(),
                                           argv=("python3", "unrelated.py"), cmdline=b"python3\0unrelated.py\0")
            return module.ProcessCensus([row for row in actual if row.pid != held.pid] + [replacement], "proven",
                                        actual.unavailable)
        return actual
    module.process_census = observed
    r2_case.projection.after_signal.append(lambda pid, number: held.wait(timeout=5) if pid == held.pid else None)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [held.pid]
    assert answer["absence_evidence"] == [{"pid": held.pid, "proof": "qualified_namespace_ESRCH"}]
    saved = json.loads((module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody/state.json").read_text())
    assert not saved["active"] and saved["entries"][0]["resolved"]


def test_r21_new_birth_during_escalation_receives_term_first(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    first = r2_case.spawn(["claude", "--resume", session], ignore=True)
    replacement = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    # Two real current instances: a late census appearance must receive its own TERM before KILL.
    # No writable historical resolution is used as authority for the newly discovered instance.
    census, calls = module.process_census, []
    def observed(bound):
        actual = census(bound)
        calls.append(True)
        if len(calls) <= 2:
            return module.ProcessCensus([row for row in actual if row.pid != replacement.pid], "proven", actual.unavailable)
        return actual
    module.process_census = observed
    def settled(pid, number):
        if pid == replacement.pid and number == signal.SIGTERM:
            replacement.wait(timeout=5)
    r2_case.projection.after_signal.append(settled)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "stopped"
    delivered = [number for pid, number in r2_case.projection.events if pid == replacement.pid]
    assert delivered == [signal.SIGTERM]
    assert replacement.wait(timeout=5) == -signal.SIGTERM
    assert first.wait(timeout=5) == -signal.SIGKILL


@pytest.mark.parametrize("host,plan", [("claude-code", True), ("codex-cli", True), ("codex-cli", False)])
def test_r21_resume_can_be_stopped_mid_turn(r2_case, capsys, monkeypatch, host, plan):
    import fcntl
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace
    import hierarchy_hosts

    session = str(uuid.uuid4())
    r2_case.bind(host, session)
    r2_case.launch.publish_to(REVIEW, "resume-stop")
    if plan:
        record = hierarchy_hosts.plan_record("pilot", "codex-cli", host, {"pilot/front-door": "claude-code"}, "0" * 64)
        (r2_case.launch.base / "host-plan.json").write_text(json.dumps(record))
    module = r2_case.module(False)
    started, actors = threading.Event(), []
    argv = ["claude", "--resume", session] if host == "claude-code" else ["codex", "exec", "resume", session]
    def spawn():
        child = r2_case.spawn(argv)
        actors.append(child)
        started.set()
        return child
    run = module.subprocess.run
    def external(command, **options):
        if any(str(word).endswith("hierarchy_wake.py") for word in command):
            if "_resume-wake" in command:
                code, result = module.admitted_wake(module.Launches(str(r2_case.launch.base)), REVIEW,
                    options["pass_fds"][0], str(r2_case.launch.source / "tools/hierarchy_wake.py"), False,
                    command[command.index("--admission-namespace") + 1])
                return SimpleNamespace(returncode=code, stdout=json.dumps(result))
            spawn().wait(timeout=10)
            return SimpleNamespace(returncode=3, stdout='{"state":"woken_unread"}')
        return run(command, **options)
    module.subprocess = R2Facade(module.subprocess, run=external)
    real_loader = module.load_wake
    def load_wake(launches):
        wake = real_loader(launches)
        # Real registered actor at the OS creation boundary; the producer and consumer remain real.
        wake.subprocess = R2Facade(subprocess, Popen=lambda *args, **kwargs: spawn())
        class Paths(type(Path())):
            @classmethod
            def home(cls):
                return r2_case.home
        wake.Path = Paths
        return wake
    monkeypatch.setattr(module, "load_wake", load_wake)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(module.resume, module.Launches(str(r2_case.launch.base)), REVIEW, False)
        try:
            assert started.wait(timeout=5), "resume did not reach the host turn"
            # Observe actual lock availability before making one public stop call.
            descriptor = os.open(r2_case.launch.root / "bindings" / REVIEW, os.O_RDONLY | os.O_DIRECTORY)
            try:
                def available():
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        return False
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    return True
                wait_until(available, seconds=R2_STOP_TIMEOUT_SECONDS)
            finally:
                os.close(descriptor)
            code, answer = r2_case.stop(module, capsys, 0)
            assert code == 0 and answer["state"] == "stopped" and actors[0].pid in answer["pids"]
            assert actors[0].wait(timeout=5) == -signal.SIGTERM
        finally:
            for config in r2_case.configs:
                config.with_suffix(".exit").touch()
        result = pending.result(timeout=R2_STOP_TIMEOUT_SECONDS)
    assert result[0] == 3 and result[1]["state"] == "resumed_unread"


def test_r21_stop_retires_a_crashed_resumes_running_record(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, held.pid)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "stopped" and held.wait(timeout=5) == -signal.SIGTERM
    assert not (launches.folder(REVIEW) / ".running-wake").exists()


@pytest.mark.parametrize("bad", ["malformed", "oversize", "directory", "symlink", "binding"])
def test_r21_bad_running_wake_refuses_before_signals(r2_case, capsys, bad):
    from tests.conftest import symlink_or_skip

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    record = module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, held.pid)
    path = launches.folder(REVIEW) / ".running-wake"
    secret = "untrusted-running-wake-input"
    if bad == "directory":
        path.unlink()
        path.mkdir()
    elif bad == "symlink":
        path.unlink()
        symlink_or_skip(r2_case.launch.tmp / "missing", path)
    elif bad == "binding":
        record["binding"]["session"] = secret
        path.write_text(json.dumps(record))
    else:
        path.write_text((secret * 20000) if bad == "oversize" else '{"' + secret + '":')
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 2 and answer["state"] == "refused" and answer["error"]
    assert secret not in json.dumps(answer)
    assert held.poll() is None and r2_case.projection.events == []


def test_r21_running_wake_cleanup_failure_is_a_stop_failure(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    known = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    module.write_running_wake(launches, REVIEW, known, "wake-" + uuid.uuid4().hex, held.pid)
    unlink = module.os.unlink
    def failed(name, *args, **kwargs):
        if name == ".running-wake":
            raise OSError(5, "modelled running record deletion failure")
        return unlink(name, *args, **kwargs)
    module.os.unlink = failed
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["error"] == "running wake cleanup unavailable"
    assert held.wait(timeout=5) == -signal.SIGTERM
    assert (launches.folder(REVIEW) / ".running-wake").is_file()


def test_r20_nonleader_host_keeps_its_real_descendant_in_scope(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    # Actual wrapper -> host -> worker ancestry/group; only complete host argv is MODELLED.
    family = r2_case.spawn(["sh", "wrapper.sh", session], tree=True,
                           middle_argv=["codex", "exec", "resume", session])
    wrapper, host, worker = (family[label] for label in ("H", "M", "W"))
    physical = r2_kernel_process(host.pid)
    assert physical["pgid"] == wrapper.pid and physical["ppid"] == wrapper.pid
    code, answer = r2_case.stop(r2_case.module(), capsys, 0)
    assert worker.poll() == "CONFIRMED_EXIT" or code == 3
    assert not (answer["state"] == "stopped" and worker.poll() is None)
    assert wrapper.poll() is None and all(pid != wrapper.pid for pid, _ in r2_case.projection.events)


@pytest.mark.parametrize("program,option", [("python3", "--after"), ("job.py", "--run")])
def test_r20_message_uuid_does_not_spare_a_real_subtree(r2_case, capsys, program, option):
    session, message = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True,
                           middle_argv=[program, option, message])
    code, answer = r2_case.stop(r2_case.module(), capsys, 0)
    assert code == 0 and answer["state"] == "stopped"
    assert {family[label].pid for label in ("H", "M", "W")} <= set(answer["pids"])
    assert family["M"].poll() == family["W"].poll() == "CONFIRMED_EXIT"


def test_r20_parsed_other_session_host_is_spared(r2_case, capsys):
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True,
                           middle_argv=["codex", "exec", "resume", other])
    code, answer = r2_case.stop(r2_case.module(), capsys, 0)
    # R25: a correctly spared other session still keeps the retained physical group nonempty.
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["unresolved_groups"] == [family["H"].pid]
    assert family["M"].pid in answer["spared_descendants"]
    assert family["M"].poll() is None and family["W"].poll() is None
    assert all(pid not in (family["M"].pid, family["W"].pid) for pid, _ in r2_case.projection.events)


@pytest.mark.parametrize("surface", ["start", "resume"])
def test_r20_unresolved_custody_fences_start_and_resume(r2_case, capsys, surface):
    from types import SimpleNamespace

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", "--print", session])
    module = r2_case.module()
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["unresolved_pids"]
    called = []
    def external(argv, **kwargs):
        # No real turn: model the external OS process boundary only, with no permission to signal.
        called.append(argv)
        return SimpleNamespace(returncode=0, stdout='{"state":"dry_run"}', stderr="")
    module.subprocess.run = external
    request = r2_case.launch.tmp / "r20-start.json"
    request.write_text(json.dumps({"endpoint": REVIEW, "cwd": str(r2_case.launch.source)}))
    words = (["start", "--request", str(request)] if surface == "start" else
             ["resume", "--endpoint", REVIEW, "--dry-run"])
    code = module.main(["--base", str(r2_case.launch.base), *words])
    refused = json.loads(capsys.readouterr().out)
    # R27 keeps negative selector classification on every retained-instance check. A stable
    # ambiguous selector blocks authority, without claiming that its birth or UIDs changed.
    assert code == 2 and "original process identity blocked" in refused.get("error", "") and not called
    assert "manual reconciliation" in refused["error"]
    assert "retry hierarchy_launcher.py --base " in refused["error"] and "stop --endpoint " + REVIEW in refused["error"]
    assert held.poll() is None and not r2_case.projection.events
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody/state.json"
    entry = next(entry for entry in json.loads(path.read_text())["entries"] if entry["pid"] == held.pid)
    assert entry["blocked"] and not entry["identity_lost"]


@pytest.mark.parametrize("retained", [False, True])
def test_r20_unsupported_stop_never_creates_or_rewrites_custody(r2_case, capsys, retained):
    if retained:
        held, path, _ = r7_pending_attempt(r2_case, capsys)
        before = path.read_bytes()
    else:
        r2_case.bind("claude-code", str(uuid.uuid4()))
        path = r2_case.launch.base / "launches" / REVIEW.replace("/", "%2F") / ".stop-custody" / "state.json"
        before, held = None, None
    module = r2_case.module(False)
    r2_case.ps(module, None, [])
    events = list(r2_case.projection.events)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["argv_boundaries"] == "unproven" and answer["reason"] == "argv_boundaries_unavailable"
    assert "unsupported" in answer.get("error", "") and "manually" in answer["error"]
    assert r2_case.projection.events == events
    if retained:
        assert path.read_bytes() == before and held.pid in answer["pids"] and held.poll() is None
    else:
        assert not path.exists() and answer["pids"] == []


@pytest.mark.parametrize("pidfds", [True, False], ids=["pidfd", "numeric"])
@pytest.mark.parametrize("descendant", [False, True], ids=["root", "descendant"])
def test_r20_resolved_pid_does_not_hide_a_fresh_physical_instance(r2_case, capsys, pidfds, descendant):
    import time

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(pidfds)
    old = r2_case.spawn()
    previous = module.read_process(old.pid).snapshot
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert old.wait(timeout=5) == 0
    time.sleep(2 / os.sysconf("SC_CLK_TCK"))
    family = r2_case.spawn(["claude", "--resume", session], tree=descendant)
    current = family["W"] if descendant else family
    row = module.read_process(current.pid).snapshot
    assert row.start_time != previous.start_time
    # MODELLED historical numeric-PID reuse; CURRENT birth/raw/UID/parents/pidfd/signals stay physical.
    historical = previous._replace(pid=current.pid)
    observed = dict(candidates={current.pid: historical}, initial_unavailable={}, blocked=set(),
                    identity_lost=set(), resolved={current.pid: "qualified_namespace_ESRCH"})
    launches = module.Launches(str(r2_case.launch.base))
    binding = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    with module.StopCustody(launches, REVIEW, binding) as custody:
        custody.save(observed, {current.pid}, active=True)
    before = custody.path.read_bytes()
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [current.pid]
    assert "manual reconciliation" in answer["error"]
    assert not r2_case.projection.events
    assert all(child.poll() is None for child in family.values()) if descendant else current.poll() is None
    assert custody.path.read_bytes() == before


@pytest.mark.parametrize("failure", ["permission", "vanished"])
def test_r20_unreadable_launch_directory_never_becomes_caller_asserted(r2_case, capsys, failure):
    import errno
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for
    from tests.integration.test_hierarchy_handoff import mailbox_files

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    assert r2_case.stop(r2_case.module(), capsys, 0)[0] == 0
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module()
    directory = module.Launches(str(r2_case.launch.base)).folder(REVIEW)
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = spec_for(r2_case.launch)
    before = mailbox_files(r2_case.launch.base)
    if failure == "permission":
        directory.chmod(0o100)
    else:
        listing = module.os.scandir
        def vanished(path):
            if isinstance(path, int) and os.path.samefile('/proc/self/fd/%d' % path, directory):
                raise FileNotFoundError(errno.ENOENT, "modelled endpoint vanished during scan")
            return listing(path)
        module.os.scandir = vanished
    try:
        answer = run_main(control, r2_case.launch, spec, capsys, 2)
        assert "launch directory unreadable" in answer["error"]
        assert held.poll() is None
        assert r2_case.projection.events == []
    finally:
        directory.chmod(0o700)
    assert mailbox_files(r2_case.launch.base) == before


@pytest.mark.parametrize("equals", [False, True], ids=["separate", "equals"])
def test_r20_whitespace_selector_is_discovered_before_handoff(r2_case, capsys, equals):
    import hashlib
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = "modelled legacy session"
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module()
    mailbox = module.Launches(str(r2_case.launch.base)).mailbox
    brief = r2_case.launch.base / "r20-legacy-brief.md"
    brief.write_text("Continue the modelled role.\n")
    mailbox.bind(mailbox.draft_handoff({"endpoint": REVIEW, "host": "claude-code", "session": session,
                                      "outgoing_stopped": True,
                                      "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}))
    assert r2_case.stop(r2_case.module(), capsys, 0)[0] == 0
    held = r2_case.spawn(["claude", *( ["--resume=" + session] if equals else ["--resume", session])])
    control = handoff_module()
    control.hierarchy_launcher = r2_case.module()
    answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
    assert "live process remains" in answer["error"] and str(held.pid) in answer["error"]
    assert held.poll() is None and r2_case.projection.events == []


def test_r20_handoff_rejects_a_parent_replaced_during_launch_enumeration(r2_case, capsys):
    import shutil
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for
    from tests.integration.test_hierarchy_handoff import mailbox_files

    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    control = handoff_module()
    control.hierarchy_launcher = module
    base = r2_case.launch.base
    folder = module.Launches(str(base)).folder(REVIEW)
    spec = spec_for(r2_case.launch)
    before = mailbox_files(base)
    original, replacement = base.with_name(base.name + "-old"), base.with_name(base.name + "-replacement")
    shutil.copytree(base, replacement)
    listing, changed = module.os.scandir, []

    def swapped(path):
        if isinstance(path, int) and os.path.samefile('/proc/self/fd/%d' % path, folder) and not changed:
            base.rename(original)
            replacement.rename(base)
            changed.append(True)
        return listing(path)

    module.os.scandir = swapped  # MODELLED namespace race; the descriptor/inode changes are actual.
    try:
        answer = run_main(control, r2_case.launch, spec, capsys, 2)
        assert changed and "launch directory changed while reading" in answer["error"]
        assert mailbox_files(original) == before and mailbox_files(base) == before
        assert r2_case.projection.events == []
    finally:
        if changed:
            base.rename(replacement)
            original.rename(base)


@pytest.mark.parametrize("moment", ["before-stop", "after-stop"])
@pytest.mark.parametrize("live", [False, True], ids=["idle", "live"])
def test_r22_cleanup_never_stops_or_deletes_a_successor(r2_case, capsys, moment, live):
    import contextlib
    import io
    from tests.integration.test_hierarchy_native_probe import Probe
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, spec_for

    session, successor = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    discovery = r2_case.module(False)
    folder = r2_case.launch.tmp / "r22-successor-probe"
    folder.mkdir()
    probe, children = Probe(folder), []
    try:
        plan = probe.plan([{"role": "implementer"}])
        plan["roles"][0].update(base=str(r2_case.launch.base), endpoint=REVIEW)
        (probe.root / "probe.json").write_text(json.dumps(plan))
        auth = probe.codex_home / "auth.json"
        auth.write_text("test-owned disposable credential")
        control = r16_cleanup_control(probe, discovery)
        runner, switches = control.Runner, []

        def replace_binding():
            path = r2_case.launch.tmp / "r22-handoff.json"
            path.write_text(json.dumps(spec_for(r2_case.launch, session=successor)))
            handing = handoff_module()
            handing.hierarchy_launcher = discovery
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = handing.main(["--spec", str(path)])
            assert code == 0 and json.loads(output.getvalue())["entries"][0]["generation"] == 2
            switches.append(True)
            if live:
                child = r2_case.spawn(["codex", "exec", "resume", successor])
                children.append((child, r2_case.configs[-1].with_suffix(".exit")))

        class ScopedRunner(runner):
            def launcher(self, base, *words):
                if moment == "before-stop":
                    replace_binding()
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = discovery.main(["--base", base, *words])
                result = json.loads(output.getvalue())
                if moment == "after-stop":
                    assert code == 0 and result["session"] == session
                    replace_binding()
                return code, result

        control.Runner = ScopedRunner
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)["cleanup"]
        assert switches and code == 3 and not answer["worktree_removed"]
        assert Path(plan["worktree"]).is_dir() and answer["auth_removed"] and not auth.exists()
        reasons = [entry["reason"] for entry in answer["unresolved_custody"]]
        assert any("cleanup binding changed; preserve the worktree" in reason for reason in reasons)
        assert r2_case.launch.binding()["session"] == successor
        assert not r2_case.projection.events
        assert all(child.poll() is None for child, _ in children)
    finally:
        for child, exit_path in children:
            if child.poll() is None:
                exit_path.touch()
                assert child.wait(timeout=5) == 0
            else:
                child.wait(timeout=5)
        probe.close()


def test_r22_expected_unbound_stop_cannot_select_a_new_binding(r2_case, capsys):
    # Cleanup inspected an unbound endpoint. An actual binding/host appears before its fenced stop.
    r2_case.bind("codex-cli", str(uuid.uuid4()))
    held = r2_case.spawn(["codex", "exec", "resume", r2_case.launch.binding()["session"]])
    module = r2_case.module(False)
    assert module.main(["--base", str(r2_case.launch.base), "stop", "--endpoint", REVIEW,
                        "--expected-binding", "null", "--grace-seconds", "0"]) == 2
    answer = json.loads(capsys.readouterr().out)
    assert answer["state"] == "refused" and answer["error"] == module.CLEANUP_BINDING_CHANGED
    assert held.poll() is None and not r2_case.projection.events


@pytest.mark.parametrize("raw", ["{", "[]", "true", '{"host":"secret","host":"secret"}',
                                  '{"host":"codex-cli","session":"s","generation":true}',
                                  "secret" * 1000, '"secret-\u00e9"'])
def test_r22_expected_stop_input_is_bounded_and_redacted(launch, capsys, monkeypatch, raw):
    module = launcher_module()
    parsing, calls = module.metadata_json, []
    def parsed(*args):
        calls.append(True)
        return parsing(*args)
    monkeypatch.setattr(module, "metadata_json", parsed)
    before = launch.records()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW,
                        "--expected-binding", raw]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "invalid expected stop binding"}
    if len(raw) > 4096 or not raw.isascii():
        assert not calls
    assert launch.records() == before


def test_r20_probe_busy_precheck_still_invokes_its_fenced_stop(r2_case, capsys):
    import contextlib
    import io
    from tests.integration.test_hierarchy_native_probe import Probe

    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    discovery = r2_case.module(False)
    held = r2_case.spawn(["codex", "exec", "resume", session])
    folder = r2_case.launch.tmp / "r20-probe"
    folder.mkdir()
    probe = Probe(folder)
    try:
        plan = probe.plan([{"role": "implementer"}])
        planned = plan["roles"][0]
        planned.update(base=str(r2_case.launch.base), endpoint=REVIEW)
        (probe.root / "probe.json").write_text(json.dumps(plan))
        control = r16_cleanup_control(probe, discovery)
        runner, locking = control.Runner, control.cleanup_locks
        calls, faults = [], []
        class ScopedRunner(runner):
            def launcher(self, base, *words):
                calls.append((base, words))
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = discovery.main(["--base", base, *words])
                return code, json.loads(out.getvalue())
        @contextlib.contextmanager
        def busy_once(roles):
            if not faults:
                faults.append(True)
                raise ValueError("modelled mailbox writer is busy")
            with locking(roles) as scopes:
                yield scopes
        control.Runner, control.cleanup_locks = ScopedRunner, busy_once
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)
        assert faults and calls and all(words[0] == "stop" for _, words in calls)
        assert held.wait(timeout=5) == -signal.SIGTERM
        assert code == 3 and not answer["cleanup"]["worktree_removed"]
        assert Path(plan["worktree"]).is_dir() and answer["cleanup"]["unresolved_custody"]
    finally:
        probe.close()


def test_r20_reused_root_retains_the_original_orphan_group(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    old = r2_case.spawn(["claude", "--resume", session], tree=True)
    historical = module.read_process(old["H"].pid).snapshot
    for label in ("H", "M"):
        slot = next(slot for slot, entry in r2_case.custody.entries.items() if entry["pid"] == old[label].pid)
        r2_case.custody.kill_owned(slot)
    assert old["H"].wait(timeout=5) == -signal.SIGKILL
    wait_until(lambda: old["M"].poll() == "CONFIRMED_EXIT")
    assert old["W"].poll() is None
    new = r2_case.spawn(["claude", "--resume", session])
    assert module.read_process(new.pid).snapshot.start_time != historical.start_time
    # MODELLED historical PID reuse only. The original group/orphan and replacement host are real.
    observed = dict(candidates={new.pid: historical._replace(pid=new.pid)}, initial_unavailable={},
                    blocked=set(), identity_lost=set(), resolved={new.pid: "qualified_namespace_ESRCH"})
    launches = module.Launches(str(r2_case.launch.base))
    binding = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    with module.StopCustody(launches, REVIEW, binding) as custody:
        custody.save(observed, {new.pid})
    before = custody.path.read_bytes()
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [new.pid]
    assert "manual reconciliation" in answer["error"]
    assert new.poll() is None and old["W"].poll() is None and not r2_case.projection.events
    assert custody.path.read_bytes() == before


def test_r20_initial_foreign_uid_descendant_is_held_without_a_signal(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn_group(["claude", "--resume", session])
    host, worker = family["H"], family["M"]
    def foreign(pid, count, row):
        # MODELLED negative UID evidence only; real physical custody still owns cleanup.
        return row._replace(uid=os.geteuid() + 1, euid=os.geteuid() + 1) if pid == worker.pid else row
    r2_case.projection.after_present.append(foreign)
    code, answer = r2_case.stop(r2_case.module(), capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and answer["unresolved_pids"] == [worker.pid]
    assert worker.poll() is None and answer["pids"] == [host.pid]
    assert worker.pid not in answer.get("spared_descendants", [])
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)
    assert host.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("check", ["boot", "marker", "diagnostic"])
def test_r20_inflight_provider_loss_retains_identity_and_diagnostic_child(r2_case, capsys, check):
    from types import SimpleNamespace

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn_group(["claude", "--resume", session], stubborn=True)
    host, worker = family["H"], family["M"]
    module = r2_case.module(False)
    boot, lost, census = module.StopCustody.boot(), [], module.process_census
    def visible(bound):
        rows = census(bound)
        # MODELLED initial enumeration excludes one already registered child; all instance facts stay real.
        return rows if lost else module.ProcessCensus([r for r in rows if r.pid == host.pid], rows.argv_boundaries,
                                                     {p: r for p, r in rows.unavailable.items() if p == host.pid})
    module.process_census = visible
    def changed(pid, number):
        if pid != host.pid or number != signal.SIGTERM:
            return
        lost.append(True)
        r2_case.ps(module, host, ["claude", "--resume", session])
        run = module.subprocess.run
        def ps(command, **options):
            if "-o" not in command:
                return run(command, **options)
            targets = [host, worker]
            if "-p" in command:
                targets = [p for p in targets if p.pid == int(command[command.index("-p") + 1])]
            lines = []
            for process in targets:
                physical = r2_kernel_process(process.pid)
                argv = ["claude", "--resume", session] if process is host else ["worker"]
                lines.append("%d %d %d %d %d %s Sat Nov 7 12:00:00 2026 %s\n" % (
                    process.pid, physical["pgid"], physical["ppid"], physical["uid"], physical["euid"],
                    physical["state"], " ".join(argv)))
            return SimpleNamespace(returncode=0, stdout="".join(lines))
        module.subprocess.run = ps
    r2_case.projection.after_signal.append(changed)
    code, answer = r2_case.stop(module, capsys, 0)
    assert lost and code == 3 and answer["pids"] == [host.pid]
    assert host.poll() is None and worker.poll() is None
    assert r2_case.projection.events == [(host.pid, signal.SIGTERM)]
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    saved = json.loads(path.read_text())
    first = next(e for e in saved["entries"] if e["pid"] == host.pid)
    assert not first["blocked"] and not first["identity_lost"]
    if check == "boot":
        assert boot is not None and saved["boot"] == boot
    elif check == "marker":
        assert answer.get("argv_boundaries") == "unproven"
    else:
        entry = next(e for e in saved["entries"] if e["pid"] == worker.pid)
        assert entry["snapshot"] is None and "start_time" not in entry["partial"] and "state" not in entry["partial"]


def test_r20_late_empty_lossy_census_creates_no_custody(r2_case, capsys):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module, calls = r2_case.module(False), []
    def provider(_session):
        calls.append(True)
        return module.ProcessCensus([], "proven" if len(calls) == 1 else "unproven")
    module.process_census = provider  # MODELLED empty OS cohort, then unavailable argument boundaries.
    code, answer = r2_case.stop(module, capsys, 0)
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert len(calls) >= 2 and code == 3 and answer["pids"] == [] and r2_case.projection.events == []
    assert not path.exists()
    assert answer.get("argv_boundaries") == "unproven" and "unsupported" in answer.get("error", "")


def test_r20_readonly_consumer_accepts_qualified_absence_with_an_unavailable_boot(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    held = r2_case.spawn(["claude", "--resume", session])
    row = module.read_process(held.pid).snapshot
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and held.wait(timeout=5) == -signal.SIGTERM
    launches = module.Launches(str(r2_case.launch.base))
    binding = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    observed = dict(candidates={held.pid: row}, initial_unavailable={}, blocked=set(), identity_lost=set(),
                    resolved={held.pid: answer["absence_evidence"][0]["proof"]})
    # MODELLED crash after an actual original-instance exit checkpoint, before terminal clear.
    with module.StopCustody(launches, REVIEW, binding) as custody:
        custody.save(observed, {held.pid}, active=True)
    path = launches.folder(REVIEW) / ".stop-custody" / "state.json"
    before = path.read_bytes()
    reader = r2_case.module(False)
    r2_case.ps(reader, None, [])
    reading = reader.read_process
    reader.read_process = lambda pid, *args: reading(pid, "unproven")
    assert reader.unresolved_stop_custody(str(r2_case.launch.base), REVIEW)
    assert path.read_bytes() == before and r2_case.projection.events == [(held.pid, signal.SIGTERM)]


@pytest.mark.parametrize("damage", ["duplicate-key", "unknown-field", "large-integer", "syntax"])
def test_r20_custody_json_refuses_without_echoing_payload(r2_case, capsys, damage):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    path = r13_seed_empty_journal(module, r2_case)
    sentinel = "MODELLED_PRIVATE_INPUT_NOT_FOR_ERRORS"
    if damage == "duplicate-key":
        raw = ('{"%s":1,"%s":2}' % (sentinel, sentinel)).encode()
    elif damage == "unknown-field":
        saved = json.loads(path.read_text())
        saved[sentinel] = "private"
        raw = json.dumps(saved).encode()
    elif damage == "syntax":
        raw = ('{"%s" 1}' % sentinel).encode()
    else:
        raw = ('{"schema":' + '9' * 200 + '}').encode()
    path.write_bytes(raw)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 2 and "custody" in answer["error"]
    assert sentinel not in json.dumps(answer) and path.read_bytes() == raw and r2_case.projection.events == []
    if damage == "large-integer":
        assert "invalid stop custody JSON" in answer["error"]


def r20_legacy_session(r2_case, session):
    import hashlib
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    box = module.Launches(str(r2_case.launch.base)).mailbox
    brief = r2_case.launch.base / "r20-guard-brief.md"
    brief.write_text("Continue the modelled legacy role.\n")
    box.bind(box.draft_handoff({"endpoint": REVIEW, "host": "claude-code", "session": session,
                               "outgoing_stopped": True,
                               "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}))
    return module


def test_r20_oversized_custody_is_refused_before_opening_a_read_stream(r2_case, capsys):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    path = r13_seed_empty_journal(module, r2_case)
    with path.open("r+b") as stream:
        stream.truncate(262145)
    calls, opening = [], module.os.fdopen

    def tracked_open(descriptor, mode, *args, **kwargs):
        if "r" in mode:
            calls.append(os.fstat(descriptor).st_size)
        return opening(descriptor, mode, *args, **kwargs)

    module.os.fdopen = tracked_open  # Passive module-local OS reader observation; refusal writes stay real.
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 2 and "invalid stop custody bytes: bounded ASCII required" in answer["error"]
    assert not calls and path.stat().st_size == 262145 and r2_case.projection.events == []


def test_r20_diagnostic_whole_session_atom_stays_unowned(r2_case, capsys):
    session = "modelled legacy session"
    module = r20_legacy_session(r2_case, session)
    held = r2_case.spawn(["diagnostic", session])
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "not_running" and answer["unowned_pids"] == [held.pid]
    assert held.poll() is None and r2_case.projection.events == []


@pytest.mark.parametrize("whitespace", [False, True], ids=["uuid", "whitespace"])
@pytest.mark.parametrize("complete", [True, False], ids=["complete", "malformed"])
def test_r20_lossy_census_cannot_clear_attempts_even_after_original_exit(r2_case, capsys, whitespace, complete):
    from types import SimpleNamespace

    session = "modelled legacy session" if whitespace else str(uuid.uuid4())
    first = r20_legacy_session(r2_case, session) if whitespace else None
    if not whitespace:
        r2_case.bind("claude-code", session)
        first = r2_case.module(False)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    def interrupted(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            raise KeyboardInterrupt("modelled lost acknowledgement before provider loss")
    r2_case.projection.after_signal.append(interrupted)
    try:
        with pytest.raises(KeyboardInterrupt, match="modelled lost acknowledgement"):
            r2_case.stop(first, capsys, 0)
    finally:
        r2_case.projection.after_signal.remove(interrupted)
    capsys.readouterr()
    module, gone = r2_case.module(False), []
    def exited(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            r2_case.configs[-1].with_suffix(".exit").touch()
            assert held.wait(timeout=5) == 0
            gone.append(True)
            r2_case.ps(module, None, [])
            if not complete:
                run = module.subprocess.run
                def malformed(command, **options):
                    if "-o" in command and "-p" not in command:
                        return SimpleNamespace(returncode=0, stdout="modelled incomplete process row\n")
                    return run(command, **options)
                module.subprocess.run = malformed
    r2_case.projection.after_signal.append(exited)
    code, answer = r2_case.stop(module, capsys, 0)
    assert gone and code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [held.pid]
    assert answer["reason"] == "argv_boundaries_unavailable"
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert json.loads(path.read_text())["active"]
    assert r2_case.projection.events == [(held.pid, signal.SIGTERM), (held.pid, signal.SIGTERM)]

# Bounded selector-state table from the registry/builders and round6 modelled cases.
# i indexes argv after the program. OPTIONS -> VALUE does not consume the next token;
# an option-shaped value blocks, leaving that token (especially --) for the next transition.
# BLOCKED is sticky. A Claude -- ends options; Codex's registered resume -- S remains valid.
# Each row gives proven and flattened outcomes separately: prompt text has stronger boundaries in /proc.
SELECTOR_STATE_CASES = [
    pytest.param("claude-code", ["--print", "--system-prompt", "Explain --resume", "--", "--resume <S>"],
                 False, False, id="modelled-system-prompt-consumed-terminator"),
    pytest.param("claude-code", ["--resume", "--", "--resume <S>"],
                 False, False, id="modelled-selector-consumed-terminator"),
    pytest.param("claude-code", ["--resume", "--print", "please --resume <S>"],
                 False, False, id="modelled-claude-option-valued-selection"),
    pytest.param("codex-cli", ["exec", "resume", "--last", "resume <S> prompt"],
                 False, False, id="modelled-codex-option-valued-selection"),
    pytest.param("claude-code", ["--resume", "unknown", "--resume", "<S>"],
                 False, False, id="modelled-unknown-value-cannot-recover"),
    pytest.param("claude-code", ["--resume", "<S>", "--session-id"],
                 False, False, id="modelled-missing-value-after-bound-selection"),
    pytest.param("claude-code", ["--resume", "<S>", "--resume", "--print", "wait"],
                 False, False, id="modelled-option-value-after-bound-selection"),
    pytest.param("claude-code", ["--resume", "<S>", "--resume", "unknown"],
                 False, False, id="modelled-unknown-selection-after-bound-selection"),
    pytest.param("codex-cli", ["exec", "resume", "--", "<S>", "prompt"],
                 True, True, id="established-codex-positional-terminator"),
    pytest.param("codex-cli", ["exec", "resume", "<S>", "please resume the review"],
                 True, True, id="builder-codex-ordinary-prompt"),
    pytest.param("claude-code", ["--session-id", "<S>", "--print", "please --resume the review"],
                 True, True, id="modelled-claude-ordinary-prompt"),
    pytest.param("claude-code", ["--resume", "<S>", "--", "--resume <T>"],
                 True, False, id="modelled-proven-prompt-versus-flat-conflict"),
    pytest.param("claude-code", ["--system-prompt", "--resume", "<S>"],
                 False, False, id="modelled-opaque-configuration-value"),
    pytest.param("claude-code", ["--system-prompt", "--resume", "--session-id", "<S>"],
                 True, False, id="modelled-proven-configuration-versus-flat-ambiguity"),
]


@pytest.fixture
def launch(tmp_path, tmp_path_factory, request):
    built = Launch(tmp_path, source_seed=worker_source_seed(tmp_path_factory, request))
    built.init()
    return built


@pytest.fixture
def children(tmp_path, r2_case):
    """Physical Python children; callers supply MODELLED complete host arrays, never a native inference."""
    running = []
    for name in ("sleeper.py", "claude", "codex", "K=V"):
        (tmp_path / name).write_text(CHILD, encoding="utf-8")

    def spawn(*argv, logical_argv, body=CHILD):
        argv = list(argv)
        if argv[0] != sys.executable:
            binary = Path(argv[0]).parent / "interpreters" / Path(argv[0]).name
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.symlink_to(sys.executable)
            argv[0] = str(binary)
        ready = tmp_path / ("ready-%d" % len(running))
        process = r2_case.spawn_legacy(argv, logical_argv, body, {"STOP_OWNERSHIP_READY": str(ready)})
        argv = list(process.args)
        running.append(process)
        wait_until(lambda: ready.exists() or process.poll() is not None)
        assert process.poll() is None, "the fake process exited before it was ready"
        assert Path("/proc/%d/cmdline" % process.pid).read_bytes().split(b"\0")[:-1] == [
            os.fsencode(word) for word in argv]
        return process

    spawn.case = r2_case
    spawn.projection = r2_case.projection
    spawn.module = r2_case.module
    yield spawn  # r2_case owns every physical instance before staging and closes the whole scope independently.


@pytest.mark.parametrize("host,program", [
    ("codex-cli", ("codex", "sleeper.py")),
    ("claude-code", ("claude", "sleeper.py")),
    ("claude-code", ("env", "K=V", "claude")),
    ("claude-code", ("env", "K=V", "OTHER=value", "claude")),
    ("claude-code", ("node", "claude")),
    ("claude-code", ("env", "K=V", "node", "claude")),
])
def test_stop_matches_the_bound_hosts_program(launch, children, host, program):
    # The role owns this checkout; no ancestor repository may supply its cwd validation.
    role_cwd = launch.tmp / "role-cwd"
    role_cwd.mkdir()
    git(role_cwd, "init", "-q", "-b", "test")
    git(role_cwd, "config", "--local", "user.name", "Test")
    git(role_cwd, "config", "--local", "user.email", "test@example.invalid")
    git(role_cwd, "commit", "--allow-empty", "-qm", "role cwd")
    assert Path(git(role_cwd, "rev-parse", "--show-toplevel")).resolve() == role_cwd.resolve()
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session, cwd=str(role_cwd))
    argv = [str(launch.tmp / word) if "=" not in word else word for word in program]
    if host == "codex-cli":
        argv = [argv[0], "-c", CHILD]
    owned = children(*argv, "resume" if host == "codex-cli" else "--resume", session, logical_argv=[*(str(launch.tmp / word) if "=" not in word else word for word in program if word != "sleeper.py"), "resume" if host == "codex-cli" else "--resume", session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert stopped["state"] == "stopped" and stopped["pids"] == [owned.pid]
    assert stopped["host"] == host and stopped["session"] == session
    assert owned.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("surface", ["census", "stop", "handoff"])
@pytest.mark.parametrize("transition", ["gone", "zombie", "dead-X-modelled", "dead-x-modelled", "restored"])
def test_r19_empty_discovery_observation_is_rechecked(r2_case, capsys, surface, transition):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    if surface == "handoff":
        assert r2_case.stop(module, capsys, 0)[0] == 0  # Real managed stop history, before the held process exists.
    held = r2_case.spawn(["claude", "--resume", session])
    module.read_process(held.pid)  # Verify this module's physical receipt before the negative observation.
    emptied, exits = [], []
    if transition.startswith("dead-"):
        def dead_state(path, raw):
            if str(path) == "/proc/%d/stat" % held.pid:
                prefix, _, tail = raw.rpartition(b")")
                words = tail.split()
                if words[0] == b"Z":
                    # MODELLED Linux dead-state byte for an independently real, already-exited zombie.
                    words[0] = transition.split("-")[1].encode()
                    return prefix + b") " + b" ".join(words)
            return raw
        r2_case.projection.path_view(module, dead_state)

    def empty_then_transition(pid, count, row):
        if pid != held.pid or emptied:
            return row
        emptied.append(row.start_time)
        # MODELLED empty OS observation, with actual UID/birth and independently real lifetime transitions.
        if transition != "restored":
            r2_case.configs[0].with_suffix(".exit").touch()
            if transition == "gone":
                assert held.wait(timeout=5) == 0
            else:
                wait_until(lambda: r2_kernel_process(held.pid)["state"] == "Z")
            exits.append(True)
        return row._replace(cmdline=b"", argv=())

    r2_case.projection.after_present.append(empty_then_transition)
    if surface == "census":
        found = module.session_processes(session, set(), "claude-code")
        assert found == ([(held.pid, os.getpgid(held.pid))] if transition == "restored" else [])
    elif surface == "stop":
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 0 and answer["state"] == ("stopped" if transition == "restored" else "not_running")
        assert answer["pids"] == ([held.pid] if transition == "restored" else [])
        assert r2_case.projection.events == ([(held.pid, signal.SIGTERM)] if transition == "restored" else [])
    else:
        control = handoff_module()
        control.hierarchy_launcher = module
        answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys,
                          2 if transition == "restored" else 0)
        if transition == "restored":
            assert str(held.pid) in answer["error"] and "process census failed" not in answer["error"]
        else:
            assert answer["entries"][0]["generation"] == 2
        assert r2_case.projection.events == []
    assert emptied
    if transition != "restored":
        assert exits and held.wait(timeout=5) == 0
    elif surface == "stop":
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        assert held.poll() is None


@pytest.mark.parametrize("scope", ["user", "other-user-modelled", "kernel-modelled", "kernel-reused-birth-modelled"])
def test_r19_persistent_empty_discovery_respects_scope(r2_case, scope):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    module.read_process(held.pid)
    reads = []
    sampling = [False]
    if scope == "kernel-reused-birth-modelled":
        reading = module.read_process

        def sampled(*args, **kwargs):
            sampling[0] = True
            try:
                return reading(*args, **kwargs)
            finally:
                sampling[0] = False
        module.read_process = sampled

    def empty(path, raw):
        if str(path) == "/proc/%d/cmdline" % held.pid:
            reads.append(raw)
            return b""
        if scope == "other-user-modelled" and str(path) == "/proc/%d/status" % held.pid:
            return status_uids(raw, os.geteuid() + 1, os.geteuid() + 1)
        if scope.startswith("kernel-") and str(path) == "/proc/%d/stat" % held.pid:
            # MODELLED kernel-only scope, not an exit or positive signal grant. Physical custody stays real.
            prefix, _, tail = raw.rpartition(b")")
            words = tail.split()
            words[1], words[2] = b"2", b"0"
            words[6] = str(int(words[6]) | 0x00200000).encode()  # Linux PF_KTHREAD.
            if scope == "kernel-reused-birth-modelled" and not sampling[0]:
                # MODELLED secondary stat from a different instance: it cannot exclude the original row.
                words[19] = str(int(words[19]) + 1).encode()
            return prefix + b") " + b" ".join(words)
        return raw

    r2_case.projection.path_view(module, empty)
    if scope in ("user", "kernel-reused-birth-modelled"):
        with pytest.raises(module.CensusUnavailable, match="process census unresolved: %d" % held.pid):
            module.session_processes(session, set(), "claude-code")
        assert len(reads) >= 2  # Persistent means a fresh same-birth observation, not the first empty sample.
    else:
        assert module.session_processes(session, set(), "claude-code") == []
    assert reads and held.poll() is None and r2_case.projection.events == []


@pytest.mark.parametrize("pidfds", [False, True], ids=["numeric", "pidfd"])
@pytest.mark.parametrize("phase", ["first", "escalation"])
def test_r18_fsync_drift_is_rechecked_before_delivery(r2_case, capsys, pidfds, phase):
    import stat

    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(pidfds)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    syncing, changed = module.os.fsync, []

    def commit(fd):
        syncing(fd)
        if changed or not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        path = Path(os.readlink("/proc/self/fd/%d" % fd))
        if path.parent.name != ".stop-custody" or not path.name.endswith(".tmp"):
            return
        data = json.loads(path.read_text())
        if not any(row["pid"] == held.pid and row["attempted"] for row in data["entries"]):
            return
        if phase == "escalation" and (held.pid, signal.SIGTERM) not in r2_case.projection.events:
            return
        changed.append(True)  # MODELLED exec at the OS boundary, while the real fsync barrier blocks.
    module.os.fsync = commit

    def exec_drift(pid, count, row):
        if changed and pid == held.pid:
            return row._replace(argv=("claude", "--resume", other), cmdline=row.cmdline + other.encode() + b"\0")
        return row
    r2_case.projection.after_present.append(exec_drift)
    code, answer = r2_case.stop(module, capsys, 0)
    expected = [] if phase == "first" else [(held.pid, signal.SIGTERM)]
    assert changed and held.poll() is None and r2_case.projection.events == expected
    assert code == 3 and answer["unresolved_pids"] == [held.pid]
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert json.loads(journal.read_text())["active"]
    assert not answer.get("possible_pids")
    assert next(entry for entry in json.loads(journal.read_text())["entries"]
                if entry["pid"] == held.pid)["attempted"] is (phase == "escalation")


def test_r18_resolved_exit_survives_recovery_with_a_reused_pid(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(True)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, worker = family["H"], family["W"]

    def exit_host(pid, number):
        if pid == host.pid and number == signal.SIGTERM:
            slot = next(s for s, e in r2_case.custody.entries.items() if e["pid"] == host.pid)
            r2_case.custody.kill_owned(slot)
            assert host.wait(timeout=5) == -signal.SIGKILL

    def denied(path, raw):
        if (worker.pid, signal.SIGTERM) in r2_case.projection.events and str(path) == "/proc/%d/cmdline" % worker.pid:
            raise PermissionError("modelled unresolved worker")
        return raw
    r2_case.projection.after_signal.append(exit_host)
    r2_case.projection.path_view(module, denied)
    code, first = r2_case.stop(module, capsys, 0)
    assert code == 3 and first["unresolved_pids"] == [worker.pid]
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert next(e for e in json.loads(path.read_text())["entries"] if e["pid"] == host.pid)["resolved"] == "original_pidfd_exit"
    unrelated = r2_case.spawn(["diagnostic", "unrelated"])
    recovery = r2_case.module(False)
    census = recovery.process_census

    def reused(bound):
        rows = census(bound)
        replacement = next(row for row in rows if row.pid == unrelated.pid)
        assert replacement.start_time != next(e for e in json.loads(path.read_text())["entries"]
                                               if e["pid"] == host.pid)["snapshot"]["start_time"]
        # MODELLED PID reuse only; original H's pidfd exit and the unrelated child's identity are real.
        return recovery.ProcessCensus([*rows, replacement._replace(pid=host.pid)], rows.argv_boundaries, rows.unavailable)
    recovery.process_census = reused
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(recovery, capsys, 0)
    saved = next(e for e in json.loads(path.read_text())["entries"] if e["pid"] == host.pid)
    assert code == 3 and answer["unresolved_pids"] == [worker.pid]
    assert saved["resolved"] == "original_pidfd_exit" and not saved["blocked"] and not saved["identity_lost"]
    assert unrelated.poll() is None and r2_case.projection.events == before


def test_r18_identity_loss_handoff_names_owner_reconciliation(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for
    from tests.integration.test_hierarchy_handoff import mailbox_files

    held, path, saved = r7_pending_attempt(r2_case, capsys)
    saved["entries"][0].update(blocked=True, identity_lost=True)
    path.write_text(json.dumps(saved))
    control = handoff_module()
    control.hierarchy_launcher = r2_case.module(False)
    spec = spec_for(r2_case.launch)
    before = mailbox_files(r2_case.launch.base)
    answer = run_main(control, r2_case.launch, spec, capsys, 2)
    assert "manual reconciliation" in answer["error"] and "mv -i" in answer["error"] and str(path) in answer["error"]
    assert mailbox_files(r2_case.launch.base) == before and held.poll() is None


@pytest.mark.parametrize("arguments", [["node", "--max-old-space-size=4096", "server.js"],
                                        ["node", "--enable-source-maps", "server.js"],
                                        ["claude", "--resume", "--print", "wait"]])
@pytest.mark.parametrize("exits", [False, True], ids=["survives", "exits-with-host"])
def test_r18_hold_lineage_is_accounted_even_without_the_session(r2_case, capsys, arguments, exits):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    family = r2_case.spawn_group(["claude", "--resume", session], named_child=arguments)
    host, worker = family["H"], family["M"]

    def host_ended(pid, number):
        if pid == host.pid and number == signal.SIGTERM:
            assert host.wait(timeout=5) == -signal.SIGTERM
            if exits:
                r2_case.configs[0].with_suffix(".exit").touch()
                wait_until(lambda: worker.poll() == "CONFIRMED_EXIT")
    r2_case.projection.after_signal.append(host_ended)
    code, answer = r2_case.stop(module, capsys, 0)
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)
    if exits:
        assert code == 0 and worker.pid in [e["pid"] for e in answer["absence_evidence"]]
    else:
        assert worker.poll() is None and code == 3 and worker.pid in answer["unresolved_pids"]


def test_r18_hold_intermediate_keeps_its_subtree_and_orphan_unresolved(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, middle, worker = (family[key] for key in ("H", "M", "W"))

    def intermediate(pid, count, row):
        return row._replace(argv=("node", "--enable-source-maps", "server.js")) if pid == middle.pid else row
    r2_case.projection.after_present.append(intermediate)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and set(answer["unresolved_pids"]) == {middle.pid, worker.pid}
    assert middle.poll() is None and worker.poll() is None and host.wait(timeout=5) == -signal.SIGKILL
    assert all(pid == host.pid for pid, _ in r2_case.projection.events)


@pytest.mark.parametrize("provider", ["reader", "census"])
@pytest.mark.parametrize("other_uid", [False, True], ids=["same-user", "other-user-modelled"])
def test_r18_empty_discovery_cmdline_is_unknown_not_gone(r2_case, capsys, provider, other_uid):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    held = r2_case.spawn(["claude", "--resume", session])
    module.read_process(held.pid)  # Full positive fingerprint before the admitted negative empty observation.
    if provider == "reader":
        def empty_read(path, raw):
            if str(path) == "/proc/%d/cmdline" % held.pid:
                return b""
            if other_uid and str(path) == "/proc/%d/status" % held.pid:
                return status_uids(raw, os.geteuid() + 1, os.geteuid() + 1)
            return raw
        r2_case.projection.path_view(module, empty_read)

    def empty(pid, count, row):
        if pid == held.pid:
            return row._replace(cmdline=b"", argv=(), uid=row.uid + int(other_uid), euid=row.euid + int(other_uid))
        return row
    if provider == "census":
        r2_case.projection.after_present.append(empty)
    code, answer = r2_case.stop(module, capsys, 0)
    assert held.poll() is None and r2_case.projection.events == []
    assert code == (0 if other_uid else 3)
    if not other_uid:
        assert answer["unresolved_pids"] == [held.pid] and answer["pids"] == []


@pytest.mark.parametrize("surface", ["stop", "foreground", "background", "idempotent", "cleanup"])
def test_r18_symlinked_launches_never_means_absent_custody(r2_case, capsys, surface):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for
    from tests.integration.test_hierarchy_native_probe import Probe

    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    base = r2_case.launch.base
    original = base / "launches"
    original.mkdir(exist_ok=True)
    original.rename(base / "retained-launches")
    empty = r2_case.launch.tmp / "empty-launches"
    empty.mkdir()
    original.symlink_to(empty, target_is_directory=True)
    if surface == "stop":
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 2 and ("custody" in answer["error"] or "symlink" in answer["error"])
    elif surface == "cleanup":
        folder = r2_case.launch.tmp / "r18-probe"
        folder.mkdir()
        probe = Probe(folder)
        try:
            plan = probe.plan([{"role": "implementer"}])
            plan["roles"][0].update(base=str(base), endpoint=REVIEW)
            (probe.root / "probe.json").write_text(json.dumps(plan))
            control = r16_cleanup_control(probe, module)
            code = control.main(["cleanup", "--probe-root", str(probe.root)])
            answer = json.loads(capsys.readouterr().out)
            assert code == 3 and answer["cleanup"]["unresolved_custody"] and Path(plan["worktree"]).is_dir()
        finally:
            probe.close()
    else:
        control = handoff_module()
        control.hierarchy_launcher = module
        spec = spec_for(r2_case.launch)
        if surface == "idempotent":
            spec.update(host="claude-code", session=r2_case.launch.binding()["session"])
        if surface == "background":
            profile = base / "profiles" / (module.quoted(REVIEW) + "-g1.wake.json")
            data = json.loads(profile.read_text())
            profile.write_text(json.dumps({**data, "mode": "background"}))
        answer = run_main(control, r2_case.launch, spec, capsys, 2)
        assert "custody" in answer["error"] or "symlink" in answer["error"]
    assert r2_case.projection.events == []


@pytest.mark.parametrize("state", ["S", "Ss"])
@pytest.mark.parametrize("check", ["readable", "no-latch", "strong-provider-recovers"])
def test_r18_ps_scope_stays_diagnostic_across_recovery(r2_case, capsys, state, check):
    from types import SimpleNamespace

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn_group(["claude", "--resume", session], stubborn=True)
    host, worker = family["H"], family["M"]
    module = r2_case.module(False)
    census = module.process_census

    def only_host(bound):
        rows = census(bound)
        return module.ProcessCensus([r for r in rows if r.pid == host.pid], rows.argv_boundaries, {})
    module.process_census = only_host

    def interrupted(pid, number):
        if pid == host.pid and number == signal.SIGTERM:
            raise KeyboardInterrupt("modelled lost stop before discovering W")
    r2_case.projection.after_signal.append(interrupted)
    try:
        with pytest.raises(KeyboardInterrupt, match="modelled lost stop"):
            r2_case.stop(module, capsys, 0)
    finally:
        r2_case.projection.after_signal.remove(interrupted)
    capsys.readouterr()
    recovery = r2_case.module(False)
    r2_case.ps(recovery, worker, ["worker"])

    def shown(command, **kwargs):
        targets = [host, worker]
        if "-p" in command:
            targets = [p for p in targets if p.pid == int(command[command.index("-p") + 1])]
        lines = []
        for process in targets:
            physical = r2_kernel_process(process.pid)
            argv = ["claude", "--resume", session] if process.pid == host.pid else ["worker"]
            lines.append("%d %d %d %d %d %s Sat Nov 7 12:00:00 2026 %s\n" % (
                process.pid, physical["pgid"], physical["ppid"], physical["uid"], physical["euid"], state, " ".join(argv)))
        return SimpleNamespace(returncode=0, stdout="".join(lines))
    recovery.subprocess.run = shown  # MODELLED ps text; PIDs, UIDs, PPIDs and groups are independently real.
    before = list(r2_case.projection.events)
    path = recovery.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    before_custody = path.read_bytes()
    code, answer = r2_case.stop(recovery, capsys, 0)
    assert code == 3 and host.poll() is None and worker.poll() is None and r2_case.projection.events == before
    path = recovery.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    if check == "readable":
        assert worker.pid not in {entry["pid"] for entry in json.loads(path.read_text())["entries"]} and path.read_bytes() == before_custody
        assert recovery.unresolved_stop_custody(str(r2_case.launch.base), REVIEW)
    elif check == "no-latch":
        assert not any(e["identity_lost"] or e["blocked"] for e in json.loads(path.read_text())["entries"])
    else:
        code, final = r2_case.stop(r2_case.module(False), capsys, 0)
        assert code == 0 and final["state"] == "stopped" and worker.pid in final["pids"]
        assert (host.pid, signal.SIGKILL) in r2_case.projection.events and host.wait(timeout=5) == -signal.SIGKILL
        assert worker.poll() == "CONFIRMED_EXIT" and (worker.pid, signal.SIGKILL) in r2_case.projection.events


@pytest.mark.parametrize("shape", ["malformed", "truncated"])
def test_r18_incomplete_ps_cannot_discharge_coverage_after_a_retained_exit(r2_case, capsys, shape):
    from types import SimpleNamespace

    old, path, _ = r7_pending_attempt(r2_case, capsys)
    session = r2_case.launch.binding()["session"]
    current = r2_case.spawn(["claude", "--resume", session], ignore=True)
    r2_case.configs[0].with_suffix(".exit").touch()
    assert old.wait(timeout=5) == 0
    module = r2_case.module(False)
    r2_case.ps(module, current, ["claude", "--resume", session])
    run, reads = module.subprocess.run, []

    def truncated_census(command, **options):
        if "-o" in command and "args=" in command[command.index("-o") + 1]:
            if "-p" in command:
                if int(command[command.index("-p") + 1]) != current.pid:
                    return SimpleNamespace(returncode=1, stdout="")
                return run(command, **options)
            physical = r2_kernel_process(current.pid)
            reads.append(physical)
            # MODELLED incomplete ps output. The missing process is an independently real live child.
            text = ("unparseable process row\n" if shape == "malformed" else
                    "%d %d %d %d %d %s\n" % (current.pid, physical["pgid"], physical["ppid"],
                                               physical["uid"], physical["euid"], physical["state"]))
            return SimpleNamespace(returncode=0, stdout=text)
        return run(command, **options)

    module.subprocess.run = truncated_census
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(module, capsys, 0)
    assert reads and current.poll() is None and r2_case.projection.events == before
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [old.pid]
    assert answer["reason"] == "argv_boundaries_unavailable" and json.loads(path.read_text())["active"]


def test_r18_writer_rejects_diagnostic_snapshot_before_publication(r2_case):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    held = r2_case.spawn(["claude", "--resume", session])
    row = module.read_process(held.pid).snapshot._replace(state="Ss", start_time="Sat Nov 7 12:00:00 2026")
    observed = dict(candidates={held.pid: row}, initial_unavailable={}, blocked=set(), identity_lost=set(), resolved={})
    binding = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    with module.StopCustody(module.Launches(str(r2_case.launch.base)), REVIEW, binding) as custody:
        with pytest.raises(ValueError, match="invalid stop custody state"):
            custody.save(observed, set())
        assert not custody.path.exists()


def r18_fake_claude_hang(case, session, selectors):
    """Pinned fake's real last-selector choice; only its complete OS argv projection is MODELLED."""
    import re

    fake = ROOT / "tests/integration/hierarchy_fake_claude.py"
    home = Path(case.env["CLAUDE_CONFIG_DIR"])
    home.mkdir(parents=True, exist_ok=True)
    (home / ".credentials.json").write_text('{"fake":true}\n')
    transcript = home / "projects" / re.sub(r"[^A-Za-z0-9]", "-", str(case.launch.tmp)) / (session + ".jsonl")
    transcript.parent.mkdir(parents=True)
    transcript.write_text("")
    args = ["-p", "--verbose", "--output-format", "stream-json", "--restricted", "--strict-mcp-config",
            "--permission-mode", "bypassPermissions", "--permission-prompts", "none", "--tools=",
            *selectors, "--", "modelled hang prompt"]
    # Per-loaded fake module: no owner-home lookup, global OS patch or import from its working directory.
    body = ("import builtins, types\n"
            "from pathlib import Path\n"
            "target = Path(" + repr(str(fake)) + ")\n"
            "sys.path.insert(0, str(target.parent))\n"
            "importing = builtins.__import__\n"
            "def isolated(name, globals=None, locals=None, fromlist=(), level=0):\n"
            "    if name == 'pwd':\n"
            "        return types.SimpleNamespace(getpwuid=lambda uid: types.SimpleNamespace(pw_dir=" + repr(str(case.home)) + "))\n"
            "    return importing(name, globals, locals, fromlist, level)\n"
            "loaded = types.ModuleType('_pinned_fake_claude')\n"
            "loaded.__dict__.update(__file__=str(target), __package__='', __builtins__={**vars(builtins), '__import__': isolated})\n"
            "exec(compile(target.read_bytes(), str(target), 'exec'), loaded.__dict__)\n"
            "sys.exit(loaded.main())\n")
    held = case.spawn_legacy([str(case.launch.tmp / "claude"), *args], ["claude", *args], body,
                             {"FAKE_CLAUDE_MODE": "hang"})
    wait_until(lambda: transcript.stat().st_size > 0 or held.poll() is not None)
    assert held.poll() is None and '"sessionId": "' + session + '"' in transcript.read_text()
    return held


@pytest.mark.parametrize("surface", ["stop", "handoff"])
def test_r18_conflicting_selectors_keep_the_actual_fake_session_unresolved(r2_case, capsys, surface):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for
    from tests.integration.test_hierarchy_handoff import mailbox_files

    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    code, absent = r2_case.stop(module, capsys, 0)
    assert code == 0 and absent["state"] == "not_running"  # Establish the managed launch history before H exists.
    held = r18_fake_claude_hang(r2_case, session, ["--resume", other, "--resume", session])
    spec = spec_for(r2_case.launch)
    before = mailbox_files(r2_case.launch.base)
    if surface == "stop":
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 3 and answer["unresolved_pids"] == [held.pid]
        assert held.pid not in answer.get("spared_descendants", [])
    else:
        control = handoff_module()
        control.hierarchy_launcher = module
        answer = run_main(control, r2_case.launch, spec, capsys, 2)
        assert "process census" in answer["error"] and str(held.pid) in answer["error"]
        assert mailbox_files(r2_case.launch.base) == before
    assert held.poll() is None and r2_case.projection.events == []


def test_r18_repeated_same_session_still_stops_the_actual_fake(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    held = r18_fake_claude_hang(r2_case, session, ["--resume", session, "--resume", session])
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_r18_one_actor_interruption_fixture_declares_its_census_cohort(r2_case, capsys):
    unrelated = r2_case.spawn(["diagnostic", "outside-the-declared-cohort"])

    def empty(pid, count, row):
        return row._replace(cmdline=b"", argv=()) if pid == unrelated.pid else row
    r2_case.projection.after_present.append(empty)
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    assert [entry["pid"] for entry in saved["entries"]] == [held.pid]
    assert saved["entries"][0]["attempted"] and unrelated.poll() is None
    assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]


def test_r17_forged_attempt_never_authorizes_an_unrelated_live_process(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    editor = r2_case.spawn(["diagnostic", "open-transcript"], ignore=True)
    row = module.read_process(editor.pid).snapshot
    physical = r2_kernel_process(editor.pid)
    assert row.start_time == physical["birth"] and row.cmdline == physical["raw"]
    assert row.uid == row.euid == os.geteuid() and r2_case.projection.events == []
    launches = module.Launches(str(r2_case.launch.base))
    binding = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    forged = dict(candidates={editor.pid: row}, initial_unavailable={}, blocked=set(), identity_lost=set(), resolved={})
    # MODELLED attacker-written, schema-valid journal: actual UID/birth/raw digest, but no real public attempt.
    # The unrelated process itself stays under independent, real physical fixture custody.
    with module.StopCustody(launches, REVIEW, binding) as custody:
        custody.save(forged, {editor.pid}, active=True)
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed"
    assert editor.poll() is None and r2_case.projection.events == []
    assert editor.pid in answer["unresolved_pids"]
    assert json.loads(custody.path.read_text())["active"]


@pytest.mark.parametrize("level", ["endpoint", "launches", "base"])
def test_r17_ancestor_namespace_replacement_refuses_before_signal(r2_case, capsys, level):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    held = r2_case.spawn(["claude", "--resume", session])
    folder = module.Launches(str(r2_case.launch.base)).folder(REVIEW)
    target = {"endpoint": folder, "launches": folder.parent, "base": folder.parent.parent}[level]
    opening, swapped = module.os.open, []

    def replace(source, flags, *args, **kwargs):
        if flags & os.O_CREAT and str(source).endswith(".tmp") and not swapped:
            target.rename(target.with_name(target.name + "-original"))
            target.mkdir()
            swapped.append(True)
        return opening(source, flags, *args, **kwargs)

    module.os.open = replace
    code, answer = r2_case.stop(module, capsys, 0)
    assert swapped and code == 2 and "stop custody namespace changed" in answer["error"]
    assert held.poll() is None and r2_case.projection.events == []


@pytest.mark.parametrize("interrupted", ["worker", "leader"])
def test_r17_recovery_proves_live_ancestry_before_any_delivery(r2_case, capsys, interrupted):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, worker = family["H"], family["W"]
    if interrupted == "worker":
        def lost(pid, number):
            if pid == worker.pid and number == signal.SIGTERM:
                raise KeyboardInterrupt("modelled lost worker acknowledgement")
        r2_case.projection.after_signal.append(lost)
        try:
            with pytest.raises(KeyboardInterrupt, match="modelled lost worker acknowledgement"):
                r2_case.stop(module, capsys, 0)
        finally:
            r2_case.projection.after_signal.remove(lost)
        capsys.readouterr()
    else:
        # MODELLED lost pre-syscall acknowledgement: this stores H as possibly attempted, not authority.
        row = module.read_process(host.pid).snapshot
        observed = dict(candidates={host.pid: row}, initial_unavailable={}, blocked=set(),
                        identity_lost=set(), resolved={})
        binding = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
        with module.StopCustody(module.Launches(str(r2_case.launch.base)), REVIEW, binding) as custody:
            custody.save(observed, {host.pid})

    def reaped(pid, number):
        if pid == host.pid and number == signal.SIGTERM:
            # MODELLED host exit at TERM receipt: the tree fixture's H deliberately ignores TERM.
            # Independent physical custody ends only H, exposing whether W was discovered first.
            slot = next(slot for slot, entry in r2_case.custody.entries.items() if entry["pid"] == host.pid)
            r2_case.custody.kill_owned(slot)
            assert host.wait(timeout=5) == -signal.SIGKILL
    r2_case.projection.after_signal.append(reaped)
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 0 and answer["state"] == "stopped"
    assert worker.poll() == "CONFIRMED_EXIT" and worker.pid in answer["pids"]
    events = r2_case.projection.events
    assert events.index((worker.pid, signal.SIGTERM)) < events.index((host.pid, signal.SIGTERM))


@pytest.mark.parametrize("coverage", ["argv_boundaries_unavailable", "session_instance_unresolved_after_exit"])
def test_r17_every_coverage_obligation_roundtrips_to_next_stop(r2_case, capsys, coverage):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    path = r13_seed_empty_journal(module, r2_case)
    saved = json.loads(path.read_text())
    saved.update(active=True, coverage=coverage)
    path.write_text(json.dumps(saved))
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 0 and answer["state"] == "not_running"
    assert not json.loads(path.read_text())["active"] and r2_case.projection.events == []


def test_r17_no_proc_retained_exit_is_verified_without_boot_id(r2_case, capsys):
    held, path, _ = r7_pending_attempt(r2_case, capsys)
    r2_case.configs[0].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    before = path.read_bytes()
    module = r2_case.module(False)
    r2_case.ps(module, held, ["claude", "--resume", r2_case.launch.binding()["session"]])
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == [held.pid]
    assert path.read_bytes() == before and json.loads(path.read_text())["active"]
    # A second no-/proc invocation can read the completed journal, without a corrupt boot=None dead end.
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and path.read_bytes() == before


def test_r17_empty_ps_journal_never_creates_an_exit_proof(r2_case, capsys):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    r2_case.ps(module, None, [])
    for _ in range(2):
        code, answer = r2_case.stop(module, capsys, 0)
        assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
        assert answer["reason"] == "argv_boundaries_unavailable" and r2_case.projection.events == []
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert not path.exists()


@pytest.mark.parametrize("session", ["s 1", "s\t1", "s\n1"], ids=["space", "tab", "newline"])
def test_r17_ps_cannot_clear_coverage_for_a_whitespace_session(r2_case, capsys, session):
    import hashlib

    r2_case.bind("codex-cli", str(uuid.uuid4()))
    module = r2_case.module(False)
    launches = module.Launches(str(r2_case.launch.base))
    brief = r2_case.launch.base / "r17-ps-brief.md"
    brief.write_text("Continue the modelled role.\n")
    launches.mailbox.bind(launches.mailbox.draft_handoff({
        "endpoint": REVIEW, "host": "codex-cli", "session": session, "outgoing_stopped": True,
        "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}))
    argv = ["codex", "exec", "resume", session]
    old = r2_case.spawn(argv)
    row = module.read_process(old.pid).snapshot
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert old.wait(timeout=5) == 0 and module.read_process(old.pid).kind == "CONFIRMED_ABSENT"
    binding = {key: r2_case.launch.binding()[key] for key in ("host", "session", "generation")}
    # Legitimate previously discharged C, not borrowed authority: its original instance is physically gone.
    observed = dict(candidates={old.pid: row}, initial_unavailable={}, blocked=set(), identity_lost=set(),
                    resolved={old.pid: "qualified_namespace_ESRCH"})
    with module.StopCustody(launches, REVIEW, binding) as custody:
        custody.save(observed, set(), active=False)
    current = r2_case.spawn(argv)
    r2_case.ps(module, current, argv)  # MODELLED flattened boundary, independently real live process/UID.
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
    assert current.poll() is None and r2_case.projection.events == []
    assert answer["reason"] == "argv_boundaries_unavailable"


@pytest.mark.parametrize("spelling", ["glued", "space", "colon"])
def test_r17_discovery_and_custody_cover_registry_session_spellings(r2_case, capsys, spelling):
    session = str(uuid.uuid4()) if spelling == "glued" else "s 1" if spelling == "space" else "s:1"
    # MODELLED a binding produced by handoff, whose public session contract admits these atoms.
    r2_case.bind("codex-cli" if spelling != "glued" else "claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    mailbox = module.Launches(str(r2_case.launch.base)).mailbox
    brief = r2_case.launch.base / "r17-brief.md"
    brief.write_text("Continue the modelled role.\n")
    import hashlib
    mailbox.bind(mailbox.draft_handoff({"endpoint": REVIEW, "host": "claude-code" if spelling == "glued" else "codex-cli",
                                       "session": session, "outgoing_stopped": True,
                                       "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}))
    argv = ["claude", "-r" + session, "-p", "wait"] if spelling == "glued" else ["codex", "exec", "resume", session]
    held = r2_case.spawn(argv)
    code, answer = r2_case.stop(module, capsys, 0)
    if spelling == "glued":
        assert code == 3 and answer["state"] == "stop_failed" and answer["unresolved_pids"] == [held.pid]
        assert held.poll() is None and r2_case.projection.events == []
    else:
        assert code == 0 and answer["state"] == "stopped" and held.wait(timeout=5) == -signal.SIGTERM
        assert not module.unresolved_stop_custody(str(r2_case.launch.base), REVIEW)


@pytest.mark.parametrize("evidence,expected", [("incoherent", "refuse"), ("no-birth", "resolved"),
                                               ("replacement", "refuse")])
def test_r17_resolved_partial_evidence_uses_only_coherent_birth(r2_case, capsys, evidence, expected):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    entry = saved["entries"][0]
    entry.update(snapshot=None, attempted=False, resolved="matching_partial_birth_zombie")
    birth = r2_kernel_process(held.pid)["birth"]
    entry["partial"] = {} if evidence == "no-birth" else {
        "start_time": str(int(birth) - 1), "coherent_birth": evidence == "replacement"}
    saved["active"] = False
    saved.pop("groups", None)  # Historical per-PID record; no retained group is claimed by this fixture.
    path.write_text(json.dumps(saved))
    module = r2_case.module(False)
    reading = module.read_process

    def unavailable(pid, *args):
        if pid == held.pid and evidence == "replacement":
            return module.ProcessObservation("UNAVAILABLE", pid, partial={"start_time": birth, "coherent_birth": True},
                                             reason="modelled replacement cmdline unreadable")
        return reading(pid, *args)
    module.read_process = unavailable
    if evidence == "no-birth":
        r2_case.configs[0].with_suffix(".exit").touch()
        assert held.wait(timeout=5) == 0
    if expected == "refuse":
        with pytest.raises(ValueError, match="resolved stop custody lacks physical exit proof"):
            module.require_resolved_custody(str(r2_case.launch.base), REVIEW)
    else:
        module.require_resolved_custody(str(r2_case.launch.base), REVIEW)
    assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]


def test_r15_delivery_rediscovers_a_late_visible_owned_group_child(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn_group(["claude", "--resume", session])
    host, worker = family["H"], family["M"]
    physical = r2_kernel_process(worker.pid)
    assert physical["ppid"] == host.pid and physical["pgid"] == host.pid
    module, censuses = r2_case.module(False), []
    census = module.process_census

    def enumerated(bound):
        result = census(bound)
        censuses.append(True)
        # MODELLED enumeration racing a fork: only the initial snapshot omits this test-owned child.
        # Every returned atom, UID, birth, PPID, group and subsequent observation stays physical.
        if len(censuses) == 1:
            return module.ProcessCensus([row for row in result if row.pid != worker.pid],
                                        result.argv_boundaries, result.unavailable)
        return result

    def delivered(pid, number):
        if pid == host.pid and number == signal.SIGTERM:
            assert host.wait(timeout=5) == -signal.SIGTERM

    module.process_census = enumerated
    r2_case.projection.after_signal.append(delivered)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "stopped"
    assert worker.poll() == "CONFIRMED_EXIT"
    assert answer["pids"] == sorted([host.pid, worker.pid])
    assert (worker.pid, signal.SIGTERM) in r2_case.projection.events


def test_r15_missing_intermediary_keeps_the_visible_worker_pending(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, middle, worker = (family[name] for name in ("H", "M", "W"))
    module, hidden, ended = r2_case.module(False), [], []

    def unavailable(path, raw):
        if str(path) == "/proc/%d/status" % middle.pid and not ended:
            hidden.append(True)
            raise PermissionError("modelled unreadable intermediary metadata")
        return raw

    def delivered(pid, number):
        if pid == host.pid and number == signal.SIGTERM:
            for name in ("H", "M"):
                slot = next(slot for slot, row in r2_case.custody.entries.items() if row["pid"] == family[name].pid)
                r2_case.custody.kill_owned(slot)
            assert host.wait(timeout=5) == -signal.SIGKILL
            wait_until(lambda: middle.poll() == "CONFIRMED_EXIT")
            ended.append(True)

    r2_case.projection.path_view(module, unavailable)
    r2_case.projection.after_signal.append(delivered)
    code, answer = r2_case.stop(module, capsys, 0)
    assert hidden and ended and worker.poll() is None
    assert code == 3 and answer["state"] == "stop_failed"
    assert worker.pid in answer["unresolved_pids"] and worker.pid not in answer["pids"]
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert json.loads(journal.read_text())["active"]


def test_r15_terminal_success_requires_a_fresh_group_census(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn_group(["claude", "--resume", session])
    host, worker = family["H"], family["M"]
    module, censuses = r2_case.module(False), []
    census = module.process_census

    def enumerated(bound):
        result = census(bound)
        censuses.append(True)
        # MODELLED fork after delivery discovery. The worker's real parent, group, birth and UID stay intact.
        if len(censuses) <= 2:
            return module.ProcessCensus([row for row in result if row.pid != worker.pid],
                                        result.argv_boundaries, result.unavailable)
        return result

    def delivered(pid, number):
        if pid == host.pid and number == signal.SIGTERM:
            assert host.wait(timeout=5) == -signal.SIGTERM

    module.process_census = enumerated
    r2_case.projection.after_signal.append(delivered)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 3 and answer["state"] == "stop_failed" and worker.poll() is None
    assert answer["pids"] == [host.pid] and answer["unresolved_pids"] == [worker.pid]
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)


def test_r15_fresh_session_instance_after_exit_never_borrows_the_old_attempt(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    r2_case.projection.group_reaping = False  # This control deliberately keeps the actual zombie available.
    module, witnessed, replacements = r2_case.module(False), [], []

    def delivered(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            wait_until(lambda: r2_kernel_process(pid)["state"].startswith("Z"))

    reading = module.read_process

    def replaced(pid, *args, **kwargs):
        physical = reading(pid, *args, **kwargs)  # Preserve the strict, module-local receipt reader first.
        row = physical.snapshot
        if pid == held.pid and row is not None and row.state.startswith("Z"):
            if not witnessed:
                witnessed.append(row.start_time)  # The original exit is physically real and unreaped.
            else:
                replacements.append(True)
                # MODELLED later PID reuse at the OS boundary; negative discovery only, never authority.
                return physical._replace(snapshot=row._replace(
                    state="R", start_time=str(int(row.start_time) + 1), argv=("claude", "--resume", session)))
        return physical

    r2_case.projection.after_signal.append(delivered)
    module.read_process = replaced
    try:
        code, answer = r2_case.stop(module, capsys, 0)
        assert witnessed and replacements and held.returncode is None
        assert code == 3 and answer["state"] == "stop_failed"
        assert answer["pids"] == [held.pid] and answer["unresolved_pids"] == [held.pid]
        assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    finally:
        assert held.wait(timeout=5) == -signal.SIGTERM


def test_r15_fresh_read_does_not_replace_initial_unknown_group_evidence(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn_group(["claude", "--resume", session])
    host, worker = family["H"], family["M"]
    module, reads, missing = r2_case.module(False), [], []

    def before(pid, count):
        if pid == worker.pid:
            reads.append(count)

    def unavailable(path, physical):
        if str(path) == "/proc/%d/status" % worker.pid and len(reads) == 1:
            missing.append(True)
            # MODELLED incomplete initial UID evidence. Fresh readable atoms cannot replace that instance.
            return b"\n".join(line for line in physical.splitlines() if not line.startswith(b"Uid:"))
        return physical

    r2_case.projection.before_read.append(before)
    r2_case.projection.path_view(module, unavailable)
    code, answer = r2_case.stop(module, capsys, 0)
    assert missing and len(reads) > 1 and worker.poll() is None
    assert code == 3 and answer["state"] == "stop_failed"
    assert answer["pids"] == [host.pid] and answer["unresolved_pids"] == [worker.pid]
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)
    assert host.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("surface", ["stop", "handoff"])
@pytest.mark.parametrize("observation", ["full", "partial"])
def test_r15_real_unreaped_zombie_is_valid_exit_evidence(r2_case, capsys, surface, observation):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    assert r2_case.launch.start(thread=session, cwd=str(r2_case.launch.source))["session"] == session
    held = r2_case.spawn(["codex", "exec", "resume", session])
    r2_case.projection.group_reaping = False
    first = r2_case.module(False)

    def exited(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            wait_until(lambda: r2_kernel_process(pid)["state"].startswith("Z"))

    r2_case.projection.after_signal.append(exited)
    try:
        code, answer = r2_case.stop(first, capsys)
        assert code == 3 and answer["state"] == "stop_failed" and held.returncode is None
        assert answer["unresolved_groups"] == [held.pid]
        assert {e["proof"] for e in answer["absence_evidence"] if e["pid"] == held.pid} == {"matching_birth_zombie"}
        original = r2_kernel_process(held.pid)
        assert original["state"].startswith("Z")
        second = r2_case.module(False)
        if observation == "partial":
            def incomplete(path, raw):
                if str(path) == "/proc/%d/status" % held.pid:
                    raise PermissionError("modelled UID unreadability after actual zombie exit")
                return raw
            r2_case.projection.path_view(second, incomplete)
        if surface == "stop":
            code, answer = r2_case.stop(second, capsys, 0)
            assert code == 3 and answer["state"] == "stop_failed" and answer["unresolved_groups"] == [held.pid]
        else:
            control = handoff_module()
            control.hierarchy_launcher = second
            answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
            assert "stop custody unresolved" in answer["error"]
        current = r2_kernel_process(held.pid)
        assert current["birth"] == original["birth"] and current["state"].startswith("Z")
        assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    finally:
        assert held.wait(timeout=5) == -signal.SIGTERM
    assert r2_case.stop(r2_case.module(False), capsys, 0)[0] == 0
    if surface == "handoff":
        answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 0)
        assert answer["entries"][0]["generation"] == 2


@pytest.mark.parametrize("fault", ["active-orphan", "unreadable-custody", "ambiguous-selector",
                                   "active-host", "late-custody", "late-binding"])
def test_r15_probe_cleanup_preserves_custody_but_removes_auth_and_finishes_roles(r2_case, capsys, fault):
    import builtins
    import contextlib
    import io
    from types import ModuleType, SimpleNamespace
    from tests.integration.test_hierarchy_native_probe import PROBE, Probe

    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    discovery = r2_case.module(False)
    if fault == "active-orphan":
        family = r2_case.spawn(["codex", "exec", "resume", session], tree=True)

        def interrupted(pid, number):
            if pid == family["W"].pid and number == signal.SIGTERM:
                for name in ("H", "M"):
                    slot = next(slot for slot, row in r2_case.custody.entries.items()
                                if row["pid"] == family[name].pid)
                    r2_case.custody.kill_owned(slot)
                assert family["H"].wait(timeout=5) == -signal.SIGKILL
                wait_until(lambda: family["M"].poll() == "CONFIRMED_EXIT")
                raise KeyboardInterrupt("modelled probe loss retaining an actual orphan")

        r2_case.projection.after_signal.append(interrupted)
        try:
            with pytest.raises(KeyboardInterrupt, match="retaining an actual orphan"):
                r2_case.stop(discovery, capsys, 0)
        finally:
            r2_case.projection.after_signal.remove(interrupted)
        capsys.readouterr()
        held = family["W"]
        assert held.poll() is None and not r2_case.launch.records()
    else:
        argv = ["codex", "exec", "resume", *( ["--last"] if fault == "ambiguous-selector" else []), session]
        held = r2_case.spawn(argv, ignore=True)
        if fault == "unreadable-custody":
            r13_seed_empty_journal(discovery, r2_case)
            opening = discovery.os.open

            def denied(path, *args, **kwargs):
                if path == "state.json":
                    raise PermissionError("modelled unreadable endpoint custody")
                return opening(path, *args, **kwargs)

            discovery.os.open = denied
        elif fault == "active-host":
            def interrupted(pid, number):
                if pid == held.pid and number == signal.SIGTERM:
                    raise KeyboardInterrupt("modelled loss with an owned host still live")
            r2_case.projection.after_signal.append(interrupted)
            try:
                with pytest.raises(KeyboardInterrupt, match="owned host still live"):
                    r2_case.stop(discovery, capsys, 0)
            finally:
                r2_case.projection.after_signal.remove(interrupted)
            capsys.readouterr()

    # A second authentic binding/launch record makes continuing cleanup observable through a real TERM.
    endpoint = "pilot/lane/f2"
    started = r2_case.launch.start(thread=other, endpoint=endpoint, cwd=str(r2_case.launch.source),
                                  writable_roots=[str(r2_case.launch.source)])
    assert started["session"] == other
    second = r2_case.spawn(["codex", "exec", "resume", other])
    late = []

    def changed_after_stop():
        if fault == "late-custody":
            # MODELLED concurrent custody publication, after the first role stopped but before deletion.
            path = r13_seed_empty_journal(discovery, r2_case)
            saved = json.loads(path.read_text())
            saved["active"] = True
            path.write_text(json.dumps(saved))
            late.append(path)
        elif fault == "late-binding":
            import contextlib
            import io
            from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, spec_for
            successor = str(uuid.uuid4())
            path = r2_case.launch.tmp / "r16-handoff.json"
            path.write_text(json.dumps(spec_for(r2_case.launch, session=successor)))
            handing = handoff_module()
            handing.hierarchy_launcher = r2_case.module(False)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = handing.main(["--spec", str(path)])
            assert code == 0 and json.loads(output.getvalue())["entries"][0]["generation"] == 2
            late.append(r2_case.spawn(["codex", "exec", "resume", successor], ignore=True))

    # A real, test-owned exited PID supplies the stale run-lock prerequisite without inventing liveness.
    stale = r2_case.spawn(None)
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert stale.wait(timeout=5) == 0

    folder = r2_case.launch.tmp / "r15-probe"
    folder.mkdir()
    probe = Probe(folder)
    try:
        plan = probe.plan([{"role": "implementer"}, {"role": "reviewer", "reader_shell": True}])
        # Explicit test-owned planned bases/endpoints; no production callback or argv/identity rewrite.
        for planned, target in zip(plan["roles"], (REVIEW, endpoint)):
            planned.update(base=str(r2_case.launch.base), endpoint=target)
        (probe.root / "probe.json").write_text(json.dumps(plan))
        auth = probe.codex_home / "auth.json"
        auth.write_text("test-owned fake credential")
        (probe.root / ".run.lock").write_text(json.dumps({"pid": stale.pid}))
        importing = builtins.__import__

        def isolated(name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and name == "hierarchy_launcher":
                return discovery
            if level == 0 and name == "pwd":
                return SimpleNamespace(getpwuid=lambda _uid: SimpleNamespace(pw_dir=str(probe.passwd_home)))
            return importing(name, globals, locals, fromlist, level)

        control = ModuleType("_r15_probe_cleanup")
        control.__dict__.update(__file__=str(PROBE), __package__="",
                                __builtins__={**vars(builtins), "__import__": isolated})
        exec(compile(PROBE.read_bytes(), str(PROBE), "exec"), control.__dict__)
        control.os = R2Facade(os, environ=probe.env())
        runner = control.Runner
        calls = []

        class ScopedRunner(runner):
            def launcher(self, base, *words):
                assert words[0] == "stop" and base == str(r2_case.launch.base)
                calls.append(words)
                module = discovery if words[words.index("--endpoint") + 1] == REVIEW else r2_case.module(False)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = module.main(["--base", str(base), *words])
                if words[words.index("--endpoint") + 1] == REVIEW and code == 0:
                    changed_after_stop()  # The public outgoing stop, including custody clear, has completed.
                return code, json.loads(output.getvalue())

        control.Runner = ScopedRunner
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)
        if fault == "active-host":
            assert code == 0 and "unresolved_custody" not in answer["cleanup"]
            assert answer["cleanup"]["worktree_removed"] and not Path(plan["worktree"]).exists()
        else:
            assert code == 3 and answer["cleanup"]["unresolved_custody"]
            assert Path(plan["worktree"]).is_dir() and not answer["cleanup"]["worktree_removed"]
        assert not auth.exists() and answer["cleanup"]["auth_removed"]
        assert (probe.root / "report.json").is_file() and (probe.root / "cleanup.json").is_file()
        assert not (probe.root / ".run.lock").exists()
        assert any(words[words.index("--endpoint") + 1] == endpoint for words in calls)
        assert second.wait(timeout=5) == -signal.SIGTERM
        assert fault != "ambiguous-selector" or held.poll() is None
        if fault == "active-host":
            assert held.wait(timeout=5) == -signal.SIGKILL
            stopped = r2_case.launch.records()[-1]
            assert stopped["action"] == "stop" and stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
            path = r2_case.launch.base / "launches" / discovery.quoted(REVIEW) / ".stop-custody" / "state.json"
            assert not json.loads(path.read_text())["active"]
        if fault in ("late-custody", "late-binding"):
            assert late
        if fault == "late-binding":
            assert late[0].poll() is None and all(pid != late[0].pid for pid, _ in r2_case.projection.events)
    finally:
        probe.close()


def test_public_handoff_without_a_host_sees_live_claude(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    code, record = r2_case.stop(r2_case.module(), capsys, grace=0)
    assert code == 0 and record["state"] == "not_running"
    held = r2_case.spawn(["claude", "--resume", session])
    control = handoff_module()
    control.hierarchy_launcher = r2_case.module()
    spec = spec_for(r2_case.launch)
    before = mailbox_files(r2_case.launch.base)
    answer = run_main(control, r2_case.launch, spec, capsys, 2)
    assert "live process remains" in answer["error"] and str(held.pid) in answer["error"]
    assert mailbox_files(r2_case.launch.base) == before and held.poll() is None


def r16_cleanup_control(probe, discovery):
    """Per-loaded trusted probe with the existing explicit MODELLED_OS_BOUNDARY signal facade."""
    import builtins
    from types import ModuleType, SimpleNamespace
    from tests.integration.test_hierarchy_native_probe import PROBE

    importing = builtins.__import__

    def isolated(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == "hierarchy_launcher":
            return discovery
        if level == 0 and name == "pwd":
            return SimpleNamespace(getpwuid=lambda _uid: SimpleNamespace(pw_dir=str(probe.passwd_home)))
        return importing(name, globals, locals, fromlist, level)

    control = ModuleType("_r16_cleanup")
    control.__dict__.update(__file__=str(PROBE), __package__="",
                            __builtins__={**vars(builtins), "__import__": isolated})
    exec(compile(PROBE.read_bytes(), str(PROBE), "exec"), control.__dict__)
    control.os = R2Facade(os, environ=probe.env())
    return control


@pytest.mark.parametrize("fault", ["launch-json", "launch-list", "provision", "busy"])
def test_r17_probe_cleanup_checks_all_roles_despite_unreadable_role(r2_case, capsys, fault):
    from contextlib import contextmanager
    from tests.integration.test_hierarchy_native_probe import Probe

    module = r2_case.module(False)
    folder = r2_case.launch.tmp / "r17-probe"
    folder.mkdir()
    probe = Probe(folder)
    try:
        plan = probe.plan([{"role": "implementer"}, {"role": "reviewer", "reader_shell": True}])
        first, second = plan["roles"]
        auth = probe.codex_home / "auth.json"
        auth.write_text("test-owned disposable credential")
        if fault == "launch-json":
            logs = Path(first["base"]) / "launches" / module.quoted(first["endpoint"])
            logs.mkdir(parents=True)
            (logs / "invalid.json").write_text("{")
        if fault == "provision":
            (Path(first["base"]) / "provision.json").write_text("{}")
        # A real binding on role 2 must still be read in the final census, even if role 1's lock is busy.
        session = str(uuid.uuid4())
        module.add_role({"base": second["base"], "endpoint": second["endpoint"], "host": "codex-cli",
                         "session": session, "cwd": plan["worktree"]})
        control, censuses = r16_cleanup_control(probe, module), []
        if fault == "launch-list":
            logs = Path(first["base"]) / "launches" / module.quoted(first["endpoint"])
            logs.mkdir(parents=True)
            listing = module.os.scandir
            def unreadable(directory):
                if isinstance(directory, int) and os.path.samefile('/proc/self/fd/%d' % directory, logs):
                    raise PermissionError("modelled launch directory unreadable")
                return listing(directory)
            module.os.scandir = unreadable
        census, locking = module.session_processes, control.cleanup_locks

        def enumerated(bound, *args, **kwargs):
            censuses.append(bound)
            return census(bound, *args, **kwargs)
        module.session_processes = enumerated

        @contextmanager
        def busy(roles):
            if any(role["base"] == first["base"] for role in roles):
                raise ValueError("modelled busy endpoint")
            with locking(roles) as scopes:
                yield scopes
        if fault == "busy":
            control.cleanup_locks = busy
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)
        assert code == 3 and answer["cleanup"]["unresolved_custody"]
        assert Path(plan["worktree"]).is_dir() and not answer["cleanup"]["worktree_removed"]
        assert not auth.exists() and censuses.count(session) >= 3
    finally:
        probe.close()


@pytest.mark.parametrize("fault", ["git-list", "report-write"])
def test_r16_cleanup_failure_still_removes_auth_and_releases_run_lock(r2_case, capsys, fault):
    import errno
    from tests.integration.test_hierarchy_native_probe import Probe

    discovery = r2_case.module(False)
    stale = r2_case.spawn()
    r2_case.configs[-1].with_suffix(".exit").touch()
    assert stale.wait(timeout=5) == 0
    folder = r2_case.launch.tmp / "failure-probe"
    folder.mkdir()
    probe = Probe(folder)
    try:
        plan = probe.plan([{"role": "implementer"}])
        auth, lock = probe.codex_home / "auth.json", probe.root / ".run.lock"
        auth.write_text("test-owned fake credential")
        lock.write_text(json.dumps({"pid": stale.pid}))
        control, faults = r16_cleanup_control(probe, discovery), []
        listing, writing = control.git, control.write_private

        def failed_list(*args, **kwargs):
            faults.append(True)
            raise FileNotFoundError(errno.ENOENT, "modelled git census unavailable")

        def failed_report(path, value):
            if path.name == "report.json":
                faults.append(True)
                raise OSError(errno.EIO, "modelled report write failure")
            return writing(path, value)

        if fault == "git-list":
            control.git = failed_list
        else:
            control.write_private = failed_report
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)
        assert faults and not auth.exists() and not lock.exists()
        if fault == "git-list":
            assert code == 3 and "modelled git census unavailable" in json.dumps(answer["cleanup"]["unresolved_custody"])
            assert Path(plan["worktree"]).is_dir() and (probe.root / "report.json").is_file()
        else:
            assert code == 2 and answer["error"] == "[Errno 5] modelled report write failure"
    finally:
        probe.close()


@pytest.mark.parametrize("bound", [False, True], ids=["unstarted", "bound"])
def test_r16_cleanup_holds_writer_and_endpoint_fences_through_deletion(r2_case, capsys, bound):
    import contextlib
    import io
    from tests.integration.test_hierarchy_native_probe import Probe

    discovery = r2_case.module(False)
    folder = r2_case.launch.tmp / "fenced-probe"
    folder.mkdir()
    probe = Probe(folder)
    try:
        plan = probe.plan([{"role": "implementer"}])
        role = plan["roles"][0]
        if bound:
            discovery.add_role({"base": role["base"], "endpoint": role["endpoint"], "host": "codex-cli",
                                "session": str(uuid.uuid4()), "cwd": plan["worktree"]})
        control, observed = r16_cleanup_control(probe, discovery), []
        running = control.subprocess.run

        def deleting(argv, **kwargs):
            if argv[:1] == ["git"] and "remove" in argv and "--force" in argv:
                launch = discovery.Launches(role["base"])
                with pytest.raises(ValueError, match="mailbox writer is busy"):
                    with control.writer_lock(launch.mailbox.root):
                        pytest.fail("cleanup left the writer fence open")
                if bound:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = discovery.main(["--base", role["base"], "stop", "--endpoint", role["endpoint"]])
                    assert code == 2 and "busy" in json.loads(output.getvalue())["error"]
                observed.append(True)
            return running(argv, **kwargs)

        control.subprocess = R2Facade(control.subprocess, run=deleting)
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)
        assert observed and code == 0 and answer["cleanup"]["worktree_removed"]
        assert not Path(plan["worktree"]).exists() and not (probe.root / ".run.lock").exists()
        assert (probe.root / "report.json").is_file()
    finally:
        probe.close()


@pytest.mark.parametrize("fault", ["unreadable", "unproven"])
def test_public_probe_cleanup_holds_unresolved_census(r2_case, capsys, fault):
    import builtins
    from types import ModuleType, SimpleNamespace
    from tests.integration.test_hierarchy_native_probe import PROBE, Probe

    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    held = r2_case.spawn(["codex", "exec", "resume", session], ignore=True)
    launcher = r2_case.module()
    if fault == "unreadable":
        def deny(path, raw):
            if str(path) == "/proc/%d/status" % held.pid:
                raise PermissionError("modelled unreadable cleanup candidate")
            return raw
        r2_case.projection.path_view(launcher, deny)
    else:
        snapshot = launcher.read_process(held.pid).snapshot
        launcher.process_census = lambda _session: launcher.ProcessCensus([snapshot], "unproven")
    folder = r2_case.launch.tmp / "cleanup-probe"
    folder.mkdir()
    probe = Probe(folder)
    try:
        plan = probe.plan([{"role": "implementer"}])
        planned = plan["roles"][0]
        logs = Path(planned["base"]) / "launches" / planned["endpoint"].replace("/", "%2F")
        logs.mkdir(parents=True)
        (logs / "record.json").write_text(json.dumps({"session": session}))
        auth = probe.codex_home / "auth.json"
        auth.write_text("test-owned fake login")
        importing = builtins.__import__

        def isolated(name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and name == "hierarchy_launcher":
                return launcher
            if level == 0 and name == "pwd":
                return SimpleNamespace(getpwuid=lambda _uid: SimpleNamespace(pw_dir=str(probe.passwd_home)))
            return importing(name, globals, locals, fromlist, level)

        control = ModuleType("_cleanup_under_test")
        control.__dict__.update(__file__=str(PROBE), __package__="",
                                __builtins__={**vars(builtins), "__import__": isolated})
        exec(compile(PROBE.read_bytes(), str(PROBE), "exec"), control.__dict__)
        control.os = R2Facade(os, environ=probe.env())
        code = control.main(["cleanup", "--probe-root", str(probe.root)])
        answer = json.loads(capsys.readouterr().out)
        assert code == 3 and "process census unresolved" in json.dumps(answer["cleanup"]["unresolved_custody"])
        assert held.poll() is None and not auth.exists() and Path(plan["worktree"]).is_dir()
    finally:
        probe.close()


def test_second_stop_recovers_an_unreadable_orphan_from_the_first_stop(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    leader, worker = family["H"], family["W"]
    first = r2_case.module(pidfds=False)
    term = []

    def after_signal(pid, number):
        if number == signal.SIGTERM:
            term.append(pid)
            if pid == leader.pid:
                first.os.kill(pid, signal.SIGKILL)
                assert leader.wait(timeout=5) == -signal.SIGKILL

    def denied(path, raw):
        if worker.pid in term and str(path) == "/proc/%d/cmdline" % worker.pid:
            raise PermissionError("modelled unreadable orphan")
        return raw

    r2_case.projection.after_signal.append(after_signal)
    r2_case.projection.path_view(first, denied)
    code, stopped = r2_case.stop(first, capsys, grace=0)
    assert code == 3 and stopped["state"] == "stop_failed" and worker.poll() is None
    assert worker.pid in stopped["pids"] and worker.pid in stopped["unresolved_pids"]
    second = r2_case.module(pidfds=False)  # New loaded launcher: only durable evidence can supply the orphan.
    before = list(r2_case.projection.events)
    code, recovered = r2_case.stop(second, capsys, grace=0)
    assert code == 3 and recovered["state"] == "stop_failed" and worker.poll() is None
    assert worker.pid in recovered["pids"] and worker.pid not in recovered.get("unowned_pids", [])
    assert worker.pid in recovered["unresolved_pids"] and r2_case.projection.events == before
    journal = second.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert json.loads(journal.read_text())["active"]


def r7_pending_attempt(case, capsys):
    """MODELLED interruption after one real TERM; READY/physical custody remains independent."""
    session = str(uuid.uuid4())
    case.bind("claude-code", session)
    held = case.spawn(["claude", "--resume", session], ignore=True)
    module = case.module(pidfds=False)
    census = module.process_census

    def declared_cohort(session):
        # MODELLED enumeration for this one-actor interruption fixture. A concurrent xdist worker can
        # exec an unrelated process with a transient empty cmdline; that is legitimately unknown in a
        # system-wide census (covered by r18_empty_discovery), not part of this declared test cohort.
        rows = census(session)
        return module.ProcessCensus([row for row in rows if row.pid == held.pid], rows.argv_boundaries,
                                    {pid: row for pid, row in rows.unavailable.items() if pid == held.pid})
    module.process_census = declared_cohort

    def interrupted(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            raise KeyboardInterrupt("modelled launcher loss after real TERM")

    case.projection.after_signal.append(interrupted)
    try:
        with pytest.raises(KeyboardInterrupt, match="modelled launcher loss after real TERM"):
            case.stop(module, capsys, grace=0)
    finally:
        case.projection.after_signal.remove(interrupted)
    capsys.readouterr()
    path = module.Launches(str(case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    saved = json.loads(path.read_text())
    assert saved["active"] and saved["entries"][0]["attempted"]
    assert saved["entries"][0]["snapshot"]["start_time"] == r2_kernel_process(held.pid)["birth"]
    assert held.poll() is None and case.projection.events == [(held.pid, signal.SIGTERM)]
    return held, path, saved


def r13_seed_empty_journal(module, case):
    """Negative-only journal fixture. Empty public stops deliberately no longer create this file."""
    launches = module.Launches(str(case.launch.base))
    known = {key: case.launch.binding()[key] for key in ("host", "session", "generation")}
    state = dict(candidates={}, initial_unavailable={}, blocked=set(), identity_lost=set(), resolved={})
    with module.StopCustody(launches, REVIEW, known) as custody:
        custody.save(state, set(), active=False)
    return custody.path


@pytest.mark.parametrize("site", ["restore", "poll"])
@pytest.mark.parametrize("drift", ["uid", "cmdline", "birth"])
def test_r14_latch_is_durable_before_next_observation(r2_case, capsys, site, drift):
    if site == "restore":
        held, path, _ = r7_pending_attempt(r2_case, capsys)
        module = r2_case.module(False)
    else:
        session = str(uuid.uuid4())
        r2_case.bind("claude-code", session)
        held = r2_case.spawn(["claude", "--resume", session], ignore=True)
        module = r2_case.module(False)
        path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    changed = []

    def modelled(pid, count, row):
        # MODELLED drift is post-TERM in the poll case, independent of how many discovery reads precede it.
        if pid == held.pid and (site == "restore" or (pid, signal.SIGTERM) in r2_case.projection.events):
            changed.append(True)
            return row._replace(**({"uid": row.uid + 1} if drift == "uid" else
                                  {"cmdline": row.cmdline + b"changed\0"} if drift == "cmdline" else
                                  {"start_time": str(int(row.start_time) + 1)}))
        return row

    def crash(pid, count):
        if pid == held.pid and changed:
            entry = next(row for row in json.loads(path.read_text())["entries"] if row["pid"] == pid)
            if drift == "cmdline":
                assert not entry["blocked"] and not entry["identity_lost"]
            else:
                assert entry["blocked"], "new blocked latch must precede the next process observation"
                assert entry["identity_lost"]
            raise R10Interrupted("modelled crash after durable %s latch" % site)

    r2_case.projection.after_present.append(modelled)
    r2_case.projection.before_read.append(crash)
    with pytest.raises(R10Interrupted, match="modelled crash after durable"):
        r2_case.stop(module, capsys, 1)
    capsys.readouterr()
    r2_case.projection.after_present.remove(modelled)
    r2_case.projection.before_read.remove(crash)
    assert held.poll() is None
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    if drift == "cmdline":
        assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGKILL
        assert (held.pid, signal.SIGKILL) in r2_case.projection.events
        assert json.loads(path.read_text())["active"] is False
        return
    assert code == 3 and answer["pids"] == [held.pid]
    assert answer["unresolved_pids"] == [held.pid] and r2_case.projection.events == before
    r2_case.configs[0].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    if drift in ("birth", "uid"):
        assert code == 3 and answer["unresolved_pids"] == [held.pid]
        assert "manual reconciliation" in answer["error"]
    assert r2_case.projection.events == before


@pytest.mark.parametrize("site", ["poll", "restore"])
def test_r14_empty_recheck_is_unavailable_until_a_qualified_exit(r2_case, capsys, site):
    if site == "restore":
        held, _, _ = r7_pending_attempt(r2_case, capsys)
    else:
        session = str(uuid.uuid4())
        r2_case.bind("claude-code", session)
        held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module, changed, exited = r2_case.module(False), [], []
    threshold = r2_case.projection.read_counts.get(held.pid, 0) + (1 if site == "restore" else 3)

    def empty(pid, count, row):
        if pid == held.pid and ((site == "restore" and count == threshold) or
                               (site == "poll" and not changed and
                                (pid, signal.SIGTERM) in r2_case.projection.events)):
            assert held.poll() is None
            changed.append(True)
            return row._replace(cmdline=b"", argv=())  # MODELLED missing data, no replacement identity.
        return row

    def exit_before_next_read(pid, count):
        if pid == held.pid and changed and not exited:
            r2_case.configs[0].with_suffix(".exit").touch()
            assert held.wait(timeout=5) == 0
            exited.append(True)  # Actual original exit; only now may qualified numeric absence resolve it.

    r2_case.projection.after_present.append(empty)
    r2_case.projection.before_read.append(exit_before_next_read)
    code, answer = r2_case.stop(module, capsys)
    assert changed and exited and code == 0 and answer["state"] == "stopped"
    assert answer["pids"] == [held.pid] and r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    assert answer["absence_evidence"] == [{"pid": held.pid, "proof": "qualified_namespace_ESRCH"}]


def test_r14_blocked_exit_proof_survives_outcome_crash(r2_case, capsys):
    import stat

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    r2_case.projection.group_reaping = False  # This control needs the original zombie until its explicit wait.
    module = r2_case.module(False)
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    changed, exited, events = [], [], []

    def drift(pid, count, row):
        if pid == held.pid and not changed and (pid, signal.SIGTERM) in r2_case.projection.events:
            changed.append(True)
            return row._replace(uid=row.uid + 1)  # MODELLED identity drift; never positive authority.
        return row

    syncing = module.os.fsync

    def sync(fd):
        result = syncing(fd)
        if (changed and not exited and stat.S_ISDIR(os.fstat(fd).st_mode) and
                Path(os.readlink("/proc/self/fd/%d" % fd)) == journal.parent):
            assert json.loads(journal.read_text())["entries"][0]["blocked"]
            r2_case.configs[0].with_suffix(".exit").touch()
            wait_until(lambda: r2_kernel_process(held.pid)["state"].startswith("Z"))
            exited.append(True)  # Physical matching zombie, intentionally not reaped until after the crash.
        return result

    module.os.fsync = sync
    r2_case.projection.after_present.append(drift)
    r10_observe_fsync(module, journal, events, ("outcome", "directory"))
    with pytest.raises(R10Interrupted, match="modelled interruption after outcome/directory"):
        r2_case.stop(module, capsys)
    capsys.readouterr()
    assert changed and exited and held.wait(timeout=5) == 0
    assert json.loads(journal.read_text())["entries"][0]["resolved"]
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 0 and answer["state"] == "stopped" and answer["pids"] == [held.pid]
    assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]


@pytest.mark.parametrize("boot,physical,expected", [
    ("forged", "live", 3), ("current", "live", 3),
    ("forged", "absent", 0), ("current", "reused", 3), ("forged", "reused", 3),
    ("current", "zombie", 0), ("forged", "zombie", 0),
])
def test_r14_resolved_claims_require_physical_identity(r2_case, capsys, boot, physical, expected):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    saved["active"] = False
    saved.pop("groups", None)  # Historical per-PID record, independent from the new active group journal.
    saved["entries"][0]["resolved"] = "matching_birth_zombie"
    if boot == "forged":
        saved["boot"] = "modelled forged boot"
    path.write_text(json.dumps(saved))
    if physical == "absent":
        r2_case.configs[0].with_suffix(".exit").touch()
        assert held.wait(timeout=5) == 0

    def modelled(pid, count, row):
        if pid == held.pid and physical == "reused":
            # MODELLED unrelated replacement; the fixture still independently owns the real live child.
            return row._replace(start_time=str(int(row.start_time) + 1), argv=("diagnostic",), cmdline=b"diagnostic\0")
        if pid == held.pid and physical == "zombie":
            return row._replace(state="Z")
        return row

    before = list(r2_case.projection.events)
    r2_case.projection.after_present.append(modelled)
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == expected
    assert r2_case.projection.events == before
    if expected == 3:
        assert "stop custody" in answer["error"] and "manual reconciliation" in answer["error"]
    else:
        assert answer["state"] == "not_running"
    if physical != "absent":
        assert held.poll() is None


def test_r14_grammar_hold_guidance_names_manual_process_and_followup(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    held = r2_case.spawn(["claude", "--unknown-r14", "--resume", session], ignore=True)
    control = handoff_module()
    control.hierarchy_launcher = r2_case.module(False)
    spec = spec_for(r2_case.launch)
    refused = run_main(control, r2_case.launch, spec, capsys, 2)
    assert str(held.pid) in refused["error"] and "stop this process manually" in refused["error"]
    assert "repair the process census" not in refused["error"]
    assert held.poll() is None and r2_case.projection.events == []
    r2_case.configs[0].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    control.hierarchy_launcher = r2_case.module(False)
    assert run_main(control, r2_case.launch, spec, capsys, 0)["entries"][0]["generation"] == 2


def test_r14_fresh_census_clears_obsolete_lossy_coverage(r2_case, capsys):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    saved["coverage"] = "argv_boundaries_unavailable"
    path.write_text(json.dumps(saved))
    r2_case.configs[0].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 0 and answer["state"] == "stopped"
    assert "reason" not in answer and not json.loads(path.read_text())["active"]


def test_r14_binding_mismatch_names_archive_and_followup_changes_outcome(r2_case, capsys):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    saved["binding"]["generation"] += 1
    path.write_text(json.dumps(saved))
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 2 and "belongs to another binding" in answer["error"]
    assert "manual reconciliation" in answer["error"] and "mv -i --" in answer["error"]
    assert r2_case.projection.events == before and held.poll() is None
    r2_case.configs[0].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    path.rename(path.with_name("owner-reconciled.json"))
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 0 and answer["state"] == "not_running"


def test_r14_escalation_recensuses_new_owned_root(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module, new = r2_case.module(False), []

    def started(pid, number):
        if pid == held.pid and number == signal.SIGTERM and not new:
            new.append(r2_case.spawn(["claude", "--resume", session], ignore=True))

    r2_case.projection.after_signal.append(started)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and new
    assert answer["pids"] == sorted([held.pid, new[0].pid])
    assert held.wait(timeout=5) == new[0].wait(timeout=5) == -signal.SIGKILL
    assert (new[0].pid, signal.SIGKILL) in r2_case.projection.events


@pytest.mark.parametrize("field,value", [("pid", 2 ** 63), ("pgid", 2 ** 63), ("ppid", 2 ** 63),
                                       ("uid", 2 ** 63), ("euid", 2 ** 63),
                                       ("start_time", str(2 ** 64)), ("generation", 2 ** 63)])
def test_r14_journal_ranges_refuse_before_process_observation(r2_case, capsys, field, value):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    if field == "generation":
        saved["binding"][field] = value
    else:
        saved["entries"][0]["snapshot"][field] = value
        if field == "pid":
            saved["entries"][0]["pid"] = value
    path.write_text(json.dumps(saved))
    module, opened = r2_case.module(False), []
    opening, reading = module.os.open, module.read_process

    def open_file(source, *args, **kwargs):
        if str(source) == "state.json":
            opened.append(True)
        return opening(source, *args, **kwargs)

    def observe(pid, *args):
        if opened:
            raise AssertionError("invalid journal numeric field reached the process-observation boundary")
        return reading(pid, *args)

    module.os.open, module.read_process = open_file, observe
    before = list(r2_case.projection.events)
    code, refused = r2_case.stop(module, capsys, 0)
    assert opened and code == 2 and "manual reconciliation" in refused["error"]
    assert "invalid stop custody " + field in refused["error"]
    assert held.poll() is None and r2_case.projection.events == before


def test_r14_legacy_raw_journal_refuses_with_reconciliation(r2_case, capsys):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    module = r2_case.module(False)
    physical = module.read_process(held.pid).snapshot._asdict()
    physical["cmdline"] = physical["cmdline"].hex()
    saved["schema"] = "aegis.hierarchy-stop-custody/v1"
    saved["entries"][0]["snapshot"] = physical
    path.write_text(json.dumps(saved))
    before = list(r2_case.projection.events)
    code, refused = r2_case.stop(module, capsys, 0)
    assert code == 2 and "manual reconciliation" in refused["error"] and "mv -i --" in refused["error"]
    assert held.poll() is None and r2_case.projection.events == before
    r2_case.configs[0].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    path.rename(path.with_name("reconciled-v1.json"))
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 0 and answer["state"] == "not_running"


def test_r14_pending_journal_never_persists_prompt_or_raw_argv(r2_case, capsys):
    import hashlib

    session, secret = str(uuid.uuid4()), "PRIVATE-PROMPT-" + uuid.uuid4().hex
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session, "-p", secret], ignore=True)
    module = r2_case.module(False)

    def interrupt(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            raise KeyboardInterrupt("modelled loss after real TERM with private prompt")

    r2_case.projection.after_signal.append(interrupt)
    try:
        with pytest.raises(KeyboardInterrupt, match="private prompt"):
            r2_case.stop(module, capsys, 0)
    finally:
        r2_case.projection.after_signal.remove(interrupt)
    capsys.readouterr()
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    raw = path.read_bytes()
    data = json.loads(raw)
    assert secret.encode() not in raw and secret.encode().hex().encode() not in raw
    row = data["entries"][0]["snapshot"]
    assert "argv" not in row and "cmdline" not in row
    assert row["cmdline_sha256"] == hashlib.sha256(r2_kernel_process(held.pid)["raw"]).hexdigest()
    assert held.poll() is None and r2_case.projection.events == [(held.pid, signal.SIGTERM)]


def test_r14_large_physical_argv_can_be_stopped_without_a_size_dead_end(r2_case, children, capsys):
    session = str(uuid.uuid4())
    huge = "PRIVATE-LARGE-" + uuid.uuid4().hex + "x" * 90000
    r2_case.bind("claude-code", session)
    logical = ["claude", "--resume", session, "-p", huge]
    held = children(str(r2_case.launch.tmp / "claude"), "--resume", session, "-p", huge, logical_argv=logical)
    assert len(r2_kernel_process(held.pid)["raw"]) > 90000
    module = r2_case.module(False)
    code, stopped = r2_case.stop(module, capsys)
    assert code == 0 and stopped["pids"] == [held.pid] and held.wait(timeout=5) == -signal.SIGTERM
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    raw = path.read_bytes()
    assert len(raw) < 4096 and huge.encode() not in raw and huge.encode().hex().encode() not in raw


def test_r14_prior_inactive_noop_has_zero_custody_writes(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys)[0] == 0 and held.wait(timeout=5) == -signal.SIGTERM
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    before, info, writes = path.read_bytes(), path.stat(), []
    fresh = r2_case.module(False)
    replacing = fresh.os.replace

    def replace(source, target, *args, **kwargs):
        if str(target) == "state.json" or Path(target) == path:
            writes.append(True)
        return replacing(source, target, *args, **kwargs)

    fresh.os.replace = replace
    code, stopped = r2_case.stop(fresh, capsys, 0)
    assert code == 0 and stopped["state"] == "not_running" and not writes
    assert path.read_bytes() == before and path.stat().st_ino == info.st_ino
    assert path.stat().st_mtime_ns == info.st_mtime_ns


def test_r14_commit_never_writes_through_a_replaced_directory(r2_case, capsys, tmp_path_factory):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module, swapped = r2_case.module(False), []
    folder = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody"
    outside = tmp_path_factory.mktemp("r14-untrusted-" + uuid.uuid4().hex)
    opening = module.os.open

    def swap(source, flags, *args, **kwargs):
        if flags & os.O_CREAT and str(source).endswith(".tmp") and not swapped:
            folder.rename(folder.with_name("original-custody"))
            folder.symlink_to(outside, target_is_directory=True)
            swapped.append(True)  # Actual filesystem boundary race; never process identity authority.
        return opening(source, flags, *args, **kwargs)

    module.os.open = swap
    code, refused = r2_case.stop(module, capsys, 0)
    assert swapped and code == 2 and "error" in refused
    assert list(outside.iterdir()) == [], "a pinned journal commit must never write into the replacement directory"
    assert held.poll() is None and r2_case.projection.events == []


@pytest.mark.parametrize("field", ["schema", "host", "session", "boot", "state", "start_time", "argv", "cmdline",
                                 "coverage", "resolved", "partial-state", "partial-start_time", "partial-argv",
                                 "partial-cmdline"])
def test_r13_raw_non_ascii_journal_refuses_before_effect(r2_case, capsys, field):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    # All string-bearing schema locations are attacker inputs, including negative evidence.
    if field.startswith("partial-"):
        key = field[len("partial-"):]
        saved["entries"][0]["partial"][key] = ["é"] if key == "argv" else "é"
    elif field in ("host", "session"):
        saved["binding"][field] += "é"
    elif field in ("state", "start_time", "cmdline"):
        saved["entries"][0]["snapshot"][field] = saved["entries"][0]["snapshot"].get(field, "") + "é"
    elif field == "argv":
        saved["entries"][0]["snapshot"]["argv"] = ["é"]
    elif field == "resolved":
        saved["entries"][0][field] = "é"
    else:
        saved[field] = "é"
    path.write_text(json.dumps(saved, ensure_ascii=False))
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 2 and "error" in answer
    assert r2_case.projection.events == before and held.poll() is None


@pytest.mark.parametrize("field,value", [("state", "?"), ("state", "Running"), ("start_time", "1x"),
                                       ("start_time", "１２")])
def test_r13_invalid_physical_scalar_refuses(r2_case, capsys, field, value):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    saved["entries"][0]["snapshot"][field] = value
    path.write_text(json.dumps(saved))
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(r2_case.module(False), capsys, 0)
    assert code == 2 and "invalid stop custody " + field in answer["error"]
    assert r2_case.projection.events == before and held.poll() is None


@pytest.mark.parametrize("attack", ["mode", "owner", "hardlink", "symlink"])
def test_r13_opened_journal_descriptor_is_validated(r2_case, capsys, attack):
    import stat

    held, path, saved = r7_pending_attempt(r2_case, capsys)
    module = r2_case.module(False)
    opening, reading, fstat = module.os.open, module.read_json, module.os.fstat
    swapped, target = [], path.with_name("attacker.json")
    target.write_text(json.dumps(saved))
    target.chmod(0o600 if attack != "mode" else 0o644)
    if attack == "hardlink":
        os.link(target, target.with_suffix(".link"))

    def swap():
        if not swapped:
            path.unlink()
            if attack == "symlink":
                path.symlink_to(target)
            else:
                os.replace(target, path)
            swapped.append(True)

    def opened(source, flags, *args, **kwargs):
        if str(source) == "state.json" or Path(source) == path:
            swap()
        return opening(source, flags, *args, **kwargs)

    def read(source):
        if Path(source) == path:
            swap()  # Old pathname reader's equivalent OS-open boundary.
        return reading(source)

    def info(fd):
        value = fstat(fd)
        if attack == "owner" and stat.S_ISREG(value.st_mode) and Path(os.readlink("/proc/self/fd/%d" % fd)) == path:
            parts = list(value)
            parts[4] = os.geteuid() + 1  # MODELLED descriptor owner; no chown authority or positive evidence.
            return os.stat_result(parts)
        return value

    module.os.open, module.read_json, module.os.fstat = opened, read, info
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(module, capsys, 0)
    assert swapped and code == 2 and "error" in answer
    assert r2_case.projection.events == before and held.poll() is None


@pytest.mark.parametrize("attack", ["mode", "owner", "symlink", "mode-at-state-open"])
def test_r13_custody_directory_is_pinned_and_private(r2_case, capsys, attack):
    import stat

    held, path, saved = r7_pending_attempt(r2_case, capsys)
    module = r2_case.module(False)
    opening, fstat = module.os.open, module.os.fstat
    replaced = []

    def open_directory(source, flags, *args, **kwargs):
        if attack == "mode-at-state-open" and str(source) == "state.json" and not replaced:
            path.parent.chmod(0o755)
            replaced.append(True)
        if (str(source) == ".stop-custody" or Path(source) == path.parent / "lock") and not replaced and attack != "mode-at-state-open":
            if attack == "symlink":
                backup = path.parent.with_name("original-custody")
                path.parent.rename(backup)
                path.parent.symlink_to(backup, target_is_directory=True)
            elif attack == "mode":
                path.parent.chmod(0o755)
            replaced.append(True)
        return opening(source, flags, *args, **kwargs)

    def info(fd):
        value = fstat(fd)
        if (attack == "owner" and stat.S_ISDIR(value.st_mode) and
                Path(os.readlink("/proc/self/fd/%d" % fd)) == path.parent):
            parts = list(value)
            parts[4] = os.geteuid() + 1  # MODELLED directory owner at the real descriptor boundary.
            return os.stat_result(parts)
        return value

    module.os.open, module.os.fstat = open_directory, info
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(module, capsys, 0)
    assert replaced and code == 2 and "error" in answer
    assert r2_case.projection.events == before and held.poll() is None


@pytest.mark.parametrize("attack", ["file-mode", "file-owner", "file-hardlink", "directory-mode", "directory-owner",
                                  "directory-mode-at-open"])
@pytest.mark.parametrize("present", [True, False], ids=["journal", "empty-directory"])
def test_r13_readonly_consumer_validates_private_custody(r2_case, capsys, attack, present):
    import stat
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    path = r13_seed_empty_journal(module, r2_case)
    if not present:
        path.unlink()
    if attack == "file-mode" and present:
        path.chmod(0o644)
    elif attack == "file-hardlink" and present:
        os.link(path, r2_case.launch.tmp / "outside-custody-link")
    elif attack == "directory-mode":
        path.parent.chmod(0o755)
    fstat = module.os.fstat

    def info(fd):
        value = fstat(fd)
        observed = Path(os.readlink("/proc/self/fd/%d" % fd))
        if ((attack == "file-owner" and stat.S_ISREG(value.st_mode) and observed == path) or
                (attack == "directory-owner" and stat.S_ISDIR(value.st_mode) and observed == path.parent)):
            parts = list(value)
            parts[4] = os.geteuid() + 1  # MODELLED negative filesystem owner, never process UID or authority.
            return os.stat_result(parts)
        return value

    module.os.fstat = info
    opening, stating = module.os.open, module.os.stat

    def change_directory(source, *args, **kwargs):
        if attack == "directory-mode-at-open" and str(source) == "state.json":
            path.parent.chmod(0o755)
        return opening(source, *args, **kwargs)

    module.os.open = change_directory

    def change_at_lookup(source, *args, **kwargs):
        if attack == "directory-mode-at-open" and str(source) == "state.json":
            path.parent.chmod(0o755)
        return stating(source, *args, **kwargs)

    module.os.stat = change_at_lookup
    control = handoff_module()
    control.hierarchy_launcher = module
    # No file means file-only attacks have no input to validate. The directory itself still must be private.
    invalid = present or attack.startswith("directory-")
    result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2 if invalid else 0)
    if invalid:
        assert "stop custody" in result["error"] and "manual reconciliation" in result["error"]
    else:
        assert result["entries"][0]["generation"] == 2
    assert r2_case.projection.events == []


def test_r13_writer_escaped_unicode_remains_readable(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session, "-p", "é"])
    module = r2_case.module(False)
    code, stopped = r2_case.stop(module, capsys)
    assert code == 0 and held.wait(timeout=5) == -signal.SIGTERM
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    # v2 retains only the physical command digest, never logical prompt text (class I).
    assert path.read_bytes().isascii() and b"\\u00e9" not in path.read_bytes()
    control = handoff_module()
    control.hierarchy_launcher = module
    answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 0)
    assert answer["entries"][0]["generation"] == 2


@pytest.mark.parametrize("active", [False, True])
def test_r13_forged_resolution_does_not_release_live_custody(r2_case, capsys, active):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    held, path, saved = r7_pending_attempt(r2_case, capsys)
    saved["active"] = active
    saved["entries"][0]["resolved"] = "matching_birth_zombie"
    path.write_text(json.dumps(saved))
    module = r2_case.module(False)
    control = handoff_module()
    control.hierarchy_launcher = module
    answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
    assert "stop custody" in answer["error"] and held.poll() is None
    before = list(r2_case.projection.events)
    code, answer = r2_case.stop(module, capsys, 0)
    # Inactive-with-groups is a schema refusal; a valid occupied terminal claim is a stop failure.
    assert code == (3 if active else 2) and "resolved" in answer["error"]
    assert r2_case.projection.events == before and held.poll() is None


def test_r13_noop_creates_no_custody(r2_case, capsys):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == 0 and answer["state"] == "not_running"
    assert not (module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody").exists()


def test_r13_identity_loss_is_persisted_once_across_polls(r2_case, capsys):
    import stat

    held, path, saved = r7_pending_attempt(r2_case, capsys)
    module, writes = r2_case.module(False), []
    syncing = module.os.fsync

    def changed(pid, count, row):
        return row._replace(start_time=str(int(row.start_time) + 1)) if pid == held.pid else row

    def fsync(fd):
        result = syncing(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode) and Path(os.readlink("/proc/self/fd/%d" % fd)) == path.parent:
            writes.append(json.loads(path.read_text()))
        return result

    module.os.fsync = fsync
    r2_case.projection.after_present.append(changed)
    before = list(r2_case.projection.events)
    code, stopped = r2_case.stop(module, capsys, 1)
    assert code == 3 and stopped["pids"] == [held.pid] and held.poll() is None
    assert r2_case.projection.events == before
    assert len(writes) == 1 and writes[0]["entries"][0]["identity_lost"]
    assert json.loads(path.read_text())["entries"][0]["snapshot"] == saved["entries"][0]["snapshot"]


def test_r13_incomplete_birth_latch_survives_immediate_loss(r2_case, capsys):
    from types import SimpleNamespace

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    worker = family["W"]
    module, reads, changed = r2_case.module(False), {}, []
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"

    def before(pid, count):
        reads[pid] = count

    def incomplete(path, physical):
        if str(path) == "/proc/%d/status" % worker.pid and reads.get(worker.pid) == 1:
            return b"\n".join(line for line in physical.splitlines() if not line.startswith(b"Uid:"))
        return physical

    def replaced(pid, count, row):
        if pid == worker.pid and count >= 2:
            changed.append(True)
            return row._replace(start_time=str(int(row.start_time) + 1))
        return row

    clock = module.time

    def crash():
        if changed:
            entry = next(row for row in json.loads(path.read_text())["entries"] if row["pid"] == worker.pid)
            assert entry["identity_lost"], "replacement birth must already be durable at the next OS clock boundary"
            raise R10Interrupted("modelled loss immediately after the new birth latch")
        return clock.monotonic()

    module.time = SimpleNamespace(monotonic=crash, sleep=clock.sleep)
    r2_case.projection.before_read.append(before)
    r2_case.projection.path_view(module, incomplete)
    r2_case.projection.after_present.append(replaced)
    with pytest.raises(R10Interrupted, match="immediately after the new birth latch"):
        r2_case.stop(module, capsys, 1)
    capsys.readouterr()
    assert changed and worker.poll() is None
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)


def test_r13_crash_before_initial_parent_fsync_never_signals(r2_case, capsys):
    import stat

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    folder = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody"
    syncing, cuts = module.os.fsync, []

    def cut(fd):
        if (folder.exists() and stat.S_ISDIR(os.fstat(fd).st_mode) and
                Path(os.readlink("/proc/self/fd/%d" % fd)) == folder.parent):
            cuts.append(True)
            raise R10Interrupted("modelled crash before custody parent fsync")
        return syncing(fd)

    module.os.fsync = cut
    with pytest.raises(R10Interrupted, match="before custody parent fsync"):
        r2_case.stop(module, capsys, 0)
    capsys.readouterr()
    assert cuts and not (folder / "state.json").exists()
    assert held.poll() is None and r2_case.projection.events == []
    recovered, parents = r2_case.module(False), []
    syncing = recovered.os.fsync

    def synced(fd):
        result = syncing(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            parents.append(Path(os.readlink("/proc/self/fd/%d" % fd)))
        return result

    recovered.os.fsync = synced
    r2_case.projection.after_signal.append(lambda pid, number: parents.append("signal"))
    code, stopped = r2_case.stop(recovered, capsys)
    assert code == 0 and stopped["pids"] == [held.pid] and held.wait(timeout=5) == -signal.SIGTERM
    assert parents.index(folder.parent) < parents.index("signal")


@pytest.mark.parametrize("active", [False, True])
def test_r13_previous_boot_has_an_actionable_outcome(r2_case, capsys, active):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    code, stopped = r2_case.stop(module, capsys)
    assert code == 0 and held.wait(timeout=5) == -signal.SIGTERM
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    saved = json.loads(path.read_text())
    saved.update(boot="modelled previous boot", active=active)
    path.write_text(json.dumps(saved))
    control = handoff_module()
    control.hierarchy_launcher = module
    answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2 if active else 0)
    if active:
        assert str(path) in answer["error"] and "boot changed" in answer["error"]
        assert "manual" in answer["error"] and "retry" in answer["error"]
        assert "obtain evidence with" not in answer["error"]
    else:
        assert answer["entries"][0]["generation"] == 2


def test_r13_discovery_and_handoff_share_endpoint_lock(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    held = r2_case.spawn(["claude", "--resume", session])
    control = handoff_module()
    reader = r2_case.module(False)
    # MODELLED stale/empty census in the independent handoff reader, never signal authority.
    reader.process_census = lambda session: reader.ProcessCensus([], "proven")
    control.hierarchy_launcher = reader
    discover, concurrent = module.session_processes, []

    def paused(*args):
        found = discover(*args)
        if concurrent:
            return found  # The modelled interleaving happens once; later fresh censuses remain real.
        assert found == [(held.pid, r2_kernel_process(held.pid)["pgid"])]
        result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 3)
        concurrent.append(result)
        assert "busy" in result["entries"][0]["error"]
        assert r2_case.launch.binding()["session"] == session
        return found

    module.session_processes = paused
    code, stopped = r2_case.stop(module, capsys)
    assert concurrent and code == 0 and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_r13_census_unavailable_guidance_names_repair(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    control = handoff_module()
    control.hierarchy_launcher = module
    module.process_census = lambda session: module.ProcessCensus([], "unproven")
    result = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 2)
    assert "repair the process census" in result["error"]


@pytest.mark.parametrize("stage", ["replacement", "idempotent-preflight", "idempotent-recheck"])
@pytest.mark.parametrize("fault", ["pending", "corrupt"])
def test_r13_all_custody_refusals_give_the_right_next_action(r2_case, capsys, stage, fault):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(False)
    assert r2_case.stop(module, capsys, 0)[0] == 0
    path = r13_seed_empty_journal(module, r2_case)
    saved = json.loads(path.read_text())
    saved["active"] = True
    queried, injected = module.unresolved_stop_custody, []

    def faulted(base, endpoint):
        if not injected and (stage != "idempotent-recheck" or (r2_case.launch.root / ".write.lock").exists()):
            path.write_text("{" if fault == "corrupt" else json.dumps(saved))
            injected.append(True)
        return queried(base, endpoint)

    module.unresolved_stop_custody = faulted
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = (spec_for(r2_case.launch) if stage == "replacement" else
            spec_for(r2_case.launch, host="claude-code", session=session))
    code = 3 if stage == "idempotent-recheck" else 2
    result = run_main(control, r2_case.launch, spec, capsys, code)
    error = result["error"] if code == 2 else result["entries"][0]["error"]
    assert injected and REVIEW in error and "stop custody" in error
    if fault == "pending":
        assert "run hierarchy_launcher.py" in error and "stop --endpoint" in error
    else:
        assert str(path) in error and "manual reconciliation" in error and "mv -i --" in error
        assert "obtain evidence with" not in error


def test_r13_same_length_file_edit_before_publish_never_authorizes_signal(r2_case, capsys):
    import stat

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module, changed = r2_case.module(False), []
    syncing = module.os.fsync

    def fsync(fd):
        result = syncing(fd)
        path = Path(os.readlink("/proc/self/fd/%d" % fd))
        if not changed and stat.S_ISREG(os.fstat(fd).st_mode) and path.parent.name == ".stop-custody":
            raw = path.read_bytes()
            edited = raw.replace(b'"active": true', b'"active": null', 1)
            assert len(edited) == len(raw) and edited != raw
            path.write_bytes(edited)  # MODELLED same-length attacker write at the file-fsync boundary.
            changed.append(True)
        return result

    module.os.fsync = fsync
    code, refused = r2_case.stop(module, capsys, 0)
    assert changed and code == 2 and "stop custody changed during durable commit" in refused["error"]
    assert held.poll() is None and r2_case.projection.events == []


def test_r13_published_file_identity_is_checked_on_the_opened_descriptor(r2_case, capsys):
    import stat

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(False)
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    opening, syncing, armed, swapped = module.os.open, module.os.fsync, [], []

    def fsync(fd):
        result = syncing(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode) and Path(os.readlink("/proc/self/fd/%d" % fd)) == path.parent:
            armed.append(True)
        return result

    def replace_at_open(source, flags, *args, **kwargs):
        if str(source) == "state.json" and armed and not swapped:
            replacement = path.with_name("same-content.json")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            original = path.stat().st_ino
            os.replace(replacement, path)
            assert path.stat().st_ino != original
            swapped.append(True)  # Actual inode replacement after lstat, before the descriptor read.
        return opening(source, flags, *args, **kwargs)

    module.os.open, module.os.fsync = replace_at_open, fsync
    code, refused = r2_case.stop(module, capsys, 0)
    assert swapped and code == 2 and "stop custody changed during durable commit" in refused["error"]
    assert held.poll() is None and r2_case.projection.events == []


def test_r13_recovery_syncs_legacy_directory_entries_before_effect(r2_case, capsys):
    import stat

    held, path, saved = r7_pending_attempt(r2_case, capsys)
    # A v1 journal has no evidence that an earlier writer synced its parent entries (including old writers).
    module, events = r2_case.module(False), []
    syncing = module.os.fsync

    def fsync(fd):
        result = syncing(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            events.append(Path(os.readlink("/proc/self/fd/%d" % fd)))
        return result

    module.os.fsync = fsync
    r2_case.projection.after_signal.append(lambda pid, number: events.append("signal"))
    code, stopped = r2_case.stop(module, capsys, 0)
    assert code == 0 and stopped["pids"] == [held.pid] and held.wait(timeout=5) == -signal.SIGKILL
    for parent in (path.parent.parent, path.parent.parent.parent, path.parent.parent.parent.parent):
        assert parent in events and events.index(parent) < events.index("signal")


@pytest.mark.parametrize("tears", [1, 2])
def test_r13_parent_read_retry_is_bounded(r2_case, capsys, tears):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module, reads = r2_case.module(False), []

    def torn(path, physical):
        if str(path) == "/proc/%d/stat" % held.pid:
            reads.append(True)
            if len(reads) <= 2 * tears and len(reads) % 2 == 0:
                prefix, _, tail = physical.rpartition(b")")
                words = tail.split()
                words[1] = str(os.getpid() + 1).encode()
                return prefix + b") " + b" ".join(words)
        return physical

    r2_case.projection.path_view(module, torn)
    code, answer = r2_case.stop(module, capsys, 0)
    assert code == (0 if tears == 1 else 3)
    if tears == 1:
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        assert held.poll() is None and r2_case.projection.events == []
        assert answer["unresolved_pids"] == [held.pid]


@pytest.mark.parametrize("pidfds", [False, True], ids=["start-time", "pidfd"])
def test_r7_interrupted_stop_recovers_real_orphan_without_an_outcome(r2_case, capsys, pidfds):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    module = r2_case.module(pidfds)
    recovery = r2_case.module(pidfds)  # Qualify capability before H is intentionally reaped.
    worker = family["W"]

    def interrupted(pid, number):
        if pid == worker.pid and number == signal.SIGTERM:
            # Independent physical fixture custody ends H/M; it does not enter the PUBLIC signal audit.
            for label in ("H", "M"):
                slot = next(slot for slot, entry in r2_case.custody.entries.items()
                            if entry["pid"] == family[label].pid)
                r2_case.custody.kill_owned(slot)
            assert family["H"].wait(timeout=5) == -signal.SIGKILL
            wait_until(lambda: family["M"].poll() == "CONFIRMED_EXIT")
            raise KeyboardInterrupt("modelled launcher loss with orphan")

    r2_case.projection.after_signal.append(interrupted)
    try:
        with pytest.raises(KeyboardInterrupt, match="modelled launcher loss with orphan"):
            r2_case.stop(module, capsys, grace=0)
    finally:
        r2_case.projection.after_signal.remove(interrupted)
    capsys.readouterr()
    assert not r2_case.launch.records() and worker.poll() is None
    assert r2_case.projection.events == [(worker.pid, signal.SIGTERM)]
    before = list(r2_case.projection.events)
    code, stopped = r2_case.stop(recovery, capsys, grace=0)
    assert code == 3 and stopped["state"] == "stop_failed" and worker.poll() is None
    assert stopped["pids"] == [worker.pid]
    assert stopped["unresolved_pids"] == [worker.pid] and r2_case.projection.events == before
    journal = recovery.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    assert json.loads(journal.read_text())["active"]


def test_r7_failed_pre_effect_custody_write_sends_nothing(r2_case, capsys):
    import errno

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module = r2_case.module()
    replacing, faults = module.os.replace, []

    def failed(source, target, **kwargs):
        target = Path(os.readlink("/proc/self/fd/%d" % kwargs["dst_dir_fd"])) / target if kwargs else Path(target)
        if target.parent.name == ".stop-custody":
            faults.append(str(target))
            raise OSError(errno.EIO, "modelled custody write failure before effects")
        return replacing(source, target)

    module.os.replace = failed
    code, refused = r2_case.stop(module, capsys, grace=0)
    assert code == 2 and refused["state"] == "refused"
    assert "modelled custody write failure before effects" in refused["error"]
    assert faults and held.poll() is None and r2_case.projection.events == []
    assert not Path(faults[0]).exists()


def test_r7_failed_custody_write_after_term_retains_public_accounting(r2_case, capsys):
    import errno

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module = r2_case.module()
    replacing, faults, sent = module.os.replace, [], []

    def failed(source, target, **kwargs):
        target_path = Path(os.readlink("/proc/self/fd/%d" % kwargs["dst_dir_fd"])) / target if kwargs else Path(target)
        if sent and target_path.parent.name == ".stop-custody":
            faults.append(str(target_path))
            raise OSError(errno.EIO, "modelled persistent custody write failure after TERM")
        return replacing(source, target, **kwargs)

    module.os.replace = failed
    r2_case.projection.after_signal.append(lambda pid, number: sent.append(pid)
                                          if pid == held.pid and number == signal.SIGTERM else None)
    code, stopped = r2_case.stop(module, capsys, grace=0)
    assert faults and sent == [held.pid] and held.poll() is None
    assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == [held.pid]
    assert stopped["unresolved_pids"] == [held.pid] and "custody write failure after TERM" in stopped["error"]
    pending = json.loads(Path(faults[0]).read_text())
    assert pending["active"] and pending["entries"][0]["attempted"]
    code, recovered = r2_case.stop(r2_case.module(), capsys, grace=0)
    assert code == 0 and recovered["state"] == "stopped" and recovered["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGKILL


def test_r7_failed_terminal_custody_write_records_failure_with_attempted_pids(r2_case, capsys):
    import errno

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module()
    replacing, faults = module.os.replace, []

    def failed(source, target, **kwargs):
        target_path = Path(os.readlink("/proc/self/fd/%d" % kwargs["dst_dir_fd"])) / target if kwargs else Path(target)
        source_path = Path(os.readlink("/proc/self/fd/%d" % kwargs["src_dir_fd"])) / source if kwargs else Path(source)
        if target_path.parent.name == ".stop-custody" and not json.loads(source_path.read_text())["active"]:
            faults.append(str(target_path))
            raise OSError(errno.EIO, "modelled terminal custody update failure")
        return replacing(source, target, **kwargs)

    module.os.replace = failed
    code, stopped = r2_case.stop(module, capsys, grace=1)
    assert faults and held.wait(timeout=5) == -signal.SIGTERM
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == [held.pid]
    assert "terminal custody update failure" in stopped["error"]
    assert r2_case.launch.records()[-1] == stopped
    assert json.loads(Path(faults[0]).read_text())["active"]


@pytest.mark.parametrize("corruption", ["unknown-field", "duplicate-pid", "raw-hex", "inactive-invalid-entry",
                                      "boot-mismatch", "boot-missing", "unknown-proof", "inactive-pending",
                                      "boolean-generation"])
def test_r7_corrupt_custody_refuses_before_any_new_signal(r2_case, capsys, corruption):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    if corruption == "unknown-field":
        saved["unknown"] = True
    elif corruption == "duplicate-pid":
        saved["entries"].append(saved["entries"][0].copy())
    elif corruption == "raw-hex":
        saved["entries"][0]["snapshot"]["cmdline"] = "not hex"
    elif corruption == "inactive-invalid-entry":
        saved["active"] = False
        saved["entries"][0]["attempted"] = "unexpected"
    elif corruption == "unknown-proof":
        saved["entries"][0]["resolved"] = "modelled unrecognized proof"
    elif corruption == "inactive-pending":
        saved["active"] = False
    elif corruption == "boolean-generation":
        saved["binding"]["generation"] = True
    else:
        saved["boot"] = "modelled different boot" if corruption == "boot-mismatch" else None
    raw = json.dumps(saved)
    path.write_text(raw)
    before = list(r2_case.projection.events)
    code, refused = r2_case.stop(r2_case.module(), capsys, grace=0)
    assert code == 2 and "error" in refused
    assert path.read_text() == raw and r2_case.projection.events == before and held.poll() is None


@pytest.mark.parametrize("attempted", [False, True], ids=["candidate", "attempted"])
def test_r7_reused_pid_keeps_original_birth_across_recovery(r2_case, capsys, attempted):
    if attempted:
        held, path, saved = r7_pending_attempt(r2_case, capsys)
    else:
        session = str(uuid.uuid4())
        r2_case.bind("claude-code", session)
        held = r2_case.spawn(["claude", "--resume", session], ignore=True)
        first = r2_case.module(pidfds=False)

        def drift(pid, count, row):
            return row._replace(start_time=str(int(row.start_time) + 1)) if pid == held.pid and count >= 2 else row

        r2_case.projection.after_present.append(drift)
        code, stopped = r2_case.stop(first, capsys, grace=0)
        r2_case.projection.after_present.remove(drift)
        assert code == 3 and stopped["pids"] == [] and r2_case.projection.events == []
        path = first.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
        saved = json.loads(path.read_text())
    birth = saved["entries"][0]["snapshot"]["start_time"]
    before = list(r2_case.projection.events)

    def replacement(pid, count, row):
        # MODELLED replacement birth ONLY; the independent fixture always owns the real original child.
        return row._replace(start_time=str(int(birth) + 1)) if pid == held.pid else row

    r2_case.projection.after_present.append(replacement)
    code, stopped = r2_case.stop(r2_case.module(pidfds=False), capsys, grace=0)
    assert code == 3 and stopped["pids"] == ([held.pid] if attempted else [])
    assert stopped["unresolved_pids"] == [held.pid] and held.poll() is None
    assert r2_case.projection.events == before
    pending = json.loads(path.read_text())
    assert pending["entries"][0]["snapshot"]["start_time"] == birth
    assert pending["entries"][0]["identity_lost"]
    r2_case.projection.after_present.remove(replacement)
    # Even actual later numeric absence cannot recover proof lost to an observed replacement.
    r2_case.configs[0].with_suffix(".exit").touch()
    assert held.wait(timeout=5) == 0
    code, unresolved = r2_case.stop(r2_case.module(pidfds=False), capsys, grace=0)
    assert code == 3 and unresolved["unresolved_pids"] == [held.pid]
    assert r2_case.projection.events == before


def test_r7_recovery_never_signals_an_excluded_ancestor(r2_case, capsys):
    held, path, saved = r7_pending_attempt(r2_case, capsys)
    before = list(r2_case.projection.events)
    module = r2_case.module()
    ancestors = module.ancestors
    module.ancestors = lambda: ancestors() | {held.pid}  # MODELLED ancestor overlay at the OS boundary.
    code, stopped = r2_case.stop(module, capsys, grace=0)
    assert held.poll() is None and r2_case.projection.events == before
    assert code == 3 and stopped["pids"] == [held.pid] and stopped["unresolved_pids"] == [held.pid]
    assert json.loads(path.read_text())["active"] and saved["entries"][0]["attempted"]


def test_r7_public_handoff_cannot_ignore_interrupted_orphan_custody(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    code, previous = r2_case.stop(r2_case.module(pidfds=False), capsys, grace=0)
    assert code == 0 and previous["state"] == "not_running"
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    worker = family["W"]
    stopping, discovery = r2_case.module(pidfds=False), r2_case.module(pidfds=False)

    def interrupted(pid, number):
        if pid == worker.pid and number == signal.SIGTERM:
            # Independent physical custody, not public stop attempts, deliberately leaves the real W orphan.
            for label in ("H", "M"):
                slot = next(slot for slot, entry in r2_case.custody.entries.items()
                            if entry["pid"] == family[label].pid)
                r2_case.custody.kill_owned(slot)
            assert family["H"].wait(timeout=5) == -signal.SIGKILL
            wait_until(lambda: family["M"].poll() == "CONFIRMED_EXIT")
            raise KeyboardInterrupt("modelled interruption before stop outcome")

    r2_case.projection.after_signal.append(interrupted)
    try:
        with pytest.raises(KeyboardInterrupt, match="modelled interruption before stop outcome"):
            r2_case.stop(stopping, capsys, grace=0)
    finally:
        r2_case.projection.after_signal.remove(interrupted)
    capsys.readouterr()
    pending_path = stopping.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    pending = json.loads(pending_path.read_text())
    assert pending["active"] and any(row["pid"] == worker.pid and row["attempted"] for row in pending["entries"])
    assert worker.poll() is None and r2_case.projection.events == [(worker.pid, signal.SIGTERM)]
    assert r2_case.launch.records()[-1] == previous
    control = handoff_module()
    control.hierarchy_launcher = discovery
    spec = spec_for(r2_case.launch)
    before = mailbox_files(r2_case.launch.base)
    # A previous terminal record is insufficient while a newer attempted instance remains unresolved.
    run_main(control, r2_case.launch, spec, capsys, 2)
    assert mailbox_files(r2_case.launch.base) == before and worker.poll() is None


@pytest.mark.parametrize("fault", ["active", "unreadable", "corrupt", "unknown-schema", "boot-mismatch",
                                 "symlink", "dangling-symlink"])
def test_r8_public_handoff_refuses_uncertain_custody_and_preserves_resources(r2_case, capsys, fault):
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(pidfds=False)
    code, previous = r2_case.stop(module, capsys, grace=0)
    assert code == 0 and previous["state"] == "not_running"
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    r13_seed_empty_journal(module, r2_case)
    saved = json.loads(path.read_text())
    if fault == "unreadable":
        opening = module.os.open

        def unreadable(source, *args, **kwargs):
            if str(source) == "state.json" and kwargs.get("dir_fd") is not None:
                raise PermissionError("modelled custody file read denial")
            return opening(source, *args, **kwargs)
        module.os.open = unreadable  # MODELLED descriptor I/O boundary, confined to this loaded reader.
    elif fault in ("symlink", "dangling-symlink"):
        target = path.with_name("untrusted.json")
        if fault == "symlink":
            target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
    elif fault == "corrupt":
        path.write_text("{")
    else:
        if fault == "unknown-schema":
            saved["schema"] = "aegis.hierarchy-stop-custody/unknown"
        else:
            saved["active"] = True
            if fault == "boot-mismatch":
                saved["boot"] = "modelled different boot"
        path.write_text(json.dumps(saved))
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = spec_for(r2_case.launch)
    work = r2_case.launch.source / "retain-custody.txt"
    work.write_text("test-owned worktree data")
    login = r2_case.home / "codex" / "auth.json"
    login.parent.mkdir()
    login.write_text('{"test_owned": true}')
    before = mailbox_files(r2_case.launch.base)
    files = (work.read_bytes(), login.read_bytes())
    answer = run_main(control, r2_case.launch, spec, capsys, 2)
    assert "stop custody" in answer["error"]
    assert mailbox_files(r2_case.launch.base) == before
    assert (work.read_bytes(), login.read_bytes()) == files and r2_case.projection.events == []


@pytest.mark.parametrize("scope", ["other-base", "other-endpoint"])
@pytest.mark.parametrize("state", ["absent", "resolved"])
def test_r8_handoff_ignores_unrelated_custody(r2_case, capsys, scope, state):
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    module = r2_case.module(pidfds=False)
    code, previous = r2_case.stop(module, capsys, grace=0)
    assert code == 0 and previous["state"] == "not_running"
    launches = module.Launches(str(r2_case.launch.base))
    own = launches.folder(REVIEW) / ".stop-custody" / "state.json"
    r13_seed_empty_journal(module, r2_case)
    saved = json.loads(own.read_text())
    if state == "absent":
        own.unlink()
    if scope == "other-base":
        folder = r2_case.launch.tmp / "unrelated-base" / "launches" / module.quoted(REVIEW) / ".stop-custody"
    else:
        folder = launches.folder("pilot/lane/f2") / ".stop-custody"
    folder.mkdir(parents=True, mode=0o700)
    unrelated = folder / "state.json"
    saved["active"] = True  # Negative-only modelled pending custody; never signal authority.
    unrelated.write_text(json.dumps(saved))
    unrelated.chmod(0o600)
    raw = unrelated.read_bytes()
    control = handoff_module()
    control.hierarchy_launcher = module
    answer = run_main(control, r2_case.launch, spec_for(r2_case.launch), capsys, 0)
    assert answer["entries"][0]["generation"] == 2 and unrelated.read_bytes() == raw
    assert r2_case.projection.events == []


def test_r8_handoff_refuses_custody_disappearing_during_its_read(r2_case, capsys):
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(pidfds=False)
    code, previous = r2_case.stop(module, capsys, grace=0)
    assert code == 0 and previous["state"] == "not_running"
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    r13_seed_empty_journal(module, r2_case)
    opening, deleted = module.os.open, []

    def disappeared(source, flags, *args, **kwargs):
        if source == "state.json" and path.exists():
            path.unlink()  # MODELLED file loss after the consumer's initial positive existence observation.
            deleted.append(True)
        return opening(source, flags, *args, **kwargs)

    module.os.open = disappeared
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = spec_for(r2_case.launch)
    before = mailbox_files(r2_case.launch.root)
    result = run_main(control, r2_case.launch, spec, capsys, 2)
    assert deleted == [True] and "stop custody" in result["error"]
    assert mailbox_files(r2_case.launch.root) == before and r2_case.projection.events == []


@pytest.mark.parametrize("stage", ["preflight", "recheck"])
def test_r8_idempotent_handoff_also_checks_custody(r2_case, capsys, stage):
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module(pidfds=False)
    code, stopped = r2_case.stop(module, capsys, grace=0)
    assert code == 0 and stopped["state"] == "not_running"
    control = handoff_module()
    control.hierarchy_launcher = module
    spec = spec_for(r2_case.launch)
    assert run_main(control, r2_case.launch, spec, capsys, 0)["entries"][0]["generation"] == 2
    code, stopped = r2_case.stop(module, capsys, grace=0)
    assert code == 0 and stopped["state"] == "not_running"
    path = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    r13_seed_empty_journal(module, r2_case)
    saved = json.loads(path.read_text())
    saved["active"] = True
    before = mailbox_files(r2_case.launch.root)
    queried, inject = module.unresolved_stop_custody, []

    def during_read(base, endpoint):
        if not inject and (stage == "preflight" or (r2_case.launch.root / ".write.lock").exists()):
            path.write_text(json.dumps(saved))  # MODELLED pending custody appears at this reader boundary.
            inject.append(True)
        return queried(base, endpoint)

    module.unresolved_stop_custody = during_read
    expected = 2 if stage == "preflight" else 3  # Existing mid-batch refusal contract preserves prior entries.
    result = run_main(control, r2_case.launch, spec, capsys, expected)
    error = result["error"] if expected == 2 else result["entries"][0]["error"]
    assert inject == [True] and "stop custody" in error
    assert mailbox_files(r2_case.launch.root) == before and r2_case.projection.events == []


@pytest.mark.parametrize("with_host", [False, True])
def test_stop_spares_a_diagnostic_naming_the_session(launch, children, with_host):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    diagnostic = children(sys.executable, "-c", CHILD, session, logical_argv=None)
    owned = children(str(launch.tmp / "codex"), "-c", CHILD, "resume", session, logical_argv=["codex", "resume", session]) if with_host else None

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert diagnostic.poll() is None, "a diagnostic command naming the session must never be signalled"
    assert stopped["unowned_pids"] == [diagnostic.pid]
    assert stopped["state"] == ("stopped" if with_host else "not_running")
    assert stopped["pids"] == ([owned.pid] if with_host else [])
    if owned is not None:
        assert owned.wait(timeout=5) == -signal.SIGTERM


def test_stop_spares_a_program_for_a_different_host(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "claude"), "-c", CHILD, session, logical_argv=["claude", "--resume", session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert other.poll() is None, "a claude process does not belong to a codex-cli binding"
    assert stopped["unowned_pids"] == [other.pid]
    assert stopped["state"] == "not_running" and stopped["pids"] == []


@pytest.mark.parametrize("argument", ["prefix-%s", "%s-suffix"])
def test_stop_requires_the_session_as_a_whole_argument(launch, children, argument):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "codex"), "-c", CHILD, argument % session, logical_argv=["codex", "exec", argument % session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert other.poll() is None
    assert stopped["state"] == "not_running" and stopped["pids"] == []


@pytest.mark.parametrize("program,host", [("codex", "codex-cli"), ("claude", "claude-code")])
def test_real_harness_wrapper_presents_the_hosts_program_name(tmp_path, program, host):
    from tests.integration.hierarchy_fake_wrapper import python_argv
    from tests.integration.test_hierarchy_launcher import FAKE_CODEX
    from tests.integration import hierarchy_fake_claude as fake

    hosts = Hosts(tmp_path)
    hosts.init()
    session = str(uuid.uuid4())
    binding = hosts.add_role(REVIEW, host, session=session, cwd=str(hosts.source))
    argv = binding["start_argv"] if program == "claude" else ["codex", "exec", "--json", "resume", session]
    prompt, output = tmp_path / "wrapped.prompt", tmp_path / "wrapped.stdout"
    prompt.write_text("Wait.\n", encoding="utf-8")
    context = R2Case(hosts)
    try:
        if program == "claude":
            expected, captured = hosts.captured_claude(context, argv)
        else:
            expected, captured = [*python_argv("codex", FAKE_CODEX, hosts.tmp), *argv[1:]], []
        with prompt.open("rb") as stdin, output.open("wb") as stdout:
            held = context.spawn_exec(argv, argv, expected, cwd=hosts.source, stdin=stdin, stdout=stdout,
                                      environment=hosts.env(FAKE_CODEX_MODE="hang", FAKE_CODEX_THREAD=session,
                                                            FAKE_CLAUDE_MODE="hang"),
                                      captured=captured, target=(fake.HERE, "main") if program == "claude" else None)
        marker = b'"subtype": "init"' if program == "claude" else b'"type": "thread.started"'

        def host_ready():
            context.service_exec_children()
            return marker in output.read_bytes() or held.poll() is not None

        wait_until(host_ready)
        assert held.poll() is None, "the harness wrapper must keep the fake host running"
        shown = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(held.pid)],
                               capture_output=True, text=True, timeout=5, check=True)
        assert Path(shown.stdout.split()[0]).name == program
        assert session in shown.stdout.split()
        binary = Path(os.fsdecode(Path("/proc/%d/cmdline" % held.pid).read_bytes().split(b"\0")[0]))
        assert binary.is_symlink() and binary.resolve() == Path(sys.executable).resolve()
        assert tmp_path in binary.parents
        stopped = hosts.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)
        assert stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM
    finally:
        context.close()


@pytest.mark.parametrize("host,program,script", [
    ("claude-code", "claude.exe", None),
    ("claude-code", ".claude-wrapped", None),
    ("claude-code", "host tools/claude", None),
    ("claude-code", "node", "node_modules/@anthropic-ai/claude-code/cli.js"),
    ("claude-code", "node", "nix/store/claude-code/bin/.claude-wrapped"),
    ("claude-code", "host tools/node", "host scripts/@anthropic-ai/claude-code/cli.js"),
    ("codex-cli", "host tools/codex", None),
    ("codex-cli", "vendor/platform/bin/codex", None),
    ("codex-cli", "node", "host scripts/codex"),
])
def test_stop_accepts_validated_host_entrypoints(launch, children, host, program, script):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session)
    if script is None:
        arguments = ["-c", CHILD]
    else:
        target = launch.tmp / script
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(CHILD, encoding="utf-8")
        arguments = [str(target)]
    held = children(str(launch.tmp / program), *arguments, "resume" if host == "codex-cli" else "--resume", session, logical_argv=[str(launch.tmp / program), *([] if script is None else [str(target)]), "resume" if host == "codex-cli" else "--resume", session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_stop_rejects_an_arbitrary_cli_js(launch, children, host):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session)
    script = launch.tmp / "unrelated" / "cli.js"
    script.parent.mkdir()
    script.write_text(CHILD, encoding="utf-8")
    other = children(str(launch.tmp / "node"), str(script), "--resume", session, logical_argv=["node", str(script), "--resume", session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert other.poll() is None
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [other.pid]


def test_stop_does_not_split_a_session_out_of_a_single_argument(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "codex"), "-c", CHILD, "diagnostic %s text" % session, logical_argv=["codex", "exec", "diagnostic %s text" % session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert other.poll() is None
    assert stopped["state"] == "not_running" and stopped["pids"] == []


def test_linux_matcher_reads_proc_without_a_ps_census(launch, children, monkeypatch):
    session = str(uuid.uuid4())
    held = children(str(launch.tmp / "codex"), "-c", CHILD, "resume", session, logical_argv=["codex", "exec", "resume", session])
    module = children.module()

    def no_ps(*args, **kwargs):
        raise AssertionError("a Linux process census must read /proc")

    monkeypatch.setattr(module.subprocess, "run", no_ps)
    assert module.session_processes(session, set()) == [(held.pid, os.getpgid(held.pid))]


@pytest.mark.parametrize("noise", ["Bob's.txt", 'an unmatched " quote', "the other role's contract"])
def test_ps_fallback_ignores_unrelated_quotes(monkeypatch, noise):
    from types import SimpleNamespace

    module = launcher_module()
    session = str(uuid.uuid4())
    is_dir = Path.is_dir
    R2Processes.path_view(None, module, proc_available=False)
    module.subprocess = R2Facade(module.subprocess)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout=("99 99 1 {uid} {uid} S Sat Nov 7 12:00:00 2026 less {noise}\n"
                             "123 123 1 {uid} {uid} S Sat Nov 7 12:00:00 2026 /opt/codex exec resume {session} {noise}\n").format(
                                 uid=os.geteuid(), noise=noise, session=session)))

    observed = {}
    assert module.session_processes(session, set(), observed=observed) == []
    assert observed["coverage"] == "argv_boundaries_unavailable"
    with pytest.raises(TypeError, match="process census unresolved"):
        module.session_processes(session, set())


def test_ps_fallback_does_not_reconstruct_paths_with_spaces(monkeypatch):
    from types import SimpleNamespace

    module = launcher_module()
    session = str(uuid.uuid4())
    is_dir = Path.is_dir
    R2Processes.path_view(None, module, proc_available=False)
    module.subprocess = R2Facade(module.subprocess)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=0, stdout="123 123 1 %d %d S Sat Nov 7 12:00:00 2026 /opt/host tools/codex exec resume %s\n" %
                            (os.geteuid(), os.geteuid(), session)))
    unowned = []

    observed = {}
    assert module.session_processes(session, set(), "codex-cli", unowned, observed) == []
    assert observed["coverage"] == "argv_boundaries_unavailable"
    assert unowned == [123]
    with pytest.raises(TypeError, match="process census unresolved"):
        module.session_processes(session, set(), "codex-cli")


@pytest.mark.parametrize("argv,matched", [
    (["claude", "--resume", "<uuid>"], True),
    (["claude", "-p", "--output-format", "stream-json", "--resume", "<uuid>", "--verbose"], True),
    (["/home/u/.local/share/fnm/node-versions/v24.21.0/installation/lib/node_modules/"
      "@anthropic-ai/claude-code/bin/claude.exe", "--session-id", "<uuid>", "--print"], True),
    (["claude bg-pty-host", "--bg-pty-host", "/tmp/claude.sock"], False),
    (["claude bg-spare", "--bg-spare"], False),
    (["node", "/nix/store/claude-code/bin/.claude-wrapped", "--resume", "<uuid>"], True),
])
def test_observed_claude_argv_shapes(monkeypatch, argv, matched):
    # The owner supplied these NUL-split argv shapes from Claude Code 2.1.319, plus the Nix entrypoint.
    module = launcher_module()
    session = str(uuid.uuid4())
    argv = [session if word == "<uuid>" else word for word in argv]
    row = module.ProcessSnapshot(123, 123, "S", os.geteuid(), "1", b"\0".join(os.fsencode(a) for a in argv), tuple(argv),
                                 1, os.geteuid())
    monkeypatch.setattr(module, "process_census", lambda _session: module.ProcessCensus([row], "proven"))

    assert module.session_processes(session, set(), "claude-code") == ([(123, 123)] if matched else [])


def test_wrapper_symlink_creation_is_safe_when_callers_race(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from tests.integration.hierarchy_fake_wrapper import python_argv

    barrier = Barrier(2)
    symlink_to = Path.symlink_to

    def simultaneous(path, target, *args, **kwargs):
        barrier.wait(timeout=5)
        return symlink_to(path, target, *args, **kwargs)

    monkeypatch.setattr(Path, "symlink_to", simultaneous)
    script = tmp_path / "host.py"
    script.write_text("pass\n", encoding="utf-8")
    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = [pool.submit(python_argv, "codex", script, tmp_path) for _ in range(2)]
        commands = [call.result(timeout=5) for call in calls]

    binary = tmp_path / ".python" / "codex"
    assert all(command[0] == str(binary) for command in commands)
    assert binary.is_symlink() and binary.resolve() == Path(sys.executable).resolve()
    assert list(binary.parent.iterdir()) == [binary]


def test_wrapper_imports_only_its_folder_and_python_libraries(tmp_path, monkeypatch):
    from tests.integration.hierarchy_fake_wrapper import python_argv
    from tests.integration.test_hierarchy_mailbox import ROOT

    work, folder = tmp_path / "work", tmp_path / "wrapper"
    work.mkdir()
    folder.mkdir()
    for name in ("runpy.py", "pkgutil.py"):
        (work / name).write_text('raise RuntimeError("working directory imported")\n', encoding="utf-8")
    script = folder / "host.py"
    script.write_text("import json, pkgutil, sys\nprint(json.dumps({'paths': sys.path, 'python': sys.executable}))\n",
                      encoding="utf-8")
    monkeypatch.setattr(sys, "path", ["", str(work), *sys.path])
    command = python_argv("codex", script, tmp_path)
    ran = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)

    assert ran.returncode == 0, ran.stderr
    found = json.loads(ran.stdout)
    assert found["paths"][0] == str(folder)
    assert "" not in found["paths"] and str(work) not in found["paths"] and str(ROOT) not in found["paths"]
    assert found["python"] == sys.executable


@pytest.mark.parametrize("kind", ["probe", "rollout", "team", "direct-rollout"])
def test_rollout_launch_paths_present_the_host_program(tmp_path, kind, r2_case):
    from tests.integration.hierarchy_fake_wrapper import python_argv
    from tests.integration.test_hierarchy_fake_codex_rollouts import FAKE_CODEX, Fake, codex_argv
    from tests.integration.test_hierarchy_native_probe import Probe
    from tests.integration.test_hierarchy_team import fake_codex

    # Per-loaded MODELLED OS boundary, never a native Python grammar exception.
    launcher_module = r2_case.module
    folder = tmp_path / "rollout-harness"
    folder.mkdir()
    runtime = Fake(folder)
    session = str(uuid.uuid4())
    runtime.write_script({"commands": []})
    runtime.start(FAKE_CODEX_THREAD=session)
    runtime.write_script({"mode": "hang", "commands": []})
    argv = codex_argv(runtime.profile(), ["resume", session, "hold"])
    logical_argv = list(argv)
    expected = [*python_argv("codex", FAKE_CODEX, runtime.tmp, "rollout_main"), *argv[1:]]
    captured, target = [], None
    env = runtime.env(FAKE_CODEX_THREAD=session)
    if kind == "probe":
        folder = tmp_path / "probe-harness"
        folder.mkdir()
        probe = Probe(folder)
        argv[0] = str(probe.codex)
    elif kind == "team":
        folder = tmp_path / "team-bin"
        folder.mkdir()
        argv[0] = str(fake_codex(folder))
        env["FAKE_TEAM_LOG"] = str(tmp_path / "team.log")
        script = folder / "codex-wrapper.py"
        child = [*python_argv("codex", FAKE_CODEX, folder.parent), *argv[1:]]
        captured = [{"argv": child, "expected_argv": expected, "logical_argv": logical_argv}]
        prefix = python_argv("codex", ROOT / "tests/integration/test_hierarchy_launcher.py", folder.parent,
                             "r2_captured_entry")
        (folder / "codex").write_text("#!/bin/sh\n%s \"$@\"\n" %
                                      shlex.join(["exec", *prefix, str(script), "script"]),
                                      encoding="utf-8")
        expected = [*prefix, str(script), "script", *argv[1:]]
        target = (script, "script")
    elif kind == "direct-rollout":
        argv = [sys.executable, str(FAKE_CODEX), *argv[1:]]
    output = tmp_path / "rollout.stdout"
    with output.open("wb") as stdout:
        held = r2_case.spawn_exec(argv, logical_argv, expected, cwd=runtime.work, environment=env,
                                  stdout=stdout, captured=captured, target=target)
    try:
        def turn_ready():
            r2_case.service_exec_children()
            return b'"type": "turn.started"' in output.read_bytes() or held.poll() is not None

        wait_until(turn_ready)
        assert held.poll() is None
        assert held.pid in {pid for pid, _ in launcher_module().session_processes(session, set())}
    finally:
        r2_case.close()


def test_stop_spares_another_sessions_prompt(launch, children):
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--session-id", other, "--print", session, logical_argv=["claude", "--session-id", other, "--print", session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "0", timeout=R2_STOP_TIMEOUT_SECONDS)

    assert held.poll() is None
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]


def test_stop_spares_another_users_matching_process(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    module, read = children.module(), Path.read_bytes

    def other_uid(path):
        value = read(path)
        if str(path) == "/proc/%d/status" % held.pid:
            return status_uids(value, os.geteuid() + 1, os.geteuid() + 1)
        return value

    children.projection.path_view(module, lambda path, physical: other_uid(path))
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert held.poll() is None
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]


@pytest.mark.parametrize("changed", ["cmdline", "stat"])
def test_stop_rechecks_the_census_before_signalling(launch, children, monkeypatch, capsys, changed):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    module = children.module()

    def replaced(pid, count, row):
        # MODELLED metadata drift after the physical READY receipt was independently verified.
        if pid == held.pid and count > 1:
            return (row._replace(cmdline=row.cmdline + b"different-session\\0") if changed == "cmdline"
                    else row._replace(start_time=str(int(row.start_time) + 1)))
        return row

    children.projection.after_present.append(replaced)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"]) == (0 if changed == "cmdline" else 3)
    stopped = json.loads(capsys.readouterr().out)
    if changed == "cmdline":
        assert held.wait(timeout=5) == -signal.SIGTERM
        assert "unowned_pids" not in stopped and stopped["pids"] == [held.pid]
    else:
        assert held.poll() is None
        assert "unowned_pids" not in stopped and stopped["pids"] == []


@pytest.mark.skipif(not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"),
                    reason="pidfd signalling is unavailable")
def test_stop_opens_a_pidfd_then_verifies_then_signals(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    module, events, handles = children.module(), [], {}
    opening, sending, reading = module.os.pidfd_open, module.signal.pidfd_send_signal, module.Path.read_bytes

    def opened(pid, *args):
        fd = opening(pid, *args)
        handles[fd] = pid
        if pid == held.pid:
            events.append("open")
        return fd

    def read(path):
        if str(path) == "/proc/%d/cmdline" % held.pid:
            events.append("read")
        return reading(path)

    def sent(fd, *args):
        if handles[fd] == held.pid:
            events.append("signal")
        return sending(fd, *args)

    monkeypatch.setattr(module.os, "pidfd_open", opened)
    monkeypatch.setattr(module.signal, "pidfd_send_signal", sent)
    children.projection.path_view(module, lambda path, physical: read(path))
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "stopped"
    assert "open" in events and "signal" in events
    assert "read" in events[events.index("open") + 1:events.index("signal")]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_fallback_records_unproven_argument_boundaries(launch, monkeypatch, capsys):
    from types import SimpleNamespace

    launch.add_role(REVIEW, "claude-code", session=str(uuid.uuid4()))
    module, is_dir = launcher_module(), Path.is_dir
    R2Processes.path_view(None, module, proc_available=False)
    module.subprocess = R2Facade(module.subprocess)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=""))
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW]) == 3
    assert json.loads(capsys.readouterr().out)["argv_boundaries"] == "unproven"


@pytest.mark.parametrize("uid_offset,arguments,matched", [
    (0, "claude --resume={session}", True),
    (0, "claude --session-id other --print {session}", False),
    (0, "claude --resume {session} --session-id 00000000-0000-0000-0000-000000000001", False),
    (1, "claude --resume {session}", False),
])
def test_ps_fallback_checks_uid_and_positional_selectors(monkeypatch, uid_offset, arguments, matched):
    from types import SimpleNamespace

    module, session, is_dir = launcher_module(), str(uuid.uuid4()), Path.is_dir
    R2Processes.path_view(None, module, proc_available=False)
    module.subprocess = R2Facade(module.subprocess)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0,
        stdout="123 123 1 %d %d S Sat Nov 7 12:00:00 2026 %s\n" %
               (os.geteuid() + uid_offset, os.geteuid() + uid_offset, arguments.format(session=session))))
    unowned = []
    observed = {}
    assert module.session_processes(session, set(), "claude-code", unowned, observed) == []
    assert observed["coverage"] == "argv_boundaries_unavailable"
    assert unowned == [123]
    with pytest.raises(TypeError, match="process census unresolved"):
        module.session_processes(session, set(), "claude-code")


@pytest.mark.parametrize("uid_offset,expected_exit,expected_state", [(0, 3, "stop_failed"), (1, 3, "stop_failed")])
def test_stop_spares_an_unowned_member_of_an_owned_group(launch, children, monkeypatch, capsys, uid_offset,
                                                      expected_exit, expected_state):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    other = children(sys.executable, "-c", CHILD, session, logical_argv=None)
    module = children.module()
    read = module.read_process

    def group_member(pid, *args):
        row = read(pid, *args)
        # OS boundary: the other real child stands in for a diagnostic in the leader's process group.
        return r2_map_present(row, lambda value: value._replace(pgid=leader.pid, uid=os.geteuid() + uid_offset)) if pid == other.pid else row

    monkeypatch.setattr(module, "read_process", group_member)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == expected_exit
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == expected_state and stopped["pids"] == [leader.pid]
    assert stopped["unowned_pids"] == [other.pid]
    assert leader.wait(timeout=5) == -signal.SIGTERM
    assert other.poll() is None
    if uid_offset == 0:
        assert stopped["unresolved_pids"] == [other.pid]


def test_stop_records_a_signal_permission_failure(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    module = children.module()

    def denied(*args):
        raise PermissionError("signal denied")

    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        monkeypatch.setattr(module.signal, "pidfd_send_signal", denied)
    else:
        monkeypatch.setattr(module.os, "kill", denied)
    monkeypatch.setattr(module, "KILL_WAIT_SECONDS", 0)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == "stop_failed" and stopped["pids"] == [held.pid]
    assert held.poll() is None


def status_uids(value, real, effective):
    return b"\n".join(b"Uid:\t%d\t%d\t%d\t%d" % (real, effective, effective, effective)
                      if line.startswith(b"Uid:") else line for line in value.split(b"\n"))


def fallback_process(monkeypatch, module, held, argv):
    from types import SimpleNamespace

    is_dir = Path.is_dir
    monkeypatch.setattr(module, "ancestors", lambda: {os.getpid()})
    R2Processes.path_view(None, module, proc_available=False)

    def ps(command, **options):
        if held.poll() is not None:
            return SimpleNamespace(returncode=1 if "-p" in command else 0, stdout="")
        columns = command[command.index("-o") + 1].replace("=", "").split(",")
        values = {"pid": str(held.pid), "pgid": str(held.pid), "ppid": str(os.getpid()),
                  "uid": str(os.geteuid()), "ruid": str(os.geteuid()), "stat": "S",
                  "lstart": "Sat Nov 7 12:00:00 2026", "args": " ".join(argv)}
        return SimpleNamespace(returncode=0, stdout=" ".join(values[column] for column in columns) + "\n")

    monkeypatch.setattr(module.subprocess, "run", ps)


@pytest.mark.parametrize("host,other", [("codex-cli", False), ("codex-cli", True),
                                       ("claude-code", False), ("claude-code", True)])
def test_fallback_matches_the_launchers_real_argv(launch, children, monkeypatch, capsys, host, other):
    from hierarchy_provision import codex_argv

    session = str(uuid.uuid4())
    role = launch.add_role(REVIEW, host, session=session)
    selected = str(uuid.uuid4()) if other else session
    if host == "codex-cli":
        profile = json.loads(Path(role["codex_profile"]).read_text())
        argv = codex_argv(profile, ["resume", selected, session])
    else:
        argv = [selected if word == session else word for word in role["start_argv"]] + [session]
    held = children(sys.executable, "-c", CHILD, logical_argv=None)
    module = children.module()
    fallback_process(monkeypatch, module, held, argv)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["argv_boundaries"] == "unproven"
    assert stopped["state"] == "stop_failed"
    assert stopped["pids"] == []
    if other:
        assert stopped["unowned_pids"] == [held.pid] and held.poll() is None
    else:
        assert held.poll() is None


def test_stop_matches_codex_after_an_option_terminator(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    held = children(str(launch.tmp / "codex"), "-c", CHILD, "exec", "resume", "--", session, "prompt", logical_argv=["codex", "exec", "resume", "--", session, "prompt"])
    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)
    assert stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("option", ["--loader", "--experimental-loader", "--import", "-r", "--require",
                                  "--env-file", "--conditions", "-C", "--title", "--input-type"])
def test_stop_matches_node_options_with_separate_values(launch, children, monkeypatch, capsys, option):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(sys.executable, "-c", CHILD, logical_argv=["node", option, "/opt/l.mjs", "/lib/@anthropic-ai/claude-code/cli.js",
                                    "--resume", session])
    module = children.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_stop_spares_an_unknown_node_option_value(launch, children, monkeypatch, capsys):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(sys.executable, "-c", CHILD, logical_argv=["node", "--unknown-option", "/lib/@anthropic-ai/claude-code/cli.js",
                                    "--resume", session])
    module = children.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]
    assert held.poll() is None


@pytest.mark.parametrize("missing", ["open", "send", "both"])
@pytest.mark.parametrize("scenario,error,change", [
    ("unsupported", 38, None), ("unsupported", 1, None), ("unsupported", 5, None),
    ("descendants", None, None), ("descendants", None, "cmdline"),
    ("descendants", None, "unreadable"), ("descendants", None, "named-session"),
])
def test_pidfd_fallback_cases_run_without_optional_apis(launch, children, monkeypatch, capsys,
                                                      missing, scenario, error, change):
    from types import SimpleNamespace

    class WithoutPidfds:
        projection = children.projection

        def __call__(self, *args, **kwargs):
            return children(*args, **kwargs)

        def module(self, pidfds=True):
            # The real fixture refuses native mode before loading the consumer on such builds.
            assert pidfds is False, "fallback case requested native pidfd qualification"
            module = children.module(pidfds=False)
            # Delete only from owned copies: no stdlib mutation reaches pytest or cleanup.
            module.os.original = SimpleNamespace(**{**vars(os)})
            module.signal.original = SimpleNamespace(**{**vars(signal)})
            if missing in ("open", "both"):
                if hasattr(module.os.original, "pidfd_open"):
                    del module.os.original.pidfd_open
                assert not hasattr(module.os.original, "pidfd_open")
                # The explicit ENOSYS fixture seam remains available on an API-less build.
            if missing in ("send", "both"):
                if hasattr(module.signal.original, "pidfd_send_signal"):
                    del module.signal.original.pidfd_send_signal
                if hasattr(module.signal, "pidfd_send_signal"):
                    del module.signal.pidfd_send_signal
                assert not hasattr(module.signal, "pidfd_send_signal")
            return module

    absent = WithoutPidfds()
    if scenario == "unsupported":
        test_stop_falls_back_only_when_pidfd_is_unsupported(launch, absent, monkeypatch, capsys, error)
    else:
        test_stop_retains_stubborn_descendants_after_the_middle_exits(
            launch, absent, monkeypatch, capsys, False, change)


@pytest.mark.parametrize("error", [1, 38, 5])
def test_stop_falls_back_only_when_pidfd_is_unsupported(launch, children, monkeypatch, capsys, error):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])

    def unavailable(pid):
        raise OSError(error, "pidfd unavailable")

    module = children.module(pidfds=False)
    monkeypatch.setattr(module.os, "pidfd_open", unavailable)
    module.signal = R2Facade(module.signal, pidfd_send_signal=lambda *args: pytest.fail("unopened pidfd signalled"))
    code = module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"])
    answer = json.loads(capsys.readouterr().out)
    if error == 38:  # ENOSYS establishes lack of kernel capability; other errors do not.
        assert code == 0 and answer["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        assert code == 3 and answer["state"] == "stop_failed" and answer["pids"] == []
        assert answer["error"] == ("stop could not obtain a safe process handle; preserve custody, restore "
            "pidfd availability and retry stop, or stop the host manually and have the owner reconcile this endpoint")
        assert held.poll() is None
        custody = module.Launches(str(launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
        assert json.loads(custody.read_text())["active"]
        assert children.projection.events == []

        def unsupported(pid):
            raise OSError(38, "pidfd unsupported on retry")

        module.os = R2Facade(module.os, pidfd_open=unsupported)
        assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
        assert json.loads(capsys.readouterr().out)["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM


def test_stop_spares_a_forked_claude_session(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, "--fork-session", logical_argv=["claude", "--resume", session, "--fork-session"])
    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=R2_STOP_TIMEOUT_SECONDS)
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [held.pid]
    assert held.poll() is None


@pytest.mark.parametrize("changed", ["directory", "real", "effective", "missing"])
def test_stop_uses_real_and_effective_status_uids(launch, children, monkeypatch, capsys, changed):
    from types import SimpleNamespace

    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    read, stat = Path.read_bytes, os.stat

    def status(path):
        value = read(path)
        if str(path) == "/proc/%d/status" % held.pid:
            if changed == "missing":
                return b"\n".join(line for line in value.split(b"\n") if not line.startswith(b"Uid:"))
            return status_uids(value, os.geteuid() + (changed == "real"), os.geteuid() + (changed == "effective"))
        return value

    def owner(path, *args, **kwargs):
        if changed == "directory" and os.fspath(path) == "/proc/%d" % held.pid:
            return SimpleNamespace(st_uid=os.geteuid() + 1)
        return stat(path, *args, **kwargs)

    module = children.module()
    children.projection.path_view(module, lambda path, physical: status(path))
    monkeypatch.setattr(module.os, "stat", owner)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == (3 if changed == "missing" else 0)
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == ([held.pid] if changed == "directory" else [])
    if changed == "directory":
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        assert stopped["unowned_pids"] == [held.pid] and held.poll() is None


def present_family(projection, family, change=None):
    """MODELLED parent/group edges after real birth/raw/UID capture, never a global kernel rewrite."""
    counts = {}

    def modelled(pid, count, row):
        if pid in family:
            pgid, ppid = family[pid]
            counts[pid] = counts.get(pid, 0) + 1
            fields = [b"0"] * 20
            fields[1], fields[19] = str(ppid).encode(), row.start_time.encode()
            if change is not None and counts[pid] > 1:
                change(pid, fields)
            return row._replace(ppid=int(fields[1]), pgid=pgid, start_time=fields[19].decode())
        return row

    projection.after_present.append(modelled)


@pytest.mark.parametrize("parent_owned", [False, True])
def test_stop_spares_a_group_member_selecting_another_session(launch, children, monkeypatch, capsys, parent_owned):
    session, other_session = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    leader = children(str(launch.tmp / "codex"), "-c", CHILD, "exec", "resume", session, logical_argv=["codex", "exec", "resume", session])
    shell = children(str(launch.tmp / "sh"), "-c", CHILD, logical_argv=None)
    other = children(str(launch.tmp / "other-host" / "codex"), "-c", CHILD, "exec", "resume", other_session, logical_argv=["codex", "exec", "resume", other_session])
    present_family(children.projection, {other.pid: (leader.pid, leader.pid if parent_owned else shell.pid)})
    module = children.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [leader.pid] and "unowned_pids" not in stopped
    assert leader.wait(timeout=5) == -signal.SIGTERM
    assert other.poll() is None and shell.poll() is None


@pytest.mark.parametrize("changed", [None, "ppid", "birth"])
def test_stop_checks_the_descendants_entire_parent_chain(launch, children, monkeypatch, capsys, changed):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    middle = children(sys.executable, "-c", CHILD, logical_argv=None)
    worker = children(sys.executable, "-c", CHILD, logical_argv=None)

    def retarget(pid, fields):
        if pid == middle.pid and changed == "ppid":
            fields[1] = str(os.getpid()).encode()
        if pid == middle.pid and changed == "birth":
            fields[19] = str(int(fields[19]) + 1).encode()

    present_family(children.projection, {middle.pid: (leader.pid, leader.pid), worker.pid: (leader.pid, middle.pid)}, retarget)
    module = children.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == (0 if changed is None else 3)
    stopped = json.loads(capsys.readouterr().out)
    expected = sorted([leader.pid, middle.pid, worker.pid]) if changed is None else [leader.pid]
    assert stopped["pids"] == expected and "unowned_pids" not in stopped
    assert leader.wait(timeout=5) == -signal.SIGTERM
    if changed is None:
        assert middle.wait(timeout=5) == worker.wait(timeout=5) == -signal.SIGTERM
    else:
        assert middle.poll() is None and worker.poll() is None


@pytest.mark.parametrize("changed", ["cmdline", "uid"])
def test_stop_does_not_report_non_session_group_members_as_unowned(launch, children, monkeypatch, capsys, changed):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    member = children(sys.executable, "-c", CHILD, logical_argv=None)
    present_family(children.projection, {member.pid: (leader.pid, leader.pid)})
    def replaced(pid, count, row):
        if pid == member.pid and count > 1:
            return (row._replace(uid=os.geteuid() + 1, euid=os.geteuid() + 1) if changed == "uid"
                    else row._replace(cmdline=row.cmdline + b"changed\\0"))
        return row

    children.projection.after_present.append(replaced)
    module = children.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [leader.pid]
    assert "unowned_pids" not in stopped
    assert leader.wait(timeout=5) == -signal.SIGTERM
    # R28: both a replacement UID and changed nonhost command authority prohibit a first signal.
    assert member.poll() is None
    assert all(pid != member.pid for pid, _ in children.projection.events)
    if changed == "cmdline":
        assert any(row.get("signal_refusal") == "signal_command_line_not_authorized" for row in stopped["unresolved"])


@pytest.mark.parametrize("arguments,owned", [
    (["--", "--resume <S>"], False),
    (["--", "--resume=<S>"], False),
    (["--", "--session-id <S>"], False),
    (["--resume", "<S>", "--", "--resume <T>"], False),
    (["--resume", "<S>", "--", "--resume <S>"], True),
    (["--resume", "<S>", "--", "please resume the review"], True),
])
def test_claude_fallback_terminator_keeps_prompt_text_unowned(launch, children, monkeypatch, capsys, arguments, owned):
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(sys.executable, "-c", CHILD, logical_argv=None)
    argv = ["claude", *(word.replace("<S>", session).replace("<T>", other) for word in arguments)]
    module = children.module()
    fallback_process(monkeypatch, module, held, argv)

    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["argv_boundaries"] == "unproven"
    assert stopped["state"] == "stop_failed"
    assert stopped["pids"] == []
    if owned:
        assert held.poll() is None
    else:
        assert held.poll() is None and stopped["unowned_pids"] == [held.pid]


@pytest.mark.parametrize("host,prompt", [("codex-cli", "please resume the review"),
                                        ("claude-code", "please --resume the review"),
                                        ("claude-code", "please --session-id the review")])
def test_fallback_ordinary_prompt_words_are_not_conflicting_sessions(launch, children, monkeypatch, capsys, host, prompt):
    from hierarchy_provision import codex_argv

    session = str(uuid.uuid4())
    role = launch.add_role(REVIEW, host, session=session)
    argv = (codex_argv(json.loads(Path(role["codex_profile"]).read_text()), ["resume", session, prompt])
            if host == "codex-cli" else role["start_argv"] + [prompt])
    held = children(sys.executable, "-c", CHILD, logical_argv=None)
    module = children.module()
    fallback_process(monkeypatch, module, held, argv)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [] and stopped["argv_boundaries"] == "unproven"
    assert held.poll() is None


@pytest.mark.parametrize("arguments", [
    pytest.param(["-r", "<T>", "-p", "wait"], id="modelled-short-alias-not-observed"),
    pytest.param(["--unlisted-session=<T>"], id="equals-value"),
    pytest.param(["<T>"], id="bare-uuid"),
])
def test_stop_spares_descendants_naming_another_uuid(launch, children, monkeypatch, capsys, arguments):
    # The -r alias is modelled, not an observation about an installed Claude CLI.
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])
    worker = children(str(launch.tmp / "child" / "claude"), "-c", CHILD,
                      *(word.replace("<T>", other) for word in arguments), logical_argv=["claude", *(word.replace("<T>", other) for word in arguments)])
    present_family(children.projection, {worker.pid: (leader.pid, leader.pid)})
    module = children.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [leader.pid] and "unowned_pids" not in stopped
    assert worker.poll() is None
    assert leader.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("use_pidfds", [True, False], ids=["pidfds", "start-time-evidence"])
@pytest.mark.parametrize("change", [None, "cmdline", "unreadable", "named-session"])
def test_stop_retains_stubborn_descendants_after_the_middle_exits(launch, children, monkeypatch, capsys,
                                                                use_pidfds, change):
    import errno

    if use_pidfds and not (hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")):
        pytest.skip("pidfd APIs unavailable")
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    ignore_term = CHILD.replace("import os, time", "import os, time, signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)")
    leader = children(str(launch.tmp / "claude"), "-c", ignore_term, "--resume", session, logical_argv=["claude", "--resume", session], body=ignore_term)
    middle = children(sys.executable, "-c", CHILD, logical_argv=None)
    worker = children(str(launch.tmp / "worker"), "-c", ignore_term, logical_argv=None, body=ignore_term)
    present_family(children.projection, {middle.pid: (leader.pid, leader.pid), worker.pid: (leader.pid, middle.pid)})
    module = children.module(pidfds=use_pidfds)
    term_done, handles, events = [], {}, []
    kill = module.os.kill

    def observe(pid, number):
        events.append((pid, number))
        if pid == leader.pid and number == signal.SIGTERM:
            assert middle.wait(timeout=5) == -signal.SIGTERM
            term_done.append(True)

    def killed(pid, number):
        answer = kill(pid, number)
        observe(pid, number)
        return answer

    monkeypatch.setattr(module.os, "kill", killed)
    if use_pidfds:
        opening, sending = module.os.pidfd_open, module.signal.pidfd_send_signal

        def opened(pid, *args):
            fd = opening(pid, *args)
            handles[fd] = pid
            return fd

        def sent(fd, number, *args):
            answer = sending(fd, number, *args)
            observe(handles[fd], number)
            return answer

        monkeypatch.setattr(module.os, "pidfd_open", opened)
        monkeypatch.setattr(module.signal, "pidfd_send_signal", sent)
    else:
        def unavailable(*args):
            raise OSError(errno.ENOSYS, "pidfds unavailable")
        monkeypatch.setattr(module.os, "pidfd_open", unavailable)

    def changed(pid, count, row):
        if term_done and pid == worker.pid:
            if change == "cmdline":
                return row._replace(cmdline=row.cmdline + b"changed\\0")
            if change == "named-session":
                return row._replace(cmdline=row.cmdline + b"--session-id=" + session.encode() + b"\\0",
                                    argv=(*row.argv, "--session-id=" + session))
        return row

    def unreadable(path, physical):
        if term_done and str(path) == "/proc/%d/cmdline" % worker.pid and change == "unreadable":
            raise PermissionError("worker evidence unavailable")
        return physical

    children.projection.after_present.append(changed)
    children.projection.path_view(module, unreadable)
    monkeypatch.setattr(module, "KILL_WAIT_SECONDS", 1)
    code = module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"])
    stopped = json.loads(capsys.readouterr().out)
    if change is None:
        assert code == 0 and stopped["state"] == "stopped"
        # A matching physical zombie can precede waitpid's nonblocking readiness; wait for its real status.
        assert worker.wait(timeout=5) == -signal.SIGKILL
        assert (worker.pid, signal.SIGKILL) in events
    else:
        # R28: same instance does not authorize a changed nonhost command, even if it mentions S.
        assert code == 3 and stopped["state"] == "stop_failed"
        assert worker.poll() is None and (worker.pid, signal.SIGKILL) not in events
        if change in ("cmdline", "named-session"):
            assert any(row.get("signal_refusal") == "signal_command_line_not_authorized" for row in stopped["unresolved"])
    assert stopped["pids"] == sorted([leader.pid, middle.pid, worker.pid])
    assert not set(stopped["pids"]) & set(stopped.get("unowned_pids", []))
    assert leader.wait(timeout=5) == -signal.SIGKILL


def test_stubborn_descendant_stop_waits_for_actual_kill_delivery(launch, children, monkeypatch, capsys):
    """MODELLED delayed signal delivery at this module's OS boundary; all exit observations remain physical."""
    actors, held, delivered, live_reads = [], [], [], []

    def spawn(*args, **kwargs):
        process = children(*args, **kwargs)
        actors.append(process)
        return process

    def module(pidfds=True):
        loaded = children.module(pidfds=pidfds)
        killing = loaded.os.kill

        def delayed(pid, number):
            if pid == actors[2].pid and number == signal.SIGKILL:
                held.append(pid)
                return None  # Accepted by the modelled OS, but not delivered to the real child yet.
            return killing(pid, number)

        def observed(pid, count, row):
            if held and pid == actors[2].pid and not delivered:
                physical = r2_kernel_process(pid)
                live_reads.append({key: physical[key] for key in ("pid", "birth", "state", "uid", "euid")})
                if len(live_reads) == 2:
                    killing(pid, signal.SIGKILL)
                    delivered.append(pid)
            return row

        loaded.os.kill = delayed
        children.projection.after_present.append(observed)
        return loaded

    spawn.projection, spawn.module = children.projection, module
    try:
        test_stop_retains_stubborn_descendants_after_the_middle_exits(
            launch, spawn, monkeypatch, capsys, False, None)
    finally:
        (launch.tmp / "delayed-delivery-evidence.json").write_text(json.dumps(
            {"held": held, "delivered": delivered, "physical_live_reads": live_reads,
             "stop_records": [r for r in launch.records() if r.get("action") == "stop"]}, indent=2))
    assert held == delivered == [actors[2].pid] and len(live_reads) == 2
    assert all(not row["state"].startswith("Z") for row in live_reads)
    assert actors[2].wait(timeout=5) == -signal.SIGKILL


def test_stubborn_descendant_completion_waits_for_deferred_native_reap(launch, children, monkeypatch, capsys):
    """MODELLED one deferred nonblocking reap; the matching zombie and eventual waitpid status are real."""
    actors, deferred = [], []

    def spawn(*args, **kwargs):
        process = children(*args, **kwargs)
        actors.append(process)
        if len(actors) == 3:
            polling = process.poll

            def delayed():
                if not deferred:
                    physical = r2_kernel_process(process.pid)
                    if physical["state"].startswith("Z"):
                        deferred.append({key: physical[key] for key in ("pid", "birth", "state", "uid", "euid")})
                        return None
                return polling()

            monkeypatch.setattr(process, "poll", delayed)
        return process

    spawn.projection, spawn.module = children.projection, children.module
    try:
        test_stop_retains_stubborn_descendants_after_the_middle_exits(
            launch, spawn, monkeypatch, capsys, False, None)
    finally:
        (launch.tmp / "deferred-reap-evidence.json").write_text(json.dumps(
            {"physical_zombie": deferred,
             "stop_records": [r for r in launch.records() if r.get("action") == "stop"]}, indent=2))
    assert len(deferred) == 1 and deferred[0]["birth"] == actors[2].native_birth
    assert native_wait_fields(actors[2])["returncode"] == -signal.SIGKILL


@pytest.mark.parametrize("evidence", ["proven", "unproven"])
@pytest.mark.parametrize("host,arguments,proven,flattened", SELECTOR_STATE_CASES)
def test_selector_state_table_through_public_stop(launch, children, monkeypatch, capsys, evidence,
                                                host, arguments, proven, flattened):
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, host, session=session)
    program = "codex" if host == "codex-cli" else "claude"
    argv = [program, *(word.replace("<S>", session).replace("<T>", other) for word in arguments)]
    held = children(sys.executable, "-c", CHILD, logical_argv=argv if evidence == "proven" else None)
    module = children.module()
    if evidence == "unproven":
        fallback_process(monkeypatch, module, held, argv)
    disposition = next(row for row in R2_SELECTOR_DISPOSITIONS
                       if row["host"] == host and row["arguments"] == arguments and
                       row["provider"] == ("PROVEN_ARGV" if evidence == "proven" else "LOSSY_PS"))
    verdict, expected_exit, expected_state = (disposition[key] for key in ("verdict", "expected_exit", "expected_state"))
    owned = verdict == "OWNED"
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == expected_exit
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == expected_state
    assert stopped["pids"] == ([held.pid] if verdict == "OWNED" else [])
    if evidence == "unproven":
        assert stopped["argv_boundaries"] == "unproven"
        if not owned:
            assert stopped["unowned_pids"] == [held.pid]
    if verdict == "OWNED":
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        assert held.poll() is None


@pytest.mark.parametrize("host,arguments,expected_exit", [
    pytest.param("codex-cli", ["exec", "resume", "--last", "resume <S> prompt"], 3,
                 id="modelled-codex-option-value"),
    pytest.param("claude-code", ["--resume", "--print", "please --resume <S>"], 3,
                 id="modelled-claude-option-value"),
    pytest.param("claude-code", ["-r<T>", "-p", "wait"], 3, id="modelled-attached-alias-not-observed"),
])
def test_group_descendants_with_ambiguous_selection_are_spared(launch, children, monkeypatch, capsys, host, arguments,
                                                             r2_case, expected_exit):
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    leader = r2_case.spawn(["claude", "--resume", session])
    argv = ["codex" if host == "codex-cli" else "claude",
            *(word.replace("<S>", session).replace("<T>", other) for word in arguments)]
    worker = r2_case.spawn(argv)

    def modelled_parent(pid, count, row):
        # MODELLED_OS_BOUNDARY ancestry/argv; physical birth, raw cmdline, UIDs and actual signals stay real.
        return row._replace(pgid=leader.pid, ppid=leader.pid) if pid == worker.pid else row

    r2_case.projection.after_present.append(modelled_parent)
    module = r2_case.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == expected_exit
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["pids"] == [leader.pid]
    assert worker.poll() is None
    assert leader.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("command", [["resume"], ["exec", "resume"]])
def test_proven_codex_terminator_keeps_option_shaped_positionals(launch, children, monkeypatch, capsys, command):
    # Modelled argv: --json after -- is a literal positional, not an option to skip before a registered command.
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    held = children(sys.executable, "-c", CHILD, logical_argv=["codex", "--", "--json", *command, session])
    module = children.module()
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 3
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == "stop_failed" and stopped["pids"] == []
    assert stopped["unowned_pids"] == [held.pid] and held.poll() is None


# R2 host-executed regressions. Logical host arrays below are MODELLED complete atoms; physical Python argv
# is never accepted as native CLI grammar. These tests intentionally do not reuse present_argv/global patches.
class R2Case:
    def __init__(self, launch):
        self.launch = launch
        self.custody = R2Custody(launch.tmp / "r2-physical", launch.tmp.parent / "r2-physical-UNKNOWN.json")
        try:
            self.projection = R2Processes(launch.tmp / "r2-projection")
        except BaseException:
            self.custody.close()
            raise
        self.script = launch.tmp / "r2-actor.py"
        self.script.write_text(R2_ACTOR_BOOTSTRAP, encoding="utf-8")
        self.children, self.configs, self.exec_children = [], [], {}
        self.home = launch.tmp / "r2-home"
        self.home.mkdir(mode=0o700)
        self.env = {key: value for key, value in launch.env().items()
                    if key not in ("CLAUDECODE", "CLAUDE_PID") and not key.startswith("CLAUDE_CODE_")}
        self.env.update(HOME=str(self.home), CODEX_HOME=str(self.home / "codex"),
                        CLAUDE_CONFIG_DIR=str(self.home / "claude"), PYTHONDONTWRITEBYTECODE="1")
        launch.stop_case = self
        launch.stop_projection = self.projection

    def bind(self, host, session):
        return self.launch.add_role(REVIEW, host, session=session, cwd=str(self.launch.source))

    def spawn(self, argv=None, ignore=False, tree=False, worker_argv=None, middle_argv=None, new_session=True):
        tag = "actor%d-" % len(self.configs)
        nodes = {tag + "H": {"kind": "H", "parent": None, "child": tag + "M" if tree else None}}
        if tree:
            nodes.update({tag + "M": {"kind": "M", "parent": tag + "H", "child": tag + "W"},
                          tag + "W": {"kind": "W", "parent": tag + "M", "child": None}})
        config = self.make_config(nodes, ignore=ignore, tree=tree)
        try:
            root = self.custody.launch(config, tag + "H", self.env, new_session=new_session)
            family = {"H": self.admit(tag + "H", root, argv)}
            if tree:
                for label in ("M", "W"):
                    slot = tag + label
                    self.custody.await_event(slot, "hello")
                    from tests.integration.test_hierarchy_launcher import R2OwnedChild
                    child = R2OwnedChild(self.custody, slot)
                    family[label] = self.admit(slot, child, worker_argv if label == "W" else middle_argv)
            return family if tree else root
        except BaseException:
            self.close()
            raise

    def spawn_group(self, argv, named_child=None, siblings=False, stubborn=False):
        """Bounded real group topology; only the explicitly supplied host arrays are MODELLED."""
        from tests.integration.test_hierarchy_launcher import R2OwnedChild

        tag = "actor%d-" % len(self.configs)
        nodes = {tag + "H": {"kind": "H", "parent": None, "child": tag + "M"},
                 tag + "M": {"kind": "M", "parent": tag + "H", "child": None}}
        if siblings:
            nodes[tag + "W"] = {"kind": "W", "parent": tag + "H", "child": None}
        sidecars = {tag + "H": [tag + "W"]} if siblings else {}
        config = self.make_config(nodes, ignore=stubborn, sidecars=sidecars)
        try:
            root = self.custody.launch(config, tag + "H", self.env)
            family = {"H": self.admit(tag + "H", root, argv, sidecars.get(tag + "H", ()))}
            for label in (("M", "W") if siblings else ("M",)):
                slot = tag + label
                self.custody.await_event(slot, "hello")
                child = R2OwnedChild(self.custody, slot)
                family[label] = self.admit(slot, child, named_child if label == "M" else None)
            return family
        except BaseException:
            self.close()
            raise

    def make_config(self, nodes, **extra):
        self.custody.plan(nodes)
        path = self.launch.tmp / ("actor-%d.json" % len(self.configs))
        self.configs.append(path)
        return self.custody.config(nodes, self.script, path, exit_file=str(path.with_suffix(".exit")), **extra)

    def spawn_legacy(self, argv, logical_argv, body, environment):
        """Known launch request plus private gate; modelled argv is supplied explicitly by the caller."""
        from tests.integration.hierarchy_fake_wrapper import python_argv

        tag = "actor%d-legacy" % len(self.configs)
        nodes = {tag: {"kind": "H", "parent": None, "child": None}}
        config = self.make_config(nodes)
        script = self.launch.tmp / (tag + ".py")
        prelude = (
            "import os, json, sys, runpy\nfrom pathlib import Path\n"
            "control = Path(os.environ['R2_LEGACY_CONFIG'])\n"
            "if any(p.is_symlink() for p in (control, *control.parents)):\n"
            "    raise RuntimeError('R2 fixture: linked legacy control input')\n"
            "configuration = json.loads(control.read_text())\n"
            "sys.path.insert(0, configuration['trusted_root'])\n"
            "runpy.run_path(configuration['helper'])['r2_legacy_child_gate'](configuration, os.environ['R2_LEGACY_SLOT'])\n"
        )
        script.write_text(prelude + body, encoding="utf-8")
        requested = Path(argv[0])
        directory = requested.parent if self.launch.tmp in requested.parents else self.launch.tmp
        command = [*python_argv(requested.name, script, directory), *argv[1:]]
        env = {**self.env, **environment, "R2_LEGACY_CONFIG": config["config"], "R2_LEGACY_SLOT": tag}
        try:
            process = self.custody.launch(config, tag, env, argv=command, cwd=self.launch.tmp)
            self.admit(tag, process, logical_argv)
            return process
        except BaseException:
            self.close()
            raise

    def spawn_exec(self, argv, logical_argv, expected_argv, environment=None, cwd=None,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   captured=(), target=None):
        """Actual harness exec, explicit MODELLED logical atoms; exact constructor bytes witness readiness.

        Neither program names nor the production matcher discover this receipt. Physical custody precedes
        exec, and keeps its original handle through every pending/READY failure and natural exit.
        """
        import time

        if (not isinstance(expected_argv, (list, tuple)) or not expected_argv or
                not all(isinstance(word, str) and "\0" not in word for word in expected_argv)):
            raise RuntimeError("R2 fixture: an exact actual-exec array is required")
        tag = "actor%d-exec" % len(self.configs)
        nodes = {tag: {"kind": "H", "parent": None, "child": None}}
        specs = {}
        for index, spec in enumerate(captured):
            if set(spec) != {"argv", "expected_argv", "logical_argv"}:
                raise RuntimeError("R2 fixture: invalid declared captured child")
            slot = tag + "-child%d" % index
            nodes[slot] = {"kind": "M", "parent": tag, "child": None}
            specs[slot] = spec
        extra = {"exec_argv": list(argv), "exec_slot": tag, "capture_specs": specs,
                 "exec_children": {slot: spec["argv"] for slot, spec in specs.items()}}
        if target is not None:
            import hashlib
            path, entry = target
            extra["capture_target"] = {"path": str(path), "entry": entry,
                                       "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
        config = self.make_config(nodes, **extra)
        for slot, spec in specs.items():
            self.exec_children[slot] = {"spec": spec, "state": "RESERVED"}
        env = {key: value for key, value in {**self.env, **(environment or {})}.items()
               if key not in ("CLAUDECODE", "CLAUDE_PID") and not key.startswith("CLAUDE_CODE_")}
        if target is not None:
            env["R2_CAPTURE_CONFIG"] = config["config"]
        expected = b"\0".join(os.fsencode(word) for word in expected_argv) + b"\0"
        try:
            process = self.custody.launch(config, tag, env, cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr)
            self.children.append(process)
            self.custody.await_event(tag, "hello")
            self.projection.pending(process)
            self.custody.release(tag)
            self.custody.await_event(tag, "running")
            deadline = time.monotonic() + 3
            while True:
                self.service_exec_children()
                if self.custody.observe(tag) is not None:
                    self.retire_pending_exit(process, tag)
                    return process
                try:
                    physical = r2_kernel_process(process.pid)
                    if physical["raw"] == expected:
                        self.projection.ready(process, logical_argv)
                        return process
                except (FileNotFoundError, RuntimeError):
                    receipt = self.projection.receipts.get(str(process.pid))
                    if (receipt is None or receipt["state"] != "PENDING" or
                            self.custody.observe(tag) is None):
                        raise
                    self.retire_pending_exit(process, tag)
                    return process
                if time.monotonic() >= deadline:
                    raise RuntimeError("R2 fixture: actual exec handshake failed\n" + self.custody.stderr_tail())
                time.sleep(0.01)
        except BaseException:
            self.close()
            raise

    def service_exec_children(self):
        from tests.integration.test_hierarchy_launcher import R2OwnedChild

        self.custody.pump()
        ready = False
        for slot, item in self.exec_children.items():
            if not self.custody.slots[slot]["hello"]:
                continue
            child = R2OwnedChild(self.custody, slot)
            if item["state"] == "RESERVED":
                self.projection.pending(child)
                item["state"] = "PENDING"
                self.custody.release(slot)
            if item["state"] != "PENDING":
                ready = True
                continue
            if self.custody.observe(slot) is not None:
                self.retire_pending_exit(child, slot)
                item["state"] = "EXITED"
                ready = True
                continue
            physical = r2_kernel_process(child.pid)
            expected = b"\0".join(os.fsencode(word) for word in item["spec"]["expected_argv"]) + b"\0"
            if physical["raw"] == expected:
                self.projection.ready(child, item["spec"]["logical_argv"])
                item["state"] = "READY"
                ready = True
        return ready

    def retire_pending_exit(self, process, slot):
        receipt = self.projection.receipts.get(str(process.pid))
        if (receipt is None or receipt["state"] != "PENDING" or
                self.custody.observe(slot) is None):
            raise RuntimeError("R2 fixture: pending exit needs original-instance exit evidence")
        # No positive reader has seen this pending input. Its physical exit stays in custody; a missing
        # metadata read alone can never retire it or turn it into a READY/native projection.
        del self.projection.receipts[str(process.pid)]
        self.projection.save()

    def admit(self, slot, process, argv, sidecars=()):
        self.children.append(process)
        self.custody.await_event(slot, "hello")
        self.projection.pending(process)
        self.projection.ready(process, argv)
        for child in sidecars:
            if (len(sidecars) != 1 or child not in self.custody.slots or
                    self.custody.slots[child]["parent"] != slot or
                    self.custody.slots[slot]["kind"] != "H" or self.custody.slots[child]["child"] is not None):
                raise RuntimeError("R2 fixture: invalid reserved sibling")
            self.custody.slots[child]["permitted"] = True
        self.custody.release(slot)
        self.custody.await_event(slot, "running")
        return process

    def runner(self, session=None, action="stop", timeout=R2_STOP_TIMEOUT_SECONDS, stop_words=None, echo_exit=False):
        from tests.integration.test_hierarchy_launcher import R2OwnedChild
        from tests.integration.hierarchy_fake_wrapper import python_argv
        tag = "actor%d-" % len(self.configs)
        words = stop_words if stop_words is not None else ("stop", "--endpoint", REVIEW, "--grace-seconds", "1")
        request = self.projection.command("--base", str(self.launch.base), *words)
        nodes = {tag + "R": {"kind": "R", "parent": tag + "C" if session else None, "child": None}}
        if session:
            nodes[tag + "C"] = {"kind": "C", "parent": None, "child": tag + "R"}
        config = self.make_config(nodes, runner_request=request, runner_action=action, runner_timeout=timeout,
                                  echo_exit=echo_exit)
        root_slot = tag + ("C" if session else "R")
        command = ([*python_argv("codex", self.script, self.launch.tmp), config["config"], root_slot, session]
                   if session else None)
        try:
            root = self.custody.launch(config, root_slot, self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       argv=command)
            root.capture_trace_path = self.launch.tmp / ("capture-%d-evidence.json" % root.pid)
            root.capture_event("captured")
            root.start_capture()
            root.wait_observer = lambda: [child.poll() for child in self.children if child is not root]
            self.admit(root_slot, root, ["codex", "exec", "resume", session] if session else None)
            if session:
                self.custody.await_event(tag + "R", "hello")
                child = R2OwnedChild(self.custody, tag + "R")
                self.admit(tag + "R", child, None)
            else:
                child = root
            return root, child
        except BaseException:
            self.close()
            raise

    def module(self, pidfds=True):
        import errno

        self.projection.group_observer = lambda: [child.poll() for child in self.children]
        module = launcher_module(self.projection)
        if pidfds:
            if not (hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")):
                raise RuntimeError("R2 fixture prerequisite: Linux pidfd APIs required for this selected case")
            # Qualify the host capability on our own instance, independently of the product path being tested.
            target = self.children[0].pid if self.children else os.getpid()
            try:
                fd = os.pidfd_open(target)
                try:
                    signal.pidfd_send_signal(fd, 0)
                finally:
                    os.close(fd)
            except OSError as exc:
                raise RuntimeError("R2 fixture prerequisite: actual pidfd capability failed: " + str(exc)) from exc
        else:
            def unavailable(*args):
                raise OSError(errno.ENOSYS, "modelled pidfd unavailability")
            module.os.pidfd_open = unavailable
        module.KILL_WAIT_SECONDS = 1
        return module

    def stop(self, module, capsys, grace=1):
        code = module.main(["--base", str(self.launch.base), "stop", "--endpoint", REVIEW,
                            "--grace-seconds", str(grace)])
        return code, json.loads(capsys.readouterr().out)

    def ps(self, module, process, argv):
        """MODELLED flattened ps at a module-local subprocess boundary; real PID/UID/PPID/group stay actual."""
        from types import SimpleNamespace

        run = module.subprocess.run
        self.projection.path_view(module, proc_available=False)

        def shown(command, **options):
            if "-o" not in command or "args=" not in command[command.index("-o") + 1]:
                return run(command, **options)
            if process is None or process.poll() is not None:
                return SimpleNamespace(returncode=1 if "-p" in command else 0, stdout="")
            physical = r2_kernel_process(process.pid)
            text = "%d %d %d %d %d %s Sat Nov 7 12:00:00 2026 %s\n" % (
                process.pid, physical["pgid"], physical["ppid"], physical["uid"], physical["euid"],
                physical["state"], " ".join(argv))
            return SimpleNamespace(returncode=0, stdout=text)
        module.subprocess.run = shown

    def close(self):
        return self.custody.close()


@pytest.fixture
def r2_case(launch):
    try:
        made = R2Case(launch)
    except R2CleanupUnknown as exc:
        pytest.exit("R2 fixture UNKNOWN: " + str(exc), returncode=3)
    try:
        yield made
    finally:
        try:
            made.close()
        except R2CleanupUnknown as exc:
            pytest.exit("R2 fixture UNKNOWN: " + str(exc), returncode=3)


@pytest.mark.parametrize("pidfds", [True, False], ids=["pidfd", "start-time"])
@pytest.mark.parametrize("field", ["stat", "status", "cmdline"])
def test_r2_unavailable_before_first_signal_keeps_live_candidate(r2_case, capsys, pidfds, field):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(pidfds)
    stage, faults = [], []
    opening = module.os.pidfd_open

    def opened(pid, *args):
        try:
            return opening(pid, *args)
        finally:
            if pid == held.pid:
                stage.append("recheck")  # The actual pidfd or ENOSYS fallback boundary preceded this fault.

    def unavailable(path, physical):
        if stage and str(path) == "/proc/%d/%s" % (held.pid, field):
            faults.append(field)
            raise PermissionError("modelled unavailable evidence before first signal")
        return physical

    module.os.pidfd_open = opened
    r2_case.projection.path_view(module, unavailable)
    code, stopped = r2_case.stop(module, capsys)
    assert stage and faults, "fixture prerequisite: the census and targeted recheck must both execute"
    assert any(pid == held.pid for pid, _ in r2_case.projection.opens) is pidfds, "fixture prerequisite: requested pidfd/fallback mode was actually used"
    assert held.poll() is None and r2_case.projection.events == []
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == []
    assert stopped.get("unresolved_pids") == [held.pid]
    assert "unavailable" in json.dumps(stopped)


@pytest.mark.parametrize("provider", ["proven", "unproven"])
@pytest.mark.parametrize("side", ["left", "right"])
@pytest.mark.parametrize("collision", ["claude-prompt", "claude-system", "codex-cd", "codex-builder"])
def test_r2_flatten_identical_arrays_do_not_share_ownership(r2_case, capsys, provider, side, collision):
    from hierarchy_provision import codex_argv

    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    host = "claude-code" if collision.startswith("claude") else "codex-cli"
    role = r2_case.bind(host, session)
    if collision == "claude-prompt":
        pair = (["claude", "--print", "Please --resume " + session],
                ["claude", "--print", "Please", "--resume", session])
    elif collision == "claude-system":
        pair = (["claude", "--print", "--system-prompt", "Explain --resume " + session + " carefully"],
                ["claude", "--print", "--system-prompt", "Explain", "--resume", session, "carefully"])
    elif collision == "codex-cd":
        pair = (["codex", "--cd", "resume " + other, "exec", "resume " + session],
                ["codex", "--cd", "resume " + other + " exec", "resume", session])
    else:
        prefix = codex_argv(json.loads(Path(role["codex_profile"]).read_text()))
        pair = (prefix + ["resume " + session], prefix + ["resume", session])
    assert pair[0] != pair[1] and " ".join(pair[0]) == " ".join(pair[1])
    argv = pair[side == "right"]
    held = r2_case.spawn(argv)
    module = r2_case.module()
    if provider == "unproven":
        r2_case.ps(module, held, argv)
    code, stopped = r2_case.stop(module, capsys)
    if provider == "unproven":
        assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == []
        assert stopped["argv_boundaries"] == "unproven" and stopped["unowned_pids"] == [held.pid]
        assert held.poll() is None and r2_case.projection.events == []
    elif side == "left":
        assert code == 0 and stopped["state"] == "not_running" and stopped["pids"] == []
        assert held.poll() is None and r2_case.projection.events == []
    else:
        assert code == 0 and stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM


def test_r2_exact_round7_prompt_is_only_lossy_diagnostic_evidence(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    argv = ["claude", "--print", "Please --resume " + session + " now"]
    held = r2_case.spawn(argv)
    module = r2_case.module()
    r2_case.ps(module, held, argv)
    code, stopped = r2_case.stop(module, capsys)
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == []
    assert stopped["unowned_pids"] == [held.pid] and held.poll() is None
    assert r2_case.projection.events == []


def test_r2_actual_codex_builder_keeps_single_word_resume_prompt(r2_case, capsys):
    from hierarchy_provision import codex_argv

    session = str(uuid.uuid4())
    role = r2_case.bind("codex-cli", session)
    argv = codex_argv(json.loads(Path(role["codex_profile"]).read_text()), ["resume", session, "resume"])
    held = r2_case.spawn(argv)
    code, stopped = r2_case.stop(r2_case.module(), capsys)
    assert code == 0 and stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("which", ["start", "wake"])
def test_r2_actual_claude_builder_arrays_remain_stoppable(r2_case, capsys, which):
    session = str(uuid.uuid4())
    role = r2_case.bind("claude-code", session)
    argv = role["start_argv"] if which == "start" else json.loads(Path(role["wake_profile"]).read_text())["argv"]
    held = r2_case.spawn(argv)
    code, stopped = r2_case.stop(r2_case.module(), capsys)
    assert code == 0 and stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_r2_empty_lossy_provider_cannot_prove_no_targets(r2_case, capsys):
    r2_case.bind("claude-code", str(uuid.uuid4()))
    module = r2_case.module()
    r2_case.ps(module, None, [])
    code, stopped = r2_case.stop(module, capsys)
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == []
    assert stopped["argv_boundaries"] == "unproven" and r2_case.projection.events == []


@pytest.mark.parametrize("pidfds", [True, False], ids=["pidfd", "start-time"])
@pytest.mark.parametrize("drift", [None, "cmdline", "birth", "uid", "unavailable", "named-session"])
def test_r2_real_descendant_chain_retains_attempts_after_middle_exit(r2_case, capsys, pidfds, drift):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, middle, worker = (family[label] for label in ("H", "M", "W"))
    module = r2_case.module(pidfds)
    term_done = []

    def signalled(pid, number):
        if pid == middle.pid and number == signal.SIGTERM:
            wait_until(lambda: middle.poll() is not None)
        if pid == host.pid and number == signal.SIGTERM:
            assert middle.poll() is not None
            term_done.append(True)

    def modelled_drift(pid, count, row):
        if term_done and pid == worker.pid:
            if drift == "cmdline":
                return row._replace(cmdline=row.cmdline + b"modelled-change\0")
            if drift == "named-session":
                word = "--session-id=" + session
                return row._replace(cmdline=row.cmdline + word.encode() + b"\0", argv=(*row.argv, word))
            if drift == "birth":
                return row._replace(start_time=str(int(row.start_time) + 1))
            if drift == "uid":
                return row._replace(uid=os.geteuid() + 1, euid=os.geteuid() + 1)
        return row

    def unavailable(path, physical):
        if term_done and drift == "unavailable" and str(path) == "/proc/%d/cmdline" % worker.pid:
            raise PermissionError("modelled attempted worker evidence unavailable")
        return physical

    r2_case.projection.after_signal.append(signalled)
    r2_case.projection.after_present.append(modelled_drift)
    r2_case.projection.path_view(module, unavailable)
    code, stopped = r2_case.stop(module, capsys)
    assert term_done, "fixture prerequisite: H was attempted after the real M exit"
    assert any(pid == worker.pid for pid, _ in r2_case.projection.opens) is pidfds, "fixture prerequisite: requested worker instance-handle mode was actually used"
    assert stopped["pids"] == sorted(child.pid for child in family.values())
    assert not set(stopped["pids"]) & set(stopped.get("unowned_pids", []))
    if drift is None:
        assert code == 0 and stopped["state"] == "stopped" and worker.poll() is not None
        assert (worker.pid, signal.SIGKILL) in r2_case.projection.events
    else:
        assert code == 3 and stopped["state"] == "stop_failed" and worker.poll() is None
        assert worker.pid in stopped.get("unresolved_pids", [])
        assert (worker.pid, signal.SIGKILL) not in r2_case.projection.events
        if drift in ("cmdline", "named-session"):
            assert any(row.get("signal_refusal") == "signal_command_line_not_authorized" for row in stopped["unresolved"])
    assert host.wait(timeout=5) == -signal.SIGKILL


def test_r2_projection_contract_preserves_real_evidence(r2_case):
    session = str(uuid.uuid4())
    logical = ["claude", "--resume", session]
    held = r2_case.spawn(logical)
    entry = next(e for e in r2_case.custody.entries.values() if e["pid"] == held.pid)
    if entry["fd"] is None or not entry["verified_fd"] or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("R2 fixture prerequisite: original verified pidfd required for physical sampling")
    controls = []
    try:
        # Private physical custody, not a PUBLIC stop attempt or a modelled state. R/S can legitimately
        # change between samples; holding our original instance in T preserves every comparison below.
        r2_case.projection.authorize(held.pid)
        signal.pidfd_send_signal(entry["fd"], signal.SIGSTOP)
        controls.append(int(signal.SIGSTOP))
        wait_until(lambda: r2_kernel_process(held.pid)["state"] == "T")
        physical = r2_kernel_process(held.pid)
        read_bytes, kill, send = Path.read_bytes, os.kill, getattr(signal, "pidfd_send_signal", None)
        module = r2_case.module()
        observation = module.read_process(held.pid)
        row = getattr(observation, "snapshot", observation)
        assert row.argv == tuple(logical)
        assert row.pid == held.pid and row.cmdline == physical["raw"] and row.start_time == physical["birth"]
        assert (row.uid, row.euid, row.ppid, row.pgid, row.state) == (
            physical["uid"], physical["euid"], physical["ppid"], physical["pgid"], physical["state"])
        assert Path.read_bytes is read_bytes and os.kill is kill and getattr(signal, "pidfd_send_signal", None) is send
        assert module.os is not os and module.signal is not signal and module.subprocess is not subprocess
        assert "--resume" not in [os.fsdecode(word) for word in physical["raw"].split(b"\0")]
    finally:
        r2_case.projection.authorize(held.pid)
        signal.pidfd_send_signal(entry["fd"], signal.SIGCONT)
        controls.append(int(signal.SIGCONT))
        (r2_case.launch.tmp / "r19-private-state-evidence.json").write_text(json.dumps({
            "pid": held.pid, "birth": entry["birth"], "verified_original_pidfd": True,
            "private_fixture_signals": controls, "public_signals": r2_case.projection.events}))


def test_r2_legacy_child_keeps_physical_argv_and_independent_custody(r2_case):
    session = str(uuid.uuid4())
    logical = ["codex", "exec", "resume", session]
    ready = r2_case.launch.tmp / "legacy-ready"
    held = r2_case.spawn_legacy([str(r2_case.launch.tmp / "codex"), "-c", CHILD, "resume", session], logical,
                                CHILD, {"STOP_OWNERSHIP_READY": str(ready)})
    wait_until(ready.exists)
    physical = r2_kernel_process(held.pid)
    assert Path(os.fsdecode(physical["raw"].split(b"\0")[0])).name == "codex"
    assert physical["raw"].split(b"\0")[:-1] == [os.fsencode(word) for word in held.args]
    module = r2_case.module()
    observation = module.read_process(held.pid)
    row = getattr(observation, "snapshot", observation)
    assert row.argv == tuple(logical) and row.cmdline == physical["raw"]
    assert (row.start_time, row.uid, row.euid) == (physical["birth"], physical["uid"], physical["euid"])
    report = r2_case.close()
    assert report["state"] == "CLOSED" and all(entry["exit"] for entry in report["entries"].values())
    assert held.wait(timeout=5) == 0 and r2_case.projection.events == []


@pytest.mark.parametrize("pidfds", [True, False], ids=["pidfd", "start-time"])
def test_r2_post_signal_empty_cmdline_retains_the_live_attempt(r2_case, capsys, pidfds):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module = r2_case.module(pidfds)
    terms, negatives = [], []

    def signalled(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            terms.append(pid)  # The facade calls this only after the real public signal returns.

    def empty_after_term(path, physical):
        if terms and str(path) == "/proc/%d/cmdline" % held.pid:
            negatives.append(physical)
            return b""  # MODELLED OS observation; the TERM-ignoring physical child remains alive.
        return physical

    r2_case.projection.after_signal.append(signalled)
    r2_case.projection.path_view(module, empty_after_term)
    code, stopped = r2_case.stop(module, capsys)
    assert terms == [held.pid] and negatives and all(negatives)
    assert any(pid == held.pid for pid, _ in r2_case.projection.opens) is pidfds
    assert held.poll() is None and r2_kernel_process(held.pid)["raw"]
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == [held.pid]
    assert held.pid not in stopped.get("unowned_pids", [])
    assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    observation = module.read_process(held.pid)
    row = getattr(observation, "snapshot", observation)
    physical = r2_kernel_process(held.pid)
    assert row.cmdline == b"" and row.argv == () and not row.state.startswith("Z")
    assert (row.pid, row.start_time, row.uid, row.euid, row.ppid, row.pgid) == (
        held.pid, physical["birth"], physical["uid"], physical["euid"], physical["ppid"], physical["pgid"])
    report = r2_case.close()  # Independent physical custody, never another production attempt.
    assert report["state"] == "CLOSED" and all(entry["exit"] for entry in report["entries"].values())
    assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]


@pytest.mark.parametrize("tamper", ["never-verified", "other-module", "pending", "birth", "digest",
                                     "argv", "structure", "missing"])
def test_r2_empty_cmdline_requires_the_same_module_verified_receipt(r2_case, tamper):
    session = str(uuid.uuid4())
    logical = ["claude", "--resume", session]
    held = r2_case.spawn(logical, ignore=True)
    module = r2_case.module()
    if tamper != "never-verified":
        observation = module.read_process(held.pid)
        row = getattr(observation, "snapshot", observation)
        assert row.argv == tuple(logical) and row.cmdline == r2_kernel_process(held.pid)["raw"]
    if tamper == "other-module":
        module = r2_case.module()  # A different loaded module has no verified receipt fingerprint.
    receipt = r2_case.projection.receipts[str(held.pid)]
    if tamper == "pending":
        receipt["state"] = "PENDING"
    elif tamper == "birth":
        receipt["birth"] = str(int(receipt["birth"]) + 1)
    elif tamper == "digest":
        receipt["digest"] = "0" * 64
    elif tamper == "argv":
        receipt["argv"] = ["claude", "--resume", str(uuid.uuid4())]
    elif tamper == "structure":
        receipt["unexpected"] = "modelled receipt tamper"
    elif tamper == "missing":
        del r2_case.projection.receipts[str(held.pid)]

    def empty(path, physical):
        return b"" if str(path) == "/proc/%d/cmdline" % held.pid else physical

    r2_case.projection.path_view(module, empty)
    with pytest.raises(RuntimeError, match="^R2 fixture: stale/unknown projection receipt; no native fallback$"):
        module.read_process(held.pid)
    assert held.poll() is None and r2_kernel_process(held.pid)["raw"]
    assert r2_case.projection.events == []


def test_r2_modelled_other_uid_is_spared_without_any_attempt(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module()

    def modelled_other_uid(pid, count, row):
        return row._replace(uid=os.geteuid() + 1, euid=os.geteuid() + 1) if pid == held.pid else row

    r2_case.projection.after_present.append(modelled_other_uid)
    code, stopped = r2_case.stop(module, capsys)
    assert code == 0 and stopped["state"] == "not_running" and stopped["pids"] == []
    assert stopped["unowned_pids"] == [held.pid] and held.poll() is None
    assert r2_case.projection.events == []


def test_r2_projection_contract_refuses_unknown_pending_and_stale_receipts(r2_case):
    held = r2_case.spawn(["claude", "--resume", str(uuid.uuid4())])
    module = r2_case.module()
    receipt = r2_case.projection.receipts[str(held.pid)]
    try:
        del r2_case.projection.receipts[str(held.pid)]
        with pytest.raises(RuntimeError, match="^R2 fixture: attempted signal outside the owned receipt set$"):
            module.os.kill(held.pid, signal.SIGTERM)
        assert held.poll() is None
    finally:
        r2_case.projection.receipts[str(held.pid)] = receipt
    for field, invalid in (("state", "PENDING"), ("birth", "unrecognized"), ("digest", "0" * 64)):
        original = receipt[field]
        try:
            receipt[field] = invalid
            with pytest.raises(RuntimeError, match="^R2 fixture: stale/unknown projection receipt; no native fallback$"):
                module.read_process(held.pid)
            assert held.poll() is None and r2_case.projection.events == []
        finally:
            receipt[field] = original


def test_r2_projection_contract_does_not_upgrade_ps_text(r2_case):
    session = str(uuid.uuid4())
    argv = ["claude", "--print", "Please --resume " + session + " now"]
    held = r2_case.spawn(argv)
    physical = r2_kernel_process(held.pid)
    module = r2_case.module()
    r2_case.ps(module, held, argv)
    census = module.process_census(session)
    assert census.argv_boundaries == "unproven" and len(census) == 1
    row = census[0]
    assert row.pid == held.pid and row.cmdline == os.fsencode(" ".join(argv))
    assert row.cmdline != physical["raw"]
    assert (row.uid, row.euid, row.ppid, row.pgid) == (
        physical["uid"], physical["euid"], physical["ppid"], physical["pgid"])
    assert held.poll() is None and r2_case.projection.events == []


def test_r2_projection_contract_confines_unavailable_read_to_the_loaded_module(r2_case):
    held = r2_case.spawn(["claude", "--resume", str(uuid.uuid4())])
    module = r2_case.module()
    original = Path.read_bytes

    def unreadable(path, physical):
        if str(path) == "/proc/%d/cmdline" % held.pid:
            raise PermissionError("modelled fixture reader fault")
        return physical

    r2_case.projection.path_view(module, unreadable)
    observation = module.read_process(held.pid)
    assert observation is None or getattr(observation, "kind", None) == "UNAVAILABLE"
    assert Path.read_bytes is original and r2_kernel_process(held.pid)["raw"]
    assert held.poll() is None and r2_case.projection.events == []


@pytest.mark.parametrize("pidfds", [True, False], ids=["pidfd", "start-time"])
def test_r2_confirmed_exit_before_first_signal_resolves_candidate(r2_case, capsys, pidfds):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(pidfds)
    confirmed = []

    def before(pid, count):
        if pid == held.pid and count == 2:
            r2_case.configs[0].with_suffix(".exit").touch()
            assert held.wait(timeout=5) == 0  # Real child wait proves the original instance exited.
            confirmed.append(True)

    r2_case.projection.before_read.append(before)
    code, stopped = r2_case.stop(module, capsys)
    assert confirmed and r2_case.projection.events == []
    assert code == 0 and stopped["state"] == "not_running" and stopped["pids"] == []
    assert not stopped.get("unresolved_pids")


@pytest.mark.parametrize("pidfds", [True, False], ids=["pidfd", "start-time"])
@pytest.mark.parametrize("field", ["cmdline", "birth", "uid"])
def test_r2_metadata_drift_before_first_signal_spares_live_candidate(r2_case, capsys, pidfds, field):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module(pidfds)
    changed = []

    def modelled(pid, count, row):
        if pid == held.pid and count >= 2:
            changed.append(field)
            if field == "cmdline":
                return row._replace(cmdline=row.cmdline + b"modelled-exec-change\0")
            if field == "birth":
                return row._replace(start_time=str(int(row.start_time) + 1))
            return row._replace(uid=os.geteuid() + 1, euid=os.geteuid() + 1)
        return row

    r2_case.projection.after_present.append(modelled)
    code, stopped = r2_case.stop(module, capsys)
    if field == "cmdline":
        assert changed and code == 0 and stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
        assert held.wait(timeout=5) == -signal.SIGTERM
        assert r2_case.projection.events == [(held.pid, signal.SIGTERM)]
        return
    assert changed and held.poll() is None and r2_case.projection.events == []
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == []
    assert stopped.get("unresolved_pids") == [held.pid]


@pytest.mark.parametrize("pidfds", [True, False], ids=["pidfd", "start-time"])
@pytest.mark.parametrize("field", ["birth", "ppid"])
def test_r2_parent_chain_drift_blocks_first_descendant_signal(r2_case, capsys, pidfds, field):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, middle, worker = (family[label] for label in ("H", "M", "W"))
    module = r2_case.module(pidfds)
    changed = []

    def modelled(pid, count, row):
        if pid == middle.pid and count >= 2:
            changed.append(field)
            return (row._replace(start_time=str(int(row.start_time) + 1)) if field == "birth"
                    else row._replace(ppid=os.getpid()))
        return row

    r2_case.projection.after_present.append(modelled)
    code, stopped = r2_case.stop(module, capsys)
    assert changed and middle.poll() is None and worker.poll() is None
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == [host.pid]
    assert set(stopped.get("unresolved_pids", [])) == {middle.pid, worker.pid}
    assert all(pid == host.pid for pid, _ in r2_case.projection.events)
    assert host.wait(timeout=5) == -signal.SIGKILL


@pytest.mark.parametrize("argument", ["<T>", "--unlisted=<T>", "-r<T>", "-r", "ambiguous"])
def test_r2_real_descendant_with_other_or_ambiguous_selection_is_spared(r2_case, capsys, argument):
    # -r is modelled, not observed. This negative guard never establishes root ownership.
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    argv = (["claude", "--resume", "--print", "wait"] if argument == "ambiguous" else
            ["claude", "-r", other] if argument == "-r" else
            ["claude", argument.replace("<T>", other)])
    family = r2_case.spawn(["claude", "--resume", session], tree=True, worker_argv=argv)
    host, worker = family["H"], family["W"]
    code, stopped = r2_case.stop(r2_case.module(), capsys)
    assert code == 3 and stopped["state"] == "stop_failed" and worker.poll() is None
    assert worker.pid not in stopped["pids"] and worker.pid not in stopped.get("unowned_pids", [])
    assert worker.pid in stopped["unresolved_pids"]
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)
    assert host.wait(timeout=5) == -signal.SIGKILL


def test_r2_initial_unavailable_descendant_cannot_disappear_from_accounting(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    family = r2_case.spawn(["claude", "--resume", session], tree=True)
    host, middle, worker = (family[label] for label in ("H", "M", "W"))
    module, missing = r2_case.module(), []

    def missing_uid(path, physical):
        if str(path) == "/proc/%d/status" % worker.pid:
            missing.append(True)
            # MODELLED incomplete metadata, while real PPID/birth/raw argv and independent custody remain.
            return b"\n".join(line for line in physical.splitlines() if not line.startswith(b"Uid:"))
        return physical

    r2_case.projection.path_view(module, missing_uid)
    code, stopped = r2_case.stop(module, capsys)
    assert missing and worker.poll() is None
    assert code == 3 and stopped["state"] == "stop_failed"
    assert stopped["pids"] == sorted([host.pid, middle.pid])
    assert stopped.get("unresolved_pids") == [worker.pid]
    assert worker.pid not in stopped.get("unowned_pids", [])
    assert all(pid != worker.pid for pid, _ in r2_case.projection.events)
    assert host.wait(timeout=5) == -signal.SIGKILL


def test_r2_complete_descendant_prompt_resume_remains_opaque(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    # MODELLED complete Codex argv; the final atom is its owner's prompt, not a missing selector.
    family = r2_case.spawn(["claude", "--resume", session], tree=True,
                           worker_argv=["codex", "exec", "resume", session, "resume"])
    host, middle, worker = (family[label] for label in ("H", "M", "W"))
    code, stopped = r2_case.stop(r2_case.module(), capsys)
    assert code == 0 and stopped["state"] == "stopped"
    assert stopped["pids"] == sorted([host.pid, middle.pid, worker.pid])
    assert "unresolved_pids" not in stopped and "unowned_pids" not in stopped
    assert (worker.pid, signal.SIGKILL) in r2_case.projection.events and worker.poll() is not None
    assert host.wait(timeout=5) == -signal.SIGKILL


def test_r2_initial_incomplete_candidate_resolves_on_its_actual_zombie(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    host = r2_case.spawn(["claude", "--resume", session])
    worker = r2_case.spawn()
    module, exited = r2_case.module(), []

    def missing_uid(path, physical):
        if str(path) == "/proc/%d/status" % worker.pid:
            return b"\n".join(line for line in physical.splitlines() if not line.startswith(b"Uid:"))
        return physical

    def exit_original(pid, count):
        if pid == worker.pid and count == 2:
            r2_case.configs[1].with_suffix(".exit").touch()
            # Observe a real unreaped zombie, without manufacturing absence or polling Popen's cached status.
            wait_until(lambda: r2_kernel_process(worker.pid)["state"].startswith("Z"))
            exited.append(True)

    r2_case.projection.path_view(module, missing_uid)
    r2_case.projection.before_read.append(exit_original)
    code, stopped = r2_case.stop(module, capsys)
    assert exited and worker.wait(timeout=5) == 0
    assert host.wait(timeout=5) == -signal.SIGTERM
    assert code == 0 and stopped["state"] == "stopped" and stopped["pids"] == [host.pid]
    assert "unresolved_pids" not in stopped and "unowned_pids" not in stopped
    assert r2_case.projection.events == [(host.pid, signal.SIGTERM)]


def test_r2_numeric_esrch_cannot_resolve_a_previously_lost_attempt(r2_case, capsys):
    import errno

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module = r2_case.module(pidfds=False)
    terms, drifted, missing = [], [], []

    def signalled(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            terms.append(True)

    def replacement(pid, count, row):
        if pid == held.pid and terms:
            # MODELLED reused-PID observation, not a claim that the physical test actor changed identity.
            drifted.append(True)
            return row._replace(start_time=str(int(row.start_time) + 1))
        return row

    def opening(pid, *args):
        if pid == held.pid and drifted:
            missing.append(pid)
            # MODELLED later numeric absence: it cannot recover the already-lost original-instance proof.
            raise ProcessLookupError(errno.ESRCH, "modelled numeric PID disappeared after identity loss")
        raise OSError(errno.ENOSYS, "modelled initial pidfd unavailability")

    module.os.pidfd_open = opening
    r2_case.projection.after_signal.append(signalled)
    r2_case.projection.after_present.append(replacement)
    code, stopped = r2_case.stop(module, capsys, grace=0)
    assert terms and drifted and missing, "fixture prerequisite: attempted, lost identity, then numeric ESRCH"
    assert held.poll() is None and r2_case.projection.events == [(held.pid, signal.SIGTERM)]
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == [held.pid]
    assert stopped.get("unresolved_pids") == [held.pid] and held.pid not in stopped.get("unowned_pids", [])
    assert all(row["pid"] != held.pid for row in stopped.get("absence_evidence", []))


@pytest.mark.parametrize("stage", ["before_signal", "after_signal"])
@pytest.mark.parametrize("missing_field", ["status", "cmdline"])
def test_r2_partial_replacement_birth_cannot_be_resolved_by_numeric_absence(r2_case, capsys, stage, missing_field):
    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module = r2_case.module(pidfds=False)
    terms, drift, absent = [], [], []
    killing = module.os.kill

    def before_read(pid, count):
        if pid == held.pid and ((stage == "before_signal" and count >= 2) or terms):
            drift.append(True)

    def incomplete(path, raw):
        if path.parent == Path("/proc/%d" % held.pid) and drift:
            # MODELLED coherent replacement birth plus unavailable status/cmdline at the OS boundary.
            if path.name == "stat":
                head, separator, tail = raw.rpartition(b")")
                fields = tail.split()
                fields[19] = str(int(fields[19]) + 1).encode()
                return head + separator + b" " + b" ".join(fields)
            if path.name == missing_field:
                raise PermissionError("modelled replacement metadata unavailable")
        return raw

    def numeric_absence(pid, number):
        if pid == held.pid and number == 0 and drift:
            absent.append(pid)
            if len(absent) >= 2:
                raise ProcessLookupError("modelled later numeric absence")
        return killing(pid, number)

    r2_case.projection.before_read.append(before_read)
    r2_case.projection.after_signal.append(lambda pid, number: terms.append(pid)
                                          if pid == held.pid and number == signal.SIGTERM else None)
    r2_case.projection.path_view(module, incomplete)
    module.os.kill = numeric_absence
    code, stopped = r2_case.stop(module, capsys, grace=0)
    expected = [held.pid] if stage == "after_signal" else []
    assert drift and len(absent) >= 2, "fixture prerequisite: coherent partial birth, then numeric absence"
    assert held.poll() is None and r2_case.projection.events == ([(held.pid, signal.SIGTERM)] if expected else [])
    assert code == 3 and stopped["state"] == "stop_failed" and stopped["pids"] == expected
    assert stopped.get("unresolved_pids") == [held.pid]
    assert all(row["pid"] != held.pid for row in stopped.get("absence_evidence", []))


def test_custody_cached_returncode_is_not_native_wait_evidence():
    from types import SimpleNamespace

    physical = r2_kernel_process(os.getpid())
    entry = {"pid": os.getpid(), "birth": physical["birth"], "process": SimpleNamespace(returncode=0),
             "fd": None, "verified_fd": False, "lost": False, "exit": None}
    observer = SimpleNamespace(entries={"actor": entry})
    assert R2Custody.observe(observer, "actor") is None
    assert entry["exit"] is None and entry.get("wait_status") == "unavailable"


def test_witnessed_child_keeps_echild_distinct_from_a_real_zero_status(r2_case):
    held = r2_case.spawn()
    r2_case.configs[0].with_suffix(".exit").touch()
    # A zombie leader can precede waitable thread-group exit. Observe native readiness without
    # consuming it, then keep the exact raw waitpid/status and ECHILD assertions below.
    wait_until(lambda: os.waitid(os.P_PID, held.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None)
    reaped, status = os.waitpid(held.pid, os.WNOHANG)
    assert reaped == held.pid and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert held.poll() is None and held.native_wait_evidence is None
    with pytest.raises(ChildProcessError, match="^R2 fixture: native wait status unavailable$"):
        held.wait(timeout=.1)
    slot = next(slot for slot, row in r2_case.custody.entries.items() if row["pid"] == held.pid)
    evidence = r2_case.custody.observe(slot)
    assert evidence["proof"] == "original_pidfd_exit" and "returncode" not in evidence
    assert r2_case.custody.entries[slot]["wait_status"] == "unavailable"


def test_custody_uses_original_pidfd_when_metadata_read_races_actual_exit(r2_case):
    """MODELLED read failure after an independently witnessed real child exit; no PID absence inference."""
    import importlib.util
    from types import SimpleNamespace
    from tests.integration import test_hierarchy_launcher as helper

    held = r2_case.spawn()
    slot = next(slot for slot, row in r2_case.custody.entries.items() if row["pid"] == held.pid)
    entry = r2_case.custody.entries[slot]
    assert entry["fd"] is not None and entry["verified_fd"]
    spec = importlib.util.spec_from_file_location("exit_observer_" + uuid.uuid4().hex, helper.__file__)
    isolated = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = isolated
    spec.loader.exec_module(isolated)
    observations = []

    def exiting(pid):
        assert pid == held.pid
        r2_case.configs[0].with_suffix(".exit").touch()
        assert held.wait(timeout=2) == 0
        observations.append(pid)
        raise ProcessLookupError("modelled /proc read racing confirmed original exit")

    isolated.r2_kernel_process = exiting
    observer = SimpleNamespace(entries={slot: entry})
    evidence = isolated.R2Custody.observe(observer, slot)
    assert observations == [held.pid] and evidence == {"proof": "original_pidfd_exit"}
    assert not entry["lost"]


def test_modelled_custody_lost_birth_cannot_be_resolved_by_numeric_absence(tmp_path):
    """Actorless modelled OS observations: no real PID is ever signalled or put in physical custody."""
    import importlib.util
    from tests.integration import test_hierarchy_launcher as helper

    spec = importlib.util.spec_from_file_location("actorless_custody_" + uuid.uuid4().hex, helper.__file__)
    isolated = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = isolated
    spec.loader.exec_module(isolated)
    original = r2_kernel_process(os.getpid())
    control = isolated.R2Custody(tmp_path / "observer", tmp_path / "modelled-quarantine.json")
    control.plan({"actor": {"kind": "H", "parent": None, "child": None}})
    control.slots["actor"].update(permitted=True, hello=True, released=True)
    control.entries["actor"] = {"pid": os.getpid(), "birth": original["birth"], "process": None,
                                 "fd": None, "verified_fd": False, "lost": False, "exit": None}
    reads = []

    def changed_then_missing(pid):
        reads.append(pid)
        if len(reads) == 1:
            return {**original, "birth": str(int(original["birth"]) + 1)}
        raise FileNotFoundError("modelled missing original metadata")

    def numeric_only(pid, number):
        assert number == 0, "the actorless control must never send a signal"
        raise ProcessLookupError("modelled numeric absence")

    isolated.r2_kernel_process = changed_then_missing
    isolated.os = R2Facade(os, kill=numeric_only)
    try:
        assert control.observe("actor") is None and control.entries["actor"]["lost"]
        assert control.observe("actor") is None and control.entries["actor"]["exit"] is None
        with pytest.raises(isolated.R2CleanupUnknown):
            control.close()
        assert control.report["state"] == "UNKNOWN" and control.report["unresolved_slots"] == ["actor"]
        with pytest.raises(RuntimeError, match="^R2 fixture: physical actor admission is closed$"):
            control.admit_check()
    finally:
        # This is an actorless negative observer, not an unknown real process scope. Preserve its quarantine
        # report under that explicit label and close only the pipe descriptors this control itself created.
        report = control.folder / "closure.json"
        if report.exists():
            report.rename(control.folder / "actorless-observer-report.json")
        for fd in (control.safety_read, control.safety_write, control.report_read, control.report_write,
                   *(fd for pair in control.gates.values() for fd in pair)):
            try:
                os.close(fd)
            except OSError:
                pass


def test_r2_projection_runner_uses_the_public_stop_entrypoint(r2_case):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    held = r2_case.spawn(["codex", "exec", "resume", session])
    runner, _ = r2_case.runner()
    out, err = runner.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
    assert err == "" and runner.returncode == 0, out + err
    answer = json.loads(out)
    assert answer["state"] == "stopped" and answer["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize("caller", [False, True], ids=["direct", "through-caller"])
def test_r9_public_runner_capture_drains_before_communicate(r2_case, caller):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    held = r2_case.spawn(["codex", "exec", "resume", session])
    root, _ = r2_case.runner(session=session if caller else None, action="burst")
    slot = next(slot for slot, entry in r2_case.custody.entries.items() if entry["pid"] == root.pid)
    completed_output = r2_case.custody.folder / (slot + ".capture-ready")
    # This is a transport liveness guard, not a wall-clock performance assertion. The real writer must
    # finish both streams while the fixture stages observations, before communicate begins draining.
    def completed():
        held.poll()  # The real parent must reap during staging, before communicate's observer begins.
        return completed_output.exists()
    wait_until(completed, seconds=R2_STOP_TIMEOUT_SECONDS)
    out, err = root.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
    assert root.returncode == 0 and err == "E" * (2 * 1024 * 1024)
    assert out.startswith(" " * (2 * 1024 * 1024))
    answer = json.loads(out)
    assert answer["state"] == "stopped" and answer["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_r9_identical_checkpoint_does_not_repeat_durable_io(r2_case, capsys):
    import stat

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module()
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    syncing, commits, before_effect = module.os.fsync, [], []

    def fsync(descriptor):
        answer = syncing(descriptor)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode) and Path(os.readlink("/proc/self/fd/%d" % descriptor)) == journal.parent:
            commits.append(json.loads(journal.read_text()))
        return answer

    def sent(pid, number):
        if pid == held.pid and number == signal.SIGTERM:
            before_effect.extend(commits)

    module.os.fsync = fsync
    r2_case.projection.after_signal.append(sent)
    code, stopped = r2_case.stop(module, capsys)
    assert code == 0 and stopped["state"] == "stopped" and held.wait(timeout=5) == -signal.SIGTERM
    assert len(before_effect) == 1, "the A checkpoint carries C; no separate candidate checkpoint is needed"
    assert before_effect[0]["active"] and before_effect[0]["entries"][0]["attempted"]


def test_r9_a_commit_changed_during_fsync_refuses_before_signalling(r2_case, capsys):
    import stat

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module()
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    syncing, changed = module.os.fsync, []

    def fsync(descriptor):
        syncing(descriptor)
        if (not changed and stat.S_ISDIR(os.fstat(descriptor).st_mode) and
                Path(os.readlink("/proc/self/fd/%d" % descriptor)) == journal.parent):
            # MODELLED unexpected file update at the OS boundary; never affirmative host evidence.
            with journal.open("ab") as stream:
                stream.write(b"\n")
            changed.append(True)

    module.os.fsync = fsync
    code, answer = r2_case.stop(module, capsys)
    assert changed and code == 2
    assert answer["error"] == "stop custody unavailable: stop custody changed during durable commit"
    assert answer["state"] == "refused" and "pids" not in answer
    assert r2_case.projection.events == [] and held.poll() is None


def test_r9_visible_checkpoint_from_failed_fsync_is_not_a_durable_cache(r2_case, capsys):
    import errno
    import stat

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session])
    module = r2_case.module()
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    syncing, failed = module.os.fsync, []

    def fsync(descriptor):
        if (not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode) and
                Path(os.readlink("/proc/self/fd/%d" % descriptor)) == journal.parent):
            failed.append(True)
            raise OSError(errno.EIO, "modelled directory fsync failure")
        return syncing(descriptor)

    module.os.fsync = fsync
    code, answer = r2_case.stop(module, capsys)
    assert code == 2 and answer["error"] == "stop custody unavailable: [Errno 5] modelled directory fsync failure"
    assert answer["state"] == "refused" and "pids" not in answer
    assert failed and journal.exists() and held.poll() is None and r2_case.projection.events == []
    recovered, committed = r2_case.module(), []
    syncing = recovered.os.fsync

    def committed_fsync(descriptor):
        result = syncing(descriptor)
        if (stat.S_ISDIR(os.fstat(descriptor).st_mode) and
                Path(os.readlink("/proc/self/fd/%d" % descriptor)) == journal.parent):
            committed.append(json.loads(journal.read_text()))
        return result

    recovered.os.fsync = committed_fsync
    r2_case.projection.after_signal.append(lambda pid, number: committed.append("signal"))
    code, stopped = r2_case.stop(recovered, capsys)
    assert code == 0 and stopped["pids"] == [held.pid] and held.wait(timeout=5) == -signal.SIGTERM
    assert committed[0]["active"] and committed[0]["entries"][0]["attempted"]
    assert committed.index("signal") >= 1


class R10Interrupted(BaseException):
    """MODELLED launcher loss after a real OS durability barrier; fixture custody remains independent."""


def r10_observe_fsync(module, journal, events, interrupt=None):
    import stat
    import time

    syncing = module.os.fsync

    def fsync(descriptor):
        path = Path(os.readlink("/proc/self/fd/%d" % descriptor))
        kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
        if kind == "directory" and path in journal.parents and path != journal.parent and not journal.exists():
            phase = "initialize"
        elif path == journal.parent or path.parent == journal.parent:
            data = json.loads((journal if kind == "directory" else path).read_text())
            phase = ("clear" if not data["active"] else "resolved-active" if
                     all(row["resolved"] for row in data["entries"]) else "A" if
                     any(row["attempted"] for row in data["entries"]) else "C")
        else:
            phase = "outcome"
        start = time.monotonic_ns()
        result = syncing(descriptor)
        events.append(dict(phase=phase, kind=kind, elapsed_ms=(time.monotonic_ns() - start) / 1e6))
        if (phase, kind) == interrupt:
            raise R10Interrupted("modelled interruption after %s/%s" % interrupt)
        return result

    module.os.fsync = fsync


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_r10_ordinary_stop_has_six_durable_barriers_plus_initialization(r2_case, capsys, host):
    import time

    session = str(uuid.uuid4())
    r2_case.bind(host, session)
    held = r2_case.spawn(["claude", "--resume", session] if host == "claude-code" else
                         ["codex", "exec", "resume", session])
    module = r2_case.module()
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    events = []
    r10_observe_fsync(module, journal, events)
    start = time.monotonic_ns()
    code, stopped = r2_case.stop(module, capsys)
    elapsed = (time.monotonic_ns() - start) / 1e6
    (r2_case.launch.tmp / "r10-cost-evidence.json").write_text(json.dumps(
        dict(host=host, elapsed_ms=elapsed, fsync_count=len(events), fsyncs=events)) + "\n")
    assert code == 0 and stopped["state"] == "stopped" and stopped["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM
    assert r2_case.launch.records() == [stopped]
    assert [(event["phase"], event["kind"]) for event in events] == [
        ("initialize", "directory"), ("initialize", "directory"), ("initialize", "directory"),
        ("A", "file"), ("A", "directory"),
        ("outcome", "file"), ("outcome", "directory"), ("clear", "file"), ("clear", "directory")]


@pytest.mark.parametrize("phase,kind,live,journal_state", [
    ("initialize", "directory", True, None),
    ("A", "file", True, None), ("A", "directory", True, True),
    ("outcome", "file", False, True), ("outcome", "directory", False, True),
    ("clear", "file", False, True), ("clear", "directory", False, False),
])
def test_r10_interrupted_barriers_keep_stop_and_handoff_safe(r2_case, capsys, phase, kind, live, journal_state):
    from tests.integration.test_hierarchy_handoff import mailbox_files
    from tests.integration.test_hierarchy_handoff_stop_evidence import handoff_module, run_main, spec_for

    session = str(uuid.uuid4())
    # A real managed start makes stop evidence mandatory; unmanaged caller-asserted legacy behavior is separate.
    assert r2_case.launch.start(thread=session, cwd=str(r2_case.launch.source))["session"] == session
    held = r2_case.spawn(["codex", "exec", "resume", session])
    module = r2_case.module(pidfds=False)
    journal = module.Launches(str(r2_case.launch.base)).folder(REVIEW) / ".stop-custody" / "state.json"
    events = []
    r10_observe_fsync(module, journal, events, (phase, kind))
    with pytest.raises(R10Interrupted, match="^modelled interruption after %s/%s$" % (phase, kind)):
        r2_case.stop(module, capsys)
    capsys.readouterr()
    if live:
        physical = r2_kernel_process(held.pid)
        receipt = r2_case.projection.receipts[str(held.pid)]
        assert not physical["state"].startswith(("Z", "X"))
        assert physical["birth"] == receipt["birth"] and physical["digest"] == receipt["digest"]
        assert physical["uid"] == physical["euid"] == os.geteuid()
    else:
        # Sending TERM / observing a pidfd does not mean this parent's non-blocking wait has reaped yet.
        # Establish the actual native wait PID/status before asserting any post-effect "not live" row.
        assert held.wait(timeout=5) == -signal.SIGTERM
        assert held.native_wait_evidence["wait_pid"] == held.pid
    assert (held.poll() is None) is live
    if journal_state is None:
        assert not journal.exists()
    else:
        assert json.loads(journal.read_text())["active"] is journal_state
    assert r2_case.projection.events == ([] if live else [(held.pid, signal.SIGTERM)])
    control = handoff_module()
    control.hierarchy_launcher = r2_case.module(pidfds=False)
    spec, before = spec_for(r2_case.launch), mailbox_files(r2_case.launch.base)
    if journal_state is not False:
        refused = run_main(control, r2_case.launch, spec, capsys, 2)
        assert ("stop custody unresolved" if journal_state else
                "a stopped or not_running stop record is required") in refused["error"]
        assert mailbox_files(r2_case.launch.base) == before
        if live:
            assert not r2_kernel_process(held.pid)["state"].startswith(("Z", "X"))
            assert held.poll() is None and r2_case.projection.events == []
    code, recovered = r2_case.stop(r2_case.module(pidfds=False), capsys)
    assert code == 0 and recovered["state"] == ("not_running" if journal_state is False else "stopped")
    assert recovered["pids"] == ([] if journal_state is False else [held.pid])
    assert held.wait(timeout=5) == -signal.SIGTERM
    assert not json.loads(journal.read_text())["active"]
    granted = run_main(control, r2_case.launch, spec, capsys, 0)
    assert granted["entries"][0]["generation"] == 2


@pytest.mark.parametrize("phase,kind", [("outcome", "file"), ("outcome", "directory"),
                                      ("clear", "file"), ("clear", "directory")])
def test_r11_crash_cuts_observe_exit_before_asserting_dead(r2_case, capsys, monkeypatch, phase, kind):
    import select

    spawning, delayed, held_children = r2_case.spawn, [], []

    def spawn(*args, **kwargs):
        held = spawning(*args, **kwargs)
        held_children.append(held)
        polling = held.poll

        def poll():
            # MODELLED one delayed WNOHANG result at the Popen observation boundary. The pidfd first proves
            # the REAL original exit; no status/UID/birth/argv or signal authority is fabricated.
            if not delayed and held.native_handle is not None:
                watcher = select.poll()
                watcher.register(held.native_handle, select.POLLIN)
                if watcher.poll(0):
                    delayed.append(held.pid)
                return None
            return polling()

        held.poll = poll
        return held

    monkeypatch.setattr(r2_case, "spawn", spawn)
    test_r10_interrupted_barriers_keep_stop_and_handoff_safe(r2_case, capsys, phase, kind, False, True if
                                                           (phase, kind) != ("clear", "directory") else False)
    [held] = held_children
    assert delayed == [held.pid], "fixture prerequisite: one actual exited-child poll was deferred"
    assert held.native_wait_evidence["wait_pid"] == held.pid
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_r2_ancestor_exclusion_spares_a_ready_host_named_caller(r2_case):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    held = r2_case.spawn(["codex", "exec", "resume", session])
    caller, runner = r2_case.runner(session=session)
    assert r2_kernel_process(runner.pid)["ppid"] == caller.pid
    assert session.encode() in r2_kernel_process(caller.pid)["raw"].split(b"\0")
    assert Path(os.fsdecode(r2_kernel_process(caller.pid)["raw"].split(b"\0")[0])).name == "codex"
    out, err = caller.communicate(timeout=R2_STOP_TIMEOUT_SECONDS)
    assert caller.returncode == 0 and err == "", out + err
    answer = json.loads(out)
    assert answer["state"] == "stopped" and answer["pids"] == [held.pid] and caller.pid not in answer["pids"]
    assert held.wait(timeout=5) == -signal.SIGTERM


# Exact finite 28-row matrix from the Root-admitted R2 evidence, not matcher-derived expectations.
def test_r2_fixture_closure_failed_ready_keeps_physical_custody(r2_case, monkeypatch):
    def failed_ready(*args, **kwargs):
        raise OSError("modelled READY staging failure")

    monkeypatch.setattr(r2_case.projection, "ready", failed_ready)
    with pytest.raises(OSError, match="^modelled READY staging failure$"):
        r2_case.spawn(["claude", "--resume", str(uuid.uuid4())], tree=True)
    report = r2_case.custody.report
    assert report["state"] == "CLOSED" and not report["unresolved_slots"]
    assert len(report["entries"]) == 1 and all(row["exit"] for row in report["entries"].values())
    assert len(report["uncreated_slots"]) == 2
    assert all(row["state"] == "PENDING" for row in r2_case.projection.receipts.values())
    with pytest.raises(RuntimeError, match="^R2 fixture: physical actor admission is closed$"):
        r2_case.spawn()


def test_r2_sibling_fixture_retains_real_parents_and_group(r2_case):
    session = str(uuid.uuid4())
    family = r2_case.spawn_group(None, named_child=["codex", "exec", "resume", session], siblings=True)
    host, first, second = (family[label] for label in ("H", "M", "W"))
    assert r2_kernel_process(first.pid)["ppid"] == r2_kernel_process(second.pid)["ppid"] == host.pid
    assert {r2_kernel_process(child.pid)["pgid"] for child in family.values()} == {host.pid}
    report = r2_case.close()
    assert report["state"] == "CLOSED" and report["errors"] == report["unresolved_slots"] == []
    assert len(report["entries"]) == 3 and all(row["exit"] for row in report["entries"].values())


def test_r2_sibling_fixture_closes_both_children_when_ready_staging_fails(r2_case, monkeypatch):
    ready = r2_case.projection.ready
    calls = []

    def failed_child(process, argv):
        calls.append(process.pid)
        if len(calls) == 2:
            raise OSError("modelled sibling READY staging failure")
        return ready(process, argv)

    monkeypatch.setattr(r2_case.projection, "ready", failed_child)
    with pytest.raises(OSError, match="^modelled sibling READY staging failure$"):
        r2_case.spawn_group(None, named_child=["codex", "exec", "resume", str(uuid.uuid4())], siblings=True)
    report = r2_case.custody.report
    assert report["state"] == "CLOSED" and report["errors"] == report["unresolved_slots"] == []
    assert len(report["entries"]) == 3 and all(row["exit"] for row in report["entries"].values())


def test_r2_exec_fixture_uses_actual_exec_bytes_and_owned_cleanup(r2_case):
    ready = r2_case.launch.tmp / "exec-ready"
    session = str(uuid.uuid4())
    command = [sys.executable, "-c", CHILD]
    held = r2_case.spawn_exec(command, ["codex", "exec", "resume", session], command,
                             environment={"STOP_OWNERSHIP_READY": str(ready)})
    wait_until(ready.exists)
    physical = r2_kernel_process(held.pid)
    row = r2_case.module().read_process(held.pid).snapshot
    assert physical["raw"].split(b"\0")[:-1] == [os.fsencode(word) for word in command]
    assert row.cmdline == physical["raw"] and row.start_time == physical["birth"]
    assert row.argv == ("codex", "exec", "resume", session)
    report = r2_case.close()
    assert report["state"] == "CLOSED" and report["errors"] == report["unresolved_slots"] == []
    assert r2_case.projection.events == [] and held.wait(timeout=5) < 0


def test_r2_exec_fixture_closes_an_actual_exec_on_ready_failure(r2_case, monkeypatch):
    def fail(*args):
        raise OSError("modelled actual-exec READY failure")

    monkeypatch.setattr(r2_case.projection, "ready", fail)
    command = [sys.executable, "-c", "import time; time.sleep(5)"]
    with pytest.raises(OSError, match="^modelled actual-exec READY failure$"):
        r2_case.spawn_exec(command, ["codex", "resume", str(uuid.uuid4())], command)
    report = r2_case.custody.report
    assert report["state"] == "CLOSED" and report["errors"] == report["unresolved_slots"] == []
    assert len(report["entries"]) == 1 and all(row["exit"] for row in report["entries"].values())
    assert r2_case.projection.events == []


def test_r2_exec_fixture_keeps_a_fast_original_exit_as_negative_evidence(r2_case, capsys):
    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    module = r2_case.module()
    command = [sys.executable, "-c", "pass"]
    held = r2_case.spawn_exec(command, ["codex", "resume", session], command)
    assert held.wait(timeout=5) == 0
    code, stopped = r2_case.stop(module, capsys)
    assert code == 0 and stopped["state"] == "not_running" and stopped["pids"] == []
    assert r2_case.projection.events == []


def test_r2_captured_exec_registers_a_real_child_before_releasing_it(r2_case, capsys):
    from tests.integration.hierarchy_fake_wrapper import python_argv
    from tests.integration.test_hierarchy_mailbox import ROOT

    session = str(uuid.uuid4())
    r2_case.bind("codex-cli", session)
    ready = r2_case.launch.tmp / "captured-child-ready"
    child = [sys.executable, "-c", CHILD]
    target = r2_case.launch.tmp / "captured-parent.py"
    target.write_text("import subprocess, time\nsubprocess.run(%r)\ntime.sleep(5)\n" % child, encoding="utf-8")
    prefix = python_argv("codex", ROOT / "tests/integration/test_hierarchy_launcher.py", r2_case.launch.tmp,
                         "r2_captured_entry")
    command = [*prefix, str(target), "script"]
    held = r2_case.spawn_exec(command, ["codex", "exec", "resume", session], command,
                             environment={"STOP_OWNERSHIP_READY": str(ready)},
                             captured=[{"argv": child, "expected_argv": child, "logical_argv": None}],
                             target=(target, "script"))
    try:
        wait_until(lambda: r2_case.service_exec_children() or ready.exists())
    except AssertionError as error:
        raise AssertionError("captured child did not become ready\n" + r2_case.custody.stderr_tail()) from error
    r2_case.service_exec_children()
    descendants = [e for e in r2_case.custody.entries.values() if e["pid"] != held.pid]
    assert len(descendants) == 1
    worker = descendants[0]["pid"]
    assert r2_kernel_process(worker)["ppid"] == held.pid
    code, stopped = r2_case.stop(r2_case.module(), capsys)
    assert code == 0 and stopped["state"] == "stopped" and stopped["pids"] == sorted([held.pid, worker])
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_r2_captured_exec_closes_a_child_still_behind_its_gate(r2_case, monkeypatch):
    from tests.integration.hierarchy_fake_wrapper import python_argv
    from tests.integration.test_hierarchy_mailbox import ROOT

    child = [sys.executable, "-c", "import time; time.sleep(5)"]
    target = r2_case.launch.tmp / "captured-pending-parent.py"
    target.write_text("import subprocess\nsubprocess.run(%r)\n" % child, encoding="utf-8")
    prefix = python_argv("codex", ROOT / "tests/integration/test_hierarchy_launcher.py", r2_case.launch.tmp,
                         "r2_captured_entry")
    command = [*prefix, str(target), "script"]
    releasing = r2_case.custody.release

    def failed_child(slot):
        if slot.endswith("-child0"):
            raise OSError("modelled captured-child gate failure")
        return releasing(slot)

    monkeypatch.setattr(r2_case.custody, "release", failed_child)
    with pytest.raises(OSError, match="^modelled captured-child gate failure$"):
        r2_case.spawn_exec(command, ["codex", "resume", str(uuid.uuid4())], command,
                           captured=[{"argv": child, "expected_argv": child, "logical_argv": None}],
                           target=(target, "script"))
        wait_until(lambda: r2_case.service_exec_children())
    report = r2_case.close()
    assert report["state"] == "CLOSED" and report["errors"] == report["unresolved_slots"] == []
    assert len(report["entries"]) == 2 and all(row["exit"] for row in report["entries"].values())


def test_r2_fixture_closure_partial_tree_survives_receipt_stage_failure(r2_case, monkeypatch):
    original = r2_case.projection.pending

    def failed_middle(process):
        if len(r2_case.custody.entries) >= 2:
            raise OSError("modelled middle receipt failure")
        return original(process)

    monkeypatch.setattr(r2_case.projection, "pending", failed_middle)
    with pytest.raises(OSError, match="^modelled middle receipt failure$"):
        r2_case.spawn(["claude", "--resume", str(uuid.uuid4())], tree=True)
    report = r2_case.custody.report
    assert report["state"] == "CLOSED" and not report["unresolved_slots"]
    assert len(report["entries"]) == 2 and all(row["exit"] for row in report["entries"].values())
    assert len(report["uncreated_slots"]) == 1
    assert len(r2_case.projection.receipts) == 1  # The unreceipted M still had independent physical custody.


@pytest.mark.parametrize("ending", ["timeout", "caller-killed"])
def test_r2_fixture_closure_visits_all_and_closes_orphan_runner(r2_case, ending):
    caller, runner = r2_case.runner(session=str(uuid.uuid4()), action="hang",
                                   timeout=3 if ending == "caller-killed" else 0.3)
    caller_slot = next(slot for slot, row in r2_case.custody.entries.items() if row["pid"] == caller.pid)
    if ending == "caller-killed":
        r2_case.custody.kill_owned(caller_slot)
        # An actual native wait can precede Popen cleanup; never manufacture success from ECHILD.
        assert r2_case.custody.wait_native(caller_slot) == -signal.SIGKILL
    else:
        caller.communicate(timeout=2)
        assert caller.returncode == 124  # Cached real Popen status is independent of the runner's liveness.
    assert runner.poll() is None  # Caller exit alone did not close the still-owned runner.
    seen = []

    def failed_once(slot):
        seen.append(slot)
        if len(seen) == 1:
            raise OSError("modelled first cleanup failure")

    r2_case.custody.cleanup_hook = failed_once
    with pytest.raises(R2CleanupError) as caught:
        r2_case.close()
    report = caught.value.report
    assert report["state"] == "CLOSED_WITH_ERRORS" and not report["unresolved_slots"]
    assert set(seen) == set(report["entries"]) == set(report["visited"])
    assert len(report["entries"]) == 2 and all(row["exit"] for row in report["entries"].values())
    assert any("modelled first cleanup failure" in error for error in report["errors"])
    assert runner.poll() is not None and not r2_case.custody.quarantine.exists()
    with pytest.raises(RuntimeError, match="^R2 fixture: physical actor admission is closed$"):
        r2_case.custody.admit_check()


R2_SELECTOR_DISPOSITIONS = [
    {'host': 'claude-code', 'id': 'modelled-system-prompt-consumed-terminator', 'provider': 'PROVEN_ARGV', 'arguments': ['--print', '--system-prompt', 'Explain --resume', '--', '--resume <S>'], 'verdict': 'NOT_OWNED', 'expected_exit': 0, 'expected_state': 'not_running'},
    {'host': 'claude-code', 'id': 'modelled-system-prompt-consumed-terminator', 'provider': 'LOSSY_PS', 'arguments': ['--print', '--system-prompt', 'Explain --resume', '--', '--resume <S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-selector-consumed-terminator', 'provider': 'PROVEN_ARGV', 'arguments': ['--resume', '--', '--resume <S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-selector-consumed-terminator', 'provider': 'LOSSY_PS', 'arguments': ['--resume', '--', '--resume <S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-claude-option-valued-selection', 'provider': 'PROVEN_ARGV', 'arguments': ['--resume', '--print', 'please --resume <S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-claude-option-valued-selection', 'provider': 'LOSSY_PS', 'arguments': ['--resume', '--print', 'please --resume <S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'codex-cli', 'id': 'modelled-codex-option-valued-selection', 'provider': 'PROVEN_ARGV', 'arguments': ['exec', 'resume', '--last', 'resume <S> prompt'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'codex-cli', 'id': 'modelled-codex-option-valued-selection', 'provider': 'LOSSY_PS', 'arguments': ['exec', 'resume', '--last', 'resume <S> prompt'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-unknown-value-cannot-recover', 'provider': 'PROVEN_ARGV', 'arguments': ['--resume', 'unknown', '--resume', '<S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-unknown-value-cannot-recover', 'provider': 'LOSSY_PS', 'arguments': ['--resume', 'unknown', '--resume', '<S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-missing-value-after-bound-selection', 'provider': 'PROVEN_ARGV', 'arguments': ['--resume', '<S>', '--session-id'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-missing-value-after-bound-selection', 'provider': 'LOSSY_PS', 'arguments': ['--resume', '<S>', '--session-id'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-option-value-after-bound-selection', 'provider': 'PROVEN_ARGV', 'arguments': ['--resume', '<S>', '--resume', '--print', 'wait'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-option-value-after-bound-selection', 'provider': 'LOSSY_PS', 'arguments': ['--resume', '<S>', '--resume', '--print', 'wait'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-unknown-selection-after-bound-selection', 'provider': 'PROVEN_ARGV', 'arguments': ['--resume', '<S>', '--resume', 'unknown'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-unknown-selection-after-bound-selection', 'provider': 'LOSSY_PS', 'arguments': ['--resume', '<S>', '--resume', 'unknown'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'codex-cli', 'id': 'established-codex-positional-terminator', 'provider': 'PROVEN_ARGV', 'arguments': ['exec', 'resume', '--', '<S>', 'prompt'], 'verdict': 'OWNED', 'expected_exit': 0, 'expected_state': 'stopped'},
    {'host': 'codex-cli', 'id': 'established-codex-positional-terminator', 'provider': 'LOSSY_PS', 'arguments': ['exec', 'resume', '--', '<S>', 'prompt'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'codex-cli', 'id': 'builder-codex-ordinary-prompt', 'provider': 'PROVEN_ARGV', 'arguments': ['exec', 'resume', '<S>', 'please resume the review'], 'verdict': 'OWNED', 'expected_exit': 0, 'expected_state': 'stopped'},
    {'host': 'codex-cli', 'id': 'builder-codex-ordinary-prompt', 'provider': 'LOSSY_PS', 'arguments': ['exec', 'resume', '<S>', 'please resume the review'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-claude-ordinary-prompt', 'provider': 'PROVEN_ARGV', 'arguments': ['--session-id', '<S>', '--print', 'please --resume the review'], 'verdict': 'OWNED', 'expected_exit': 0, 'expected_state': 'stopped'},
    {'host': 'claude-code', 'id': 'modelled-claude-ordinary-prompt', 'provider': 'LOSSY_PS', 'arguments': ['--session-id', '<S>', '--print', 'please --resume the review'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-proven-prompt-versus-flat-conflict', 'provider': 'PROVEN_ARGV', 'arguments': ['--resume', '<S>', '--', '--resume <T>'], 'verdict': 'OWNED', 'expected_exit': 0, 'expected_state': 'stopped'},
    {'host': 'claude-code', 'id': 'modelled-proven-prompt-versus-flat-conflict', 'provider': 'LOSSY_PS', 'arguments': ['--resume', '<S>', '--', '--resume <T>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-opaque-configuration-value', 'provider': 'PROVEN_ARGV', 'arguments': ['--system-prompt', '--resume', '<S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-opaque-configuration-value', 'provider': 'LOSSY_PS', 'arguments': ['--system-prompt', '--resume', '<S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-proven-configuration-versus-flat-ambiguity', 'provider': 'PROVEN_ARGV', 'arguments': ['--system-prompt', '--resume', '--session-id', '<S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
    {'host': 'claude-code', 'id': 'modelled-proven-configuration-versus-flat-ambiguity', 'provider': 'LOSSY_PS', 'arguments': ['--system-prompt', '--resume', '--session-id', '<S>'], 'verdict': 'HOLD', 'expected_exit': 3, 'expected_state': 'stop_failed'},
]


@pytest.mark.parametrize("case", R2_SELECTOR_DISPOSITIONS,
                         ids=[case["id"] + "-" + case["provider"].lower() for case in R2_SELECTOR_DISPOSITIONS])
def test_r2_finite_selector_disposition_through_public_stop(r2_case, capsys, case):
    session, other = str(uuid.uuid4()), str(uuid.uuid4())
    r2_case.bind(case["host"], session)
    program = "claude" if case["host"] == "claude-code" else "codex"
    argv = [program, *(word.replace("<S>", session).replace("<T>", other) for word in case["arguments"])]
    held = r2_case.spawn(argv)
    module = r2_case.module()
    if case["provider"] == "LOSSY_PS":
        r2_case.ps(module, held, argv)
    code, stopped = r2_case.stop(module, capsys)
    assert code == case["expected_exit"] and stopped["state"] == case["expected_state"]
    assert stopped["pids"] == ([held.pid] if case["verdict"] == "OWNED" else [])
    if case["verdict"] == "OWNED":
        assert held.wait(timeout=5) == -signal.SIGTERM
    else:
        assert held.poll() is None and r2_case.projection.events == []
    if case["provider"] == "LOSSY_PS":
        assert stopped["argv_boundaries"] == "unproven" and stopped["unowned_pids"] == [held.pid]
