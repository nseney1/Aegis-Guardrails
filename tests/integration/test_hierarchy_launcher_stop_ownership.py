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

from tests.integration.test_hierarchy_launcher import (Launch, REVIEW, R2Processes, R2Custody, R2CleanupError,
                                                       r2_map_present, R2Facade,
                                                       R2CleanupUnknown, R2_ACTOR_BOOTSTRAP, launcher_module,
                                                       r2_kernel_process, native_wait_fields, wait_until)
from tests.integration.test_hierarchy_launcher_hosts import Hosts
from tests.integration.test_hierarchy_mailbox import ROOT, git


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="these process argv tests need Linux")
CHILD = """
import os, time
with open(os.environ["STOP_OWNERSHIP_READY"], "w") as ready:
    ready.write("ready")
# The admitted gate's private EOF watchdog owns lifetime; elapsed test setup must not end a held process.
import signal
while True:
    signal.pause()
"""

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
def launch(tmp_path):
    built = Launch(tmp_path)
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

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert stopped["state"] == "stopped" and stopped["pids"] == [owned.pid]
    assert stopped["host"] == host and stopped["session"] == session
    assert owned.wait(timeout=5) == -signal.SIGTERM


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
        assert code in (2, 3) and "process census unresolved" in answer.get("error", "")
        assert held.poll() is None and auth.exists() and Path(plan["worktree"]).is_dir()
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
    code, recovered = r2_case.stop(second, capsys, grace=0)
    assert code == 0 and recovered["state"] == "stopped" and worker.poll() == "CONFIRMED_EXIT"
    assert worker.pid in recovered["pids"] and worker.pid not in recovered.get("unowned_pids", [])


def r7_pending_attempt(case, capsys):
    """MODELLED interruption after one real TERM; READY/physical custody remains independent."""
    session = str(uuid.uuid4())
    case.bind("claude-code", session)
    held = case.spawn(["claude", "--resume", session], ignore=True)
    module = case.module(pidfds=False)

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
        saved["entries"][0]["snapshot"][field] += "é"
    elif field == "argv":
        saved["entries"][0]["snapshot"]["argv"].append("é")
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
    opening = module.os.open

    def change_directory(source, *args, **kwargs):
        if attack == "directory-mode-at-open" and str(source) == "state.json":
            path.parent.chmod(0o755)
        return opening(source, *args, **kwargs)

    module.os.open = change_directory
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
    assert path.read_bytes().isascii() and b"\\u00e9" in path.read_bytes()
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
    assert code == 2 and "resolved" in answer["error"]
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
    code, stopped = r2_case.stop(recovery, capsys, grace=0)
    assert code == 0 and stopped["state"] == "stopped" and worker.poll() == "CONFIRMED_EXIT"
    assert stopped["pids"] == [worker.pid]


def test_r7_failed_pre_effect_custody_write_sends_nothing(r2_case, capsys):
    import errno

    session = str(uuid.uuid4())
    r2_case.bind("claude-code", session)
    held = r2_case.spawn(["claude", "--resume", session], ignore=True)
    module = r2_case.module()
    replacing, faults = module.os.replace, []

    def failed(source, target):
        if Path(target).parent.name == ".stop-custody":
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

    def failed(source, target):
        if sent and Path(target).parent.name == ".stop-custody":
            faults.append(str(target))
            raise OSError(errno.EIO, "modelled persistent custody write failure after TERM")
        return replacing(source, target)

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

    def failed(source, target):
        if Path(target).parent.name == ".stop-custody" and not json.loads(Path(source).read_text())["active"]:
            faults.append(str(target))
            raise OSError(errno.EIO, "modelled terminal custody update failure")
        return replacing(source, target)

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
    reading, deleted = module.read_json, []

    def disappeared(source):
        if Path(source) == r2_case.launch.base / "provision.json" and path.exists():
            path.unlink()  # MODELLED file loss after the consumer's initial positive existence observation.
            deleted.append(True)
        return reading(source)

    module.read_json = disappeared
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

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

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

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert other.poll() is None, "a claude process does not belong to a codex-cli binding"
    assert stopped["unowned_pids"] == [other.pid]
    assert stopped["state"] == "not_running" and stopped["pids"] == []


@pytest.mark.parametrize("argument", ["prefix-%s", "%s-suffix"])
def test_stop_requires_the_session_as_a_whole_argument(launch, children, argument):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "codex"), "-c", CHILD, argument % session, logical_argv=["codex", "exec", argument % session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

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
        stopped = hosts.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)
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

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

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

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

    assert other.poll() is None
    assert stopped["pids"] == [] and stopped["unowned_pids"] == [other.pid]


def test_stop_does_not_split_a_session_out_of_a_single_argument(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "codex-cli", session=session)
    other = children(str(launch.tmp / "codex"), "-c", CHILD, "diagnostic %s text" % session, logical_argv=["codex", "exec", "diagnostic %s text" % session])

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)

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

    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "0", timeout=5)

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
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "0"]) == 3
    stopped = json.loads(capsys.readouterr().out)
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


@pytest.mark.parametrize("uid_offset", [0, 1])
def test_stop_spares_an_unowned_member_of_an_owned_group(launch, children, monkeypatch, capsys, uid_offset):
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
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["state"] == "stopped" and stopped["pids"] == [leader.pid]
    assert stopped["unowned_pids"] == [other.pid]
    assert leader.wait(timeout=5) == -signal.SIGTERM
    assert other.poll() is None


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
    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)
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


@pytest.mark.parametrize("error", [1, 38, 5])
def test_stop_falls_back_when_pidfd_open_is_unavailable(launch, children, monkeypatch, capsys, error):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, logical_argv=["claude", "--resume", session])

    def unavailable(pid):
        raise OSError(error, "pidfd unavailable")

    module = children.module()
    monkeypatch.setattr(module.os, "pidfd_open", unavailable, raising=False)
    monkeypatch.setattr(module.signal, "pidfd_send_signal", lambda *args: pytest.fail("unopened pidfd signalled"), raising=False)
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["pids"] == [held.pid]
    assert held.wait(timeout=5) == -signal.SIGTERM


def test_stop_spares_a_forked_claude_session(launch, children):
    session = str(uuid.uuid4())
    launch.add_role(REVIEW, "claude-code", session=session)
    held = children(str(launch.tmp / "claude"), "-c", CHILD, "--resume", session, "--fork-session", logical_argv=["claude", "--resume", session, "--fork-session"])
    stopped = launch.run("stop", "--endpoint", REVIEW, "--grace-seconds", "1", timeout=5)
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
    assert stopped["pids"] == [leader.pid] and "unowned_pids" not in stopped
    assert leader.wait(timeout=5) == -signal.SIGTERM
    assert member.poll() is None


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
    assert module.main(["--base", str(launch.base), "stop", "--endpoint", REVIEW, "--grace-seconds", "1"]) == 0
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
    module = children.module()
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
        monkeypatch.setattr(module.os, "pidfd_open", unavailable, raising=False)

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
        assert code == 3 and stopped["state"] == "stop_failed"
        assert worker.poll() is None and (worker.pid, signal.SIGKILL) not in events
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

    def module():
        loaded = children.module()
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
    pytest.param("claude-code", ["-r<T>", "-p", "wait"], 0, id="modelled-attached-alias-not-observed"),
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

    def spawn(self, argv=None, ignore=False, tree=False, worker_argv=None):
        tag = "actor%d-" % len(self.configs)
        nodes = {tag + "H": {"kind": "H", "parent": None, "child": tag + "M" if tree else None}}
        if tree:
            nodes.update({tag + "M": {"kind": "M", "parent": tag + "H", "child": tag + "W"},
                          tag + "W": {"kind": "W", "parent": tag + "M", "child": None}})
        config = self.make_config(nodes, ignore=ignore, tree=tree)
        try:
            root = self.custody.launch(config, tag + "H", self.env)
            family = {"H": self.admit(tag + "H", root, argv)}
            if tree:
                for label in ("M", "W"):
                    slot = tag + label
                    self.custody.await_event(slot, "hello")
                    from tests.integration.test_hierarchy_launcher import R2OwnedChild
                    child = R2OwnedChild(self.custody, slot)
                    family[label] = self.admit(slot, child, worker_argv if label == "W" else None)
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

    def runner(self, session=None, action="stop", timeout=3, stop_words=None, echo_exit=False):
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

    def before(pid, count):
        if pid == held.pid and count >= 2:
            stage.append("recheck")

    def unavailable(path, physical):
        if stage and str(path) == "/proc/%d/%s" % (held.pid, field):
            faults.append(field)
            raise PermissionError("modelled unavailable evidence before first signal")
        return physical

    r2_case.projection.before_read.append(before)
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
    assert host.wait(timeout=5) == -signal.SIGKILL


def test_r2_projection_contract_preserves_real_evidence(r2_case):
    session = str(uuid.uuid4())
    logical = ["claude", "--resume", session]
    held = r2_case.spawn(logical)
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
    assert code == 0 and stopped["state"] == "stopped" and worker.poll() is None
    assert worker.pid not in stopped["pids"] and worker.pid not in stopped.get("unowned_pids", [])
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
    wait_until(lambda: r2_kernel_process(held.pid)["state"].startswith("Z"))
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
    out, err = runner.communicate(timeout=5)
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
    wait_until(completed_output.exists)
    out, err = root.communicate(timeout=5)
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
    out, err = caller.communicate(timeout=5)
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
