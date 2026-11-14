"""The Router's model-free code: route ROOT-approved canonical requests to the team's orchestrator.

A team is a registered workspace initiative, and its orchestrator is `<team>/orchestrator` in that
initiative's mailbox. The router actor and the borrowed `<team>/router` binding are configuration, not
authenticated identities. These tests show what the code delivers, records and refuses on fixtures; they
make no claim about what a real host lets a Router session do.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, raw_request, request
from tests.integration.test_hierarchy_mailbox import ROOT, invoke, mailbox_snapshot
from tests.integration.test_hierarchy_workspace import Workspace


pytestmark = pytest.mark.skipif(os.name != "posix", reason="durable lifecycle mutation requires POSIX directory fsync")
TOOL = ROOT / "tools" / "hierarchy_router.py"
TEAM_ENDPOINTS = ("front-door", "orchestrator", "root", "router")


@pytest.mark.parametrize("command", ["status","route"])
@pytest.mark.parametrize("planned", [False,True])
@pytest.mark.parametrize("damage", ["mailbox","team","bindings","across"])
def test_round13_public_target_error_holds_only_its_team(tmp_path,command,planned,damage):
    from tests.integration.test_hierarchy_fresh_brief import r13_consumer_probe,R13_CONSUMER_GOLDENS
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    assert r13_consumer_probe(tmp_path,command,planned,damage)==R13_CONSUMER_GOLDENS[(command,planned,damage)]


@pytest.mark.parametrize("seam", ["deliver","closing-report"])
def test_round13_delivery_and_closing_report_keep_baseline_disposition(tmp_path,seam):
    from tests.integration.test_hierarchy_fresh_brief import r13_consumer_probe,R13_CONSUMER_GOLDENS
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    damage="mailbox" if seam=="deliver" else "inputs"
    assert r13_consumer_probe(tmp_path,seam,False,damage)==R13_CONSUMER_GOLDENS[(seam,False,damage)]


R10_POLICY_TRACE = r'''
import json, sys
from pathlib import Path
from types import SimpleNamespace
tools, journal, store, phase, fault, telemetry, home = sys.argv[1:]
sys.path.insert(0, tools)
import hierarchy_router as router
import hierarchy_lifecycle as life
import hierarchy_workspace as workspace
import hierarchy_fresh_brief as fresh
home = Path(home)
(home / '.codex').mkdir(parents=True)
environment = {**router.os.environ, 'ROUND10_HOME': str(home / '.codex')}
router.os = SimpleNamespace(**{**vars(router.os), 'environ': environment})
router._owner_home = lambda: home
router._home_declarations = lambda: (('ROUND10_HOME', '.codex'),)
seen, guards = {'injected': False}, []
original = fresh._Operation.verify
identity_error = ValueError('cannot determine private directory identity')
def verified(self):
    original(self)
    if seen['injected']:
        return
    frames, frame = [], sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_filename.endswith('hierarchy_router.py'):
            frames.append((frame.f_code.co_name, frame.f_locals))
        frame = frame.f_back
    names = {name for name, _values in frames}
    selected = (
        phase == 'status-first' and any(name == 'status' and 'ledger' in values for name, values in frames)
        or phase == 'status-second' and any(name == 'row_view' and 'prior' in values and 'root' not in values
                                            for name, values in frames)
        or phase == 'report' and any(name == 'report' and 'ledger' in values for name, values in frames)
        or phase == 'route-report' and 'route' in names and any(name == 'report' and 'ledger' in values
                                                               for name, values in frames)
        or phase == 'delivery' and 'deliver' in names and any(name == 'attempt' and 'binding' in values
                                                             and 'published' not in values for name, values in frames))
    if selected:
        seen['injected'] = True
        guard = self.path_guard
        guards.append(guard)
        if fault == 'policy':
            environment['ROUND10_HOME'] = str(home / 'changed')
        else:
            guard._identity_error = identity_error
fresh._Operation.verify = verified
if phase == 'report':
    try:
        value = router.report(life.Lifecycle(journal), workspace.Store(store), 0)
    except (ValueError, OSError) as error:
        print(json.dumps({'error': str(error)}))
        code = 2
    else:
        print(json.dumps({'result': value}))
        code = 0
else:
    command = (['route', '--actor', 'router-1', '--evidence-only'] if phase in {'route-report', 'delivery'}
               else ['status'])
    code = router.main(['--lifecycle', journal, '--store', store, *command, '--wait', '0'])
if guards:
    guard = guards[0]
    failure = guard._global_failure
    seen['guard_latched'] = failure is not None
    seen['type'] = type(failure).__name__
    environment['ROUND10_HOME'] = str(home / '.codex')
    guard._identity_error = None
    try:
        guard.current()
    except (ValueError, OSError) as error:
        seen['retry_same'] = error is failure
    else:
        seen['retry_same'] = False
    router._CapturedPathGuard().current()
    seen['independent_healthy'] = True
Path(telemetry).write_text(json.dumps(seen))
sys.exit(code)
'''


@pytest.mark.parametrize("phase", ["status-first", "status-second", "report", "route-report", "delivery"])
@pytest.mark.parametrize("fault", ["policy", "identity"])
def test_round10_latched_policy_is_never_a_mailbox_row_refusal(loop, phase, fault):
    loop.approved(request("ordinary"))
    telemetry = loop.tmp / "policy-trace.json"
    result = subprocess.run([sys.executable, "-I", "-B", "-c", R10_POLICY_TRACE,
        str(ROOT / "tools"), str(loop.ledger.path), str(loop.workspace.store), phase, fault,
        str(telemetry), str(loop.tmp / "owner")], capture_output=True, timeout=30)
    assert result.stderr == b"", result.stderr
    seen = json.loads(telemetry.read_text())
    assert seen["injected"] and seen["guard_latched"], seen
    assert seen["retry_same"] and seen["independent_healthy"], seen
    expected_type = "CapturedPolicyError" if fault == "policy" else "ValueError"
    assert seen["type"] == expected_type
    expected = ("host-home configuration changed during capture" if fault == "policy"
                else "cannot determine private directory identity")
    assert result.returncode == 2, result.stdout
    assert json.loads(result.stdout)["error"] == expected
    if phase == "delivery":
        assert loop.inbox("engine") == []


def team_mailbox(tmp_path, team, endpoints=TEAM_ENDPOINTS, bound=TEAM_ENDPOINTS):
    root = tmp_path / team / "mailbox"
    root.parent.mkdir(parents=True, exist_ok=True)
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {team + "/" + e: {} for e in endpoints},
                          "counterparts": [], "writer_limit": 3})
    for endpoint in bound:
        invoke(root, "bind", {"endpoint": team + "/" + endpoint, "host": "host-one", "session": team + "-" + endpoint,
                              "expected_generation": 0})
    return root


class Loop:
    def __init__(self, tmp_path, policy_changes=None):
        self.tmp = tmp_path
        self.ledger = Ledger(tmp_path, policy_changes=policy_changes)
        self.workspace = Workspace(tmp_path)
        self.workspace.run("init", {"writer_limit": 3, "heavy_limit": 1})
        self.mailboxes = {}

    def team(self, team, **options):
        self.mailboxes[team] = team_mailbox(self.tmp, team, **options)
        self.workspace.register(team, mailbox_root=str(self.mailboxes[team]))
        return self.mailboxes[team]

    def approved(self, value):
        self.ledger.publish(value)
        self.ledger.approve(value)
        return value

    def run(self, command, *args, expect=0):
        proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", str(self.ledger.path),
                               "--store", str(self.workspace.store), command, *args],
                              capture_output=True, text=True, timeout=30,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        assert not proc.stderr, proc.stderr
        assert proc.returncode == expect, proc.stdout
        return json.loads(proc.stdout)

    def route(self, *args, actor="router-1", expect=0):
        return self.run("route", "--actor", actor, "--evidence-only", "--wait", "0.2", *args, expect=expect)

    def status(self):
        return {row["request_id"]: row for row in self.run("status")["requests"]}

    def inbox(self, team, endpoint="orchestrator"):
        return invoke(self.mailboxes[team], "inbox", endpoint=team + "/" + endpoint)["messages"]

    def row(self, value):
        return self.ledger.status()["requests"][value["id"]]


@pytest.fixture
def loop(tmp_path):
    space = Loop(tmp_path)
    space.team("engine")
    return space


@pytest.mark.parametrize("entry", ["status", "report", "route", "mcp"])
def test_round6_one_identity_snapshot_per_public_request(loop, monkeypatch, entry):
    import hierarchy_router as router
    import hierarchy_lifecycle as life
    import hierarchy_workspace as workspace
    import hierarchy_mailbox_mcp as mcp
    private = loop.tmp / "private"
    private.mkdir()
    calls = []
    real_os = router.os
    def stated(path, *args, **kwargs):
        if not isinstance(path, int) and Path(path) == private:
            calls.append(path)
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: loop.tmp / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND6_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated,
        "environ": {**os.environ, "ROUND6_HOME": str(private)}}))
    journal, store = life.Lifecycle(loop.ledger.path), workspace.Store(loop.workspace.store)
    connection = mcp.Connection(loop.mailboxes["engine"], "engine/router", "host-one", "engine-router", 1,
        workspace_store=loop.workspace.store, initiative="engine", lifecycle=loop.ledger.path)
    for _ in range(2):
        calls.clear()
        if entry == "mcp":
            answer = mcp.handle(connection, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "router_status", "arguments": {}}})
            assert not answer.get("isError"), answer
        elif entry == "status": router.status(journal, store, 0)
        elif entry == "report": router.report(journal, store, 0)
        else: router.route(journal, store, "router-1", 0)
        assert calls == [private], calls


@pytest.mark.parametrize("nested", [False, True], ids=["single", "nested"])
@pytest.mark.parametrize("surface,flag", [("router", "--lifecycle"), ("router", "--store"),
    ("router", "--recipes"), ("compose", "--root"), ("compose", "--lifecycle"),
    ("compose", "--delivery-dir"), ("verify", "--path"), ("loop", "--lifecycle"),
    ("loop", "--store"), ("loop", "--recipes"), ("loop", "--state-dir")])
def test_round6_no_plan_symlink_refusal_bytes(tmp_path, surface, flag, nested):
    from tests.conftest import symlink_or_skip
    public, linked = tmp_path / "public", tmp_path / "linked"
    public.mkdir()
    symlink_or_skip(public, linked, target_is_directory=True)
    target = str(linked / "input")
    if nested:
        destination = tmp_path / "destination"
        destination.mkdir()
        symlink_or_skip(destination, public / "inner", target_is_directory=True)
        target = str(linked / "inner/input")
    if surface == "router":
        tool = TOOL
        arguments = ["--lifecycle", str(tmp_path / "journal"), "--store", str(tmp_path / "store"),
                     "status", "--recipes", str(tmp_path / "recipes")]
    elif surface == "loop":
        tool = ROOT / "tools/hierarchy_loop.py"
        arguments = ["--lifecycle", str(tmp_path / "journal"), "--store", str(tmp_path / "store"),
            "--recipes", str(tmp_path / "recipes"), "--state-dir", str(tmp_path / "state"), "once"]
    elif surface == "compose":
        tool = ROOT / "tools/hierarchy_fresh_brief.py"
        arguments = ["compose", "--root", str(tmp_path / "mailbox"), "--initiative", "engine",
            "--endpoint", "engine/router", "--lifecycle", str(tmp_path / "journal"),
            "--delivery-dir", str(tmp_path / "delivery")]
    else:
        tool = ROOT / "tools/hierarchy_fresh_brief.py"
        arguments = ["verify", "--path", target, "--sha256", "0" * 64]
    arguments[arguments.index(flag) + 1] = target
    result = subprocess.run([sys.executable, "-I", "-B", str(tool), *arguments],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and not result.stderr, result.stdout + result.stderr
    assert json.loads(result.stdout)["error"].encode() == ("symlink paths are not supported: " + str(linked)).encode()


def test_round8_stored_public_scope_symlink_is_a_global_cli_refusal(loop):
    from tests.conftest import symlink_or_skip
    public, linked = loop.tmp / "public", loop.tmp / "linked"
    public.mkdir()
    linked.mkdir()
    loop.approved(request("hostile", paths=[str(linked / "file.py")]))
    linked.rmdir()
    symlink_or_skip(public, linked, target_is_directory=True)
    expected = "symlink paths are not supported: " + str(linked)
    for _ in range(2):
        answer = loop.run("status", "--wait", "5", expect=2)
        assert answer["error"].encode() == expected.encode()
        assert answer["state"] == "hold" and "requests" not in answer


def test_round6_no_plan_missing_journal_lock_bytes(tmp_path):
    result = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", str(tmp_path / "journal"),
        "--store", str(tmp_path / "store"), "status", "--wait", "0"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 2 and not result.stderr
    assert json.loads(result.stdout)["error"] == "[Errno 2] No such file or directory: " + repr(str(tmp_path / "journal/.write.lock"))


@pytest.mark.parametrize("component", ["root", "ancestor"])
@pytest.mark.parametrize("surface", ["status", "lock", "deliver"])
def test_round7_no_plan_not_directory_lock_bytes(tmp_path, component, surface):
    import errno
    import hierarchy_router as router
    import hierarchy_fresh_brief as fresh
    import hierarchy_lifecycle as life
    import hierarchy_workspace as workspace
    if not fresh._reference_descriptors(): pytest.skip("secure lock requires directory descriptors")
    world = Loop(tmp_path)
    world.team("engine")
    value = world.approved(request())
    ordinary = tmp_path / "ordinary"
    ordinary.write_text("regular file")
    root = ordinary if component == "root" else ordinary / "nested"
    expected = str(NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(root / ".write.lock")))
    def probe():
        if surface == "status":
            result = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", str(root),
                "--store", str(world.workspace.store), "status", "--wait", "0"],
                capture_output=True, text=True, timeout=30)
            assert result.returncode == 2 and not result.stderr
            assert json.loads(result.stdout)["error"].encode() == expected.encode()
        elif surface == "deliver":
            ledger = workspace.Store(world.workspace.store).load()
            ledger.initiatives["engine"]["mailbox_root"] = str(root)
            delivered, refusal = router.deliver(life.Lifecycle(world.ledger.path), ledger, "router-1", value["id"], 5)
            assert delivered is None
            assert refusal == {"reason": "delivery_error", "detail": expected}
        else:
            with pytest.raises(NotADirectoryError) as refusal:
                with router.writer_lock(root): pass
            assert str(refusal.value).encode() == expected.encode()
    probe()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(probe), pool.submit(probe)]: future.result(timeout=30)
    ordinary.unlink()
    root.mkdir(parents=True)
    with router.writer_lock(root): assert (root / ".write.lock").is_file()
    assert not (root / ".write.lock").exists()


def test_round6_no_plan_lock_permission_bytes_and_retry(tmp_path, monkeypatch):
    import errno
    import hierarchy_router as router
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors(): pytest.skip("secure lock requires directory descriptors")
    root, real_os, failed = tmp_path.resolve(), router.os, []
    def opened(path, *args, **kwargs):
        if path == ".write.lock" and not failed:
            failed.append(True)
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
        return real_os.open(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "open": opened}))
    with pytest.raises(PermissionError) as refusal:
        with router.writer_lock(root): pass
    assert str(refusal.value).encode() == ("[Errno 13] Permission denied: " + repr(str(root / ".write.lock"))).encode()
    assert not (root / ".write.lock").exists()
    with router.writer_lock(root): assert (root / ".write.lock").exists()
    assert not (root / ".write.lock").exists()


@pytest.mark.parametrize("stage", ["open", "stat", "fstat"])
def test_round6_lock_parent_errors_without_errno_are_refused_and_closed(tmp_path, monkeypatch, stage):
    import hierarchy_router as router
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors(): pytest.skip("secure lock requires directory descriptors")
    root, injected, live = tmp_path.resolve(), [], set()
    def fail(which):
        if stage == which and not injected:
            injected.append(which)
            raise OSError("UNTRUSTED errno-less parent failure")
    def opened(path, *args, **kwargs):
        fail("open")
        descriptor = os.open(path, *args, **kwargs)
        live.add(descriptor)
        return descriptor
    def stated(path, *args, **kwargs):
        if path == root.anchor: fail("stat")
        return os.stat(path, *args, **kwargs)
    def fstated(descriptor):
        fail("fstat")
        return os.fstat(descriptor)
    def closed(descriptor):
        live.discard(descriptor)
        return os.close(descriptor)
    boundary = SimpleNamespace(**{**vars(os), "open": opened, "stat": stated, "fstat": fstated, "close": closed})
    monkeypatch.setattr("hierarchy_router.os", boundary)
    monkeypatch.setattr("hierarchy_fresh_brief.os", boundary)
    with pytest.raises(ValueError, match="^cannot create journal lock$"):
        with router.writer_lock(root): pass
    assert injected == [stage] and not live
    assert not (root / ".write.lock").exists()
    with router.writer_lock(root): pass
    assert not live and not (root / ".write.lock").exists()


def test_an_approved_request_reaches_the_team_orchestrator_with_its_exact_bytes(loop):
    value = loop.approved(request("feature-1"))
    target = raw_request(value)
    assert loop.status()["feature-1"]["state"] == "ready"

    result = loop.route()

    assert [r["request_id"] for r in result["routed"]] == ["feature-1"]
    assert result["execution_enabled"] is False
    messages = loop.inbox("engine")
    assert len(messages) == 1
    message = messages[0]["message"]
    assert (message["from"], message["to"], message["type"]) == ("engine/router", "engine/orchestrator", "info")
    assert message["message_id"] == "route-" + target["sha256"]
    body = json.loads(message["body"])
    assert body == {"schema": "aegis.routed-request/v1", "request_id": "feature-1",
                    "request_sha256": target["sha256"], "request": target}
    routed = loop.row(value)["routed"]
    assert (routed["actor"], routed["generation"], routed["to"]) == ("router-1", 1, "engine/orchestrator")
    status = loop.status()["feature-1"]
    assert (status["state"], status["to"], status["team"]) == ("routed", "engine/orchestrator", "engine")


def test_routing_again_delivers_nothing_new_and_records_nothing(loop):
    loop.approved(request("feature-1"))
    loop.route()
    journal, mailbox = loop.ledger.files(), mailbox_snapshot(loop.mailboxes["engine"])

    again = loop.route()

    assert again["routed"] == []
    assert loop.ledger.files() == journal
    assert mailbox_snapshot(loop.mailboxes["engine"]) == mailbox


def test_a_busy_journal_refuses_the_run_before_anything_is_delivered(loop):
    loop.approved(request("feature-1"))
    lock = loop.ledger.path / ".write.lock"
    lock.write_text("{}")
    try:
        result = loop.route(expect=2)
    finally:
        lock.unlink()

    assert "busy" in result["error"]
    assert loop.inbox("engine") == []
    assert loop.status()["feature-1"]["state"] == "ready"


def test_a_busy_team_mailbox_holds_only_that_request(loop):
    loop.team("docs")
    loop.approved(request("feature-1"))
    loop.approved(request("feature-2", team="docs"))
    lock = loop.mailboxes["engine"] / ".write.lock"
    lock.write_text("{}")
    try:
        result = loop.route()
    finally:
        lock.unlink()

    assert [r["request_id"] for r in result["routed"]] == ["feature-2"]
    held = {row["request_id"]: row for row in result["requests"]}["feature-1"]
    assert (held["state"], held["reason"]) == ("held", "delivery_error")
    assert "busy" in held["detail"]
    assert loop.inbox("engine") == []
    assert [r["request_id"] for r in loop.route()["routed"]] == ["feature-1"]


def test_a_lost_journal_write_after_delivery_is_finished_by_the_next_run_without_a_second_message(loop):
    value = loop.approved(request("feature-1"))
    published = deliver_without_recording(loop, value)
    assert loop.row(value)["routed"] is None

    result = loop.route()

    assert [r["request_id"] for r in result["routed"]] == ["feature-1"]
    assert [m["message"]["message_id"] for m in loop.inbox("engine")] == [published]
    assert loop.row(value)["routed"]["to"] == "engine/orchestrator"


def deliver_without_recording(loop, value):
    """Publish exactly what the router would, as its borrowed binding, and stop before the journal write."""
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_router  # noqa: E402
    target = raw_request(value)
    identifier = hierarchy_router.route_id(target["sha256"])
    invoke(loop.mailboxes["engine"], "publish", {
        "message_id": identifier, "from": "engine/router", "to": "engine/orchestrator", "host": "host-one",
        "session": "engine-router", "binding_generation": 1, "type": "info",
        "body": hierarchy_router.route_body(value["id"], target)})
    return identifier


def test_a_message_id_that_names_different_content_is_held_and_not_recorded(loop):
    value = loop.approved(request("feature-1"))
    identifier = "route-" + raw_request(value)["sha256"]
    invoke(loop.mailboxes["engine"], "publish", {
        "message_id": identifier, "from": "engine/router", "to": "engine/orchestrator", "host": "host-one",
        "session": "engine-router", "binding_generation": 1, "type": "info", "body": "something else"})

    result = loop.route()

    assert result["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["reason"]) == ("held", "route_message_conflict")
    assert loop.row(value)["routed"] is None


def test_only_approved_live_authority_requests_are_routed(loop):
    pending = request("pending-1")
    loop.ledger.publish(pending)
    denied = request("denied-1")
    loop.ledger.publish(denied)
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="no", **loop.ledger.target(denied))
    withdrawn = loop.approved(request("withdrawn-1"))
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="withdrawn", **loop.ledger.target(withdrawn))

    result = loop.route()

    assert result["routed"] == []
    assert loop.inbox("engine") == []
    states = {key: row["state"] for key, row in loop.status().items()}
    assert states == {"pending-1": "awaiting_decision", "denied-1": "denied", "withdrawn-1": "denied"}


def test_an_expired_approval_is_held(loop):
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 2))
    value = request("feature-1", continuation={"members": [], "max_starts": 1, "expires_at": expires})
    loop.approved(value)
    time.sleep(2.2)

    result = loop.route()

    assert result["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["reason"]) == ("held", "approval_expired")
    assert loop.inbox("engine") == []


def test_a_deny_after_routing_stays_routed_and_is_reported(loop):
    value = loop.approved(request("feature-1"))
    loop.route()
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="withdrawn", **loop.ledger.target(value))

    again = loop.route()

    assert again["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["revoked_after_route"]) == ("routed", True)
    assert len(loop.inbox("engine")) == 1


def test_a_continuation_member_is_not_routed_on_its_own(loop):
    member = request("member-1", authority="feature-1")
    member_raw = raw_request(member)
    parent = request("feature-1", continuation={"members": [{"id": "member-1", "sha256": member_raw["sha256"],
                                                             "phase": member["phase"], "operation": member["operation"]}],
                                                "max_starts": 2, "expires_at": "2099-01-01T00:00:00Z"})
    loop.approved(parent)
    loop.ledger.publish(member)

    result = loop.route()

    assert [r["request_id"] for r in result["routed"]] == ["feature-1"]
    assert set(loop.status()) == {"feature-1"}


def test_each_team_gets_its_own_requests(loop):
    loop.team("docs")
    loop.approved(request("feature-1"))
    loop.approved(request("feature-2", team="docs"))

    loop.route()

    assert [m["message"]["to"] for m in loop.inbox("engine")] == ["engine/orchestrator"]
    assert [json.loads(m["message"]["body"])["request_id"] for m in loop.inbox("docs")] == ["feature-2"]


def test_request_filter_routes_only_the_named_request(loop):
    loop.approved(request("feature-1"))
    loop.approved(request("feature-2"))

    result = loop.route("--request", "feature-2")

    assert [r["request_id"] for r in result["routed"]] == ["feature-2"]
    assert loop.status()["feature-1"]["state"] == "ready"


@pytest.mark.parametrize("setup,reason", [
    ("unregistered", "team_unregistered"),
    ("paused", "team_inactive"),
    ("done", "team_inactive"),
    ("no-mailbox", "team_has_no_mailbox"),
    ("no-router-endpoint", "router_endpoint_missing"),
    ("router-unbound", "router_unbound"),
    ("orchestrator-unbound", "orchestrator_unbound"),
    ("router-unacknowledged", "router_handoff_unacknowledged"),
])
def test_an_unroutable_team_is_held_with_a_reason_and_nothing_is_written(tmp_path, setup, reason):
    loop = Loop(tmp_path)
    if setup == "paused" or setup == "done":
        loop.team("engine")
        loop.workspace.run("update", {"initiative": "engine", "source": "owner", "state": setup})
    elif setup == "no-mailbox":
        loop.workspace.register("engine")
    elif setup == "no-router-endpoint":
        loop.team("engine", endpoints=("front-door", "orchestrator", "root"), bound=("front-door", "orchestrator", "root"))
    elif setup == "router-unbound":
        loop.team("engine", bound=("front-door", "orchestrator", "root"))
    elif setup == "orchestrator-unbound":
        loop.team("engine", bound=("front-door", "root", "router"))
    elif setup == "router-unacknowledged":
        root = loop.team("engine")
        brief = root.parent / "router-handoff.md"
        brief.write_bytes(b"Router handoff.\n")
        checkpoint = {"outgoing_stopped": True, "sources": [], "lease_refs": [], "completed_checks": [],
                      "pending_message_ids": [], "last_acknowledgment_ids": [],
                      "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}]}
        invoke(root, "bind", {"endpoint": "engine/router", "host": "host-one", "session": "engine-router-2",
                              "expected_generation": 1, "checkpoint": checkpoint})
    loop.approved(request("feature-1"))
    journal = loop.ledger.files()
    mailboxes = {team: mailbox_snapshot(root) for team, root in loop.mailboxes.items()}

    result = loop.route()

    assert result["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["reason"]) == ("held", reason)
    assert loop.ledger.files() == journal
    assert {team: mailbox_snapshot(root) for team, root in loop.mailboxes.items()} == mailboxes


@pytest.mark.parametrize("actor,error", [
    ("router-9", "router actor is not in the lifecycle policy: router-9"),
    ("coordinator-1", "actor coordinator-1 is a coordinator, not a router"),
])
def test_a_wrong_router_actor_is_refused_before_anything_is_written(loop, actor, error):
    loop.approved(request("feature-1"))
    journal, mailbox = loop.ledger.files(), mailbox_snapshot(loop.mailboxes["engine"])

    result = loop.route(actor=actor, expect=2)

    assert result == {"state": "hold", "execution_enabled": False, "error": error}
    assert loop.ledger.files() == journal
    assert mailbox_snapshot(loop.mailboxes["engine"]) == mailbox


def test_a_superseded_router_actor_is_refused(tmp_path):
    (tmp_path / "probe").mkdir()
    policy = Ledger(tmp_path / "probe", initialize=False).policy
    actors = {**policy["actors"], "router-2": {**policy["actors"]["router-1"], "generation": 2}}
    loop = Loop(tmp_path, {"actors": actors, "successors": {**policy["successors"], "router-1": "router-2"}})
    loop.team("engine")
    loop.approved(request("feature-1"))
    checkpoint = loop.ledger.cli("checkpoint")["sha256"]
    loop.ledger.event("succeed", actor="router-2", predecessor="router-1", checkpoint_sha256=checkpoint)

    result = loop.route(actor="router-1", expect=2)

    assert result["error"] == "router actor router-1 is not the current router (router-2)"
    assert loop.inbox("engine") == []
    assert [r["request_id"] for r in loop.route(actor="router-2")["routed"]] == ["feature-1"]


def test_status_names_the_current_router_so_a_caller_follows_succession(tmp_path):
    (tmp_path / "probe").mkdir()
    policy = Ledger(tmp_path / "probe", initialize=False).policy
    actors = {**policy["actors"], "router-2": {**policy["actors"]["router-1"], "generation": 2}}
    loop = Loop(tmp_path, {"actors": actors, "successors": {**policy["successors"], "router-1": "router-2"}})
    loop.team("engine")
    assert loop.run("status")["router"] == "router-1"
    checkpoint = loop.ledger.cli("checkpoint")["sha256"]
    loop.ledger.event("succeed", actor="router-2", predecessor="router-1", checkpoint_sha256=checkpoint)

    result = loop.run("status")

    assert result["router"] == "router-2"
    assert sorted(result) == ["authenticated", "escalations", "execution_enabled", "identity", "requests", "router",
                              "schema"]


def test_route_requires_evidence_only(loop):
    loop.approved(request("feature-1"))

    result = loop.run("route", "--actor", "router-1", expect=2)

    assert result["error"] == "routing requires --evidence-only; the router is configuration-bound and unauthenticated"
    assert loop.inbox("engine") == []


def test_the_router_actor_cannot_approve_or_execute_in_the_journal(loop):
    value = request("feature-1")
    loop.ledger.publish(value)
    target = loop.ledger.target(value)
    for kind, body in (("decision", {"decision": "approve", "reason": "self-approval"}),
                       ("intent", {"intent_id": "attempt-1"}),
                       ("start", {"intent_id": "attempt-1"})):
        refused = loop.ledger.event(kind, actor="router-1", expect=2, **target, **body)
        assert refused["error"] == "role router cannot record " + kind


def test_the_router_endpoint_cannot_dispatch_or_request_jobs(loop):
    root = loop.mailboxes["engine"]
    for kind, extra in (("dispatch", {"brief": {"path": str(loop.tmp / "brief.md"), "sha256": "a" * 64}}),
                        ("job_request", {})):
        refused = invoke(root, "publish", {"message_id": kind.replace("_", "-") + "-1", "from": "engine/router",
                                           "to": "engine/orchestrator", "host": "host-one", "session": "engine-router",
                                           "binding_generation": 1, "type": kind, "body": "run it", **extra}, ok=False)
        assert "error" in refused
    assert loop.inbox("engine") == []


def test_the_router_loads_no_execution_code():
    probe = ("import sys; sys.path.insert(0, %r); import hierarchy_router; "
             "print(sorted(m for m in sys.modules if m.startswith('hierarchy_')))" % str(ROOT / "tools"))
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", probe], capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0, proc.stderr
    loaded = set(json.loads(proc.stdout.replace("'", '"')))
    assert loaded.isdisjoint({"hierarchy_jobs", "hierarchy_wake", "hierarchy_operator", "hierarchy_provision",
                              "hierarchy_sweep", "hierarchy_watch_supervisor"}), loaded


def test_status_changes_nothing(loop):
    loop.approved(request("feature-1"))
    journal, mailbox = loop.ledger.files(), mailbox_snapshot(loop.mailboxes["engine"])
    store = {p: p.read_bytes() for p in Path(loop.workspace.store).rglob("*") if p.is_file()}

    result = loop.run("status")

    assert result["schema"] == "aegis.router-status/v1"
    assert result["execution_enabled"] is False
    assert result["router"] == "router-1"
    assert loop.ledger.files() == journal
    assert mailbox_snapshot(loop.mailboxes["engine"]) == mailbox
    assert {p: p.read_bytes() for p in Path(loop.workspace.store).rglob("*") if p.is_file()} == store


def test_a_lost_journal_write_then_a_deny_still_shows_the_delivery_and_records_it(loop):
    value = loop.approved(request("feature-1"))
    deliver_without_recording(loop, value)
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="withdrawn", **loop.ledger.target(value))

    before = loop.status()["feature-1"]
    assert (before["state"], before["revoked_after_route"]) == ("delivered_unrecorded", True)
    result = loop.route()

    assert [(r["request_id"], r["delivered"]) for r in result["routed"]] == [("feature-1", False)]
    row = loop.status()["feature-1"]
    assert (row["state"], row["revoked_after_route"]) == ("routed", True)
    assert len(loop.inbox("engine")) == 1


def test_a_lost_journal_write_on_an_expired_approval_is_still_recorded(loop):
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 2))
    value = loop.approved(request("feature-1", continuation={"members": [], "max_starts": 1, "expires_at": expires}))
    deliver_without_recording(loop, value)
    time.sleep(2.2)

    assert loop.status()["feature-1"]["state"] == "delivered_unrecorded"
    assert [r["request_id"] for r in loop.route()["routed"]] == ["feature-1"]
    assert loop.row(value)["routed"]["to"] == "engine/orchestrator"


def test_a_router_at_its_active_cap_delivers_nothing(loop):
    value = loop.approved(request("feature-1"))
    loop.ledger.event("meter", actor="operator-1", subject="router-1", active_seconds=3600, open_since=None)
    journal = loop.ledger.files()

    result = loop.route()

    assert result["routed"] == []
    row = {r["request_id"]: r for r in result["requests"]}["feature-1"]
    assert (row["state"], row["reason"]) == ("held", "delivery_error")
    assert row["detail"] == "actor cumulative active cap reached"
    assert loop.inbox("engine") == []
    assert loop.ledger.files() == journal
    assert loop.row(value)["routed"] is None


def test_a_closed_request_is_not_routed(loop):
    value = loop.approved(request("feature-1"))
    successor = request("feature-1b")
    loop.ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": raw_request(successor),
                      "evidence": loop.ledger.evidence}, **loop.ledger.target(value))
    journal = loop.ledger.files()

    result = loop.route()

    assert result["routed"] == []
    assert {k: r["state"] for k, r in loop.status().items()} == {"feature-1": "closed", "feature-1b": "awaiting_decision"}
    assert loop.inbox("engine") == []
    assert loop.ledger.files() == journal


@pytest.mark.parametrize("change", [{"to": "engine/root"}, {"from": "engine/front-door", "session": "engine-front-door"},
                                    {"type": "escalation"}])
def test_a_same_body_message_with_another_sender_recipient_or_type_is_a_conflict(loop, change):
    value = loop.approved(request("feature-1"))
    target = raw_request(value)
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_router  # noqa: E402
    invoke(loop.mailboxes["engine"], "publish", {
        "message_id": "route-" + target["sha256"], "from": "engine/router", "to": "engine/orchestrator",
        "host": "host-one", "session": "engine-router", "binding_generation": 1, "type": "info",
        "body": hierarchy_router.route_body("feature-1", target), **change})

    result = loop.route()

    assert result["routed"] == []
    row = loop.status()["feature-1"]
    assert (row["state"], row["reason"]) == ("held", "route_message_conflict")
    assert loop.row(value)["routed"] is None


def test_an_unreadable_team_mailbox_holds_only_that_team(loop):
    loop.workspace.register("docs", mailbox_root=str(loop.tmp / "docs" / "missing-mailbox"))
    loop.approved(request("feature-1"))
    loop.approved(request("feature-2", team="docs"))

    result = loop.route()

    assert [r["request_id"] for r in result["routed"]] == ["feature-1"]
    row = loop.status()["feature-2"]
    assert (row["state"], row["reason"]) == ("held", "team_mailbox_unreadable")
    assert row["detail"]


def test_a_request_too_large_for_one_message_is_held_in_status(loop):
    stem = "/fixture/" + "/".join(["d" * 50] * 5)
    value = loop.approved(request("feature-1", paths=["%s/%03d" % (stem, i) for i in range(256)]))

    assert loop.status()["feature-1"]["reason"] == "request_too_large"
    assert loop.route()["routed"] == []
    assert loop.inbox("engine") == []
    assert loop.row(value)["routed"] is None


def test_delivery_rechecks_the_decision_under_the_lock(loop):
    """A scan that saw the request approved must not deliver it if ROOT denied it before the lock was taken."""
    value = loop.approved(request("feature-1"))
    loop.ledger.event("decision", actor="root-1", decision="deny", reason="withdrawn", **loop.ledger.target(value))
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_router  # noqa: E402
    from hierarchy_lifecycle import Lifecycle  # noqa: E402
    from hierarchy_workspace import Store  # noqa: E402
    journal = loop.ledger.files()

    result = hierarchy_router.deliver(Lifecycle(loop.ledger.path), Store(loop.workspace.store).load(),
                                      "router-1", "feature-1", 0.2)

    assert result == (None, {"reason": "denied"})
    assert loop.inbox("engine") == []
    assert loop.ledger.files() == journal


@pytest.mark.parametrize("args,error", [
    (("--request", "nope"), "unknown request id: nope"),
    (("--request", "member-1"), "only an authority request is routed; member-1 travels inside feature-1"),
    (("--wait", "61"), "--wait must be between 0 and 60 seconds"),
    (("--wait", "-1"), "--wait must be between 0 and 60 seconds"),
])
def test_bad_route_arguments_are_refused_before_anything_is_written(loop, args, error):
    member = request("member-1", authority="feature-1")
    member_raw = raw_request(member)
    loop.approved(request("feature-1", continuation={"members": [{"id": "member-1", "sha256": member_raw["sha256"],
                                                                  "phase": member["phase"], "operation": member["operation"]}],
                                                     "max_starts": 2, "expires_at": "2099-01-01T00:00:00Z"}))
    loop.ledger.publish(member)
    journal, mailbox = loop.ledger.files(), mailbox_snapshot(loop.mailboxes["engine"])

    result = loop.run("route", "--actor", "router-1", "--evidence-only", *args, expect=2)

    assert result["error"] == error
    assert loop.ledger.files() == journal
    assert mailbox_snapshot(loop.mailboxes["engine"]) == mailbox


def test_status_names_a_busy_journal_as_the_source_of_its_refusal(loop):
    (loop.ledger.path / ".write.lock").write_text("{}")

    result = loop.run("status", expect=2)

    assert result["source"] == "journal" and "busy" in result["error"]
    assert (result["state"], result["execution_enabled"]) == ("hold", False)


def test_status_names_a_broken_workspace_store_as_the_source_of_its_refusal(loop):
    (Path(loop.workspace.store) / "events" / "junk").write_text("x")

    result = loop.run("status", expect=2)

    assert result == {"state": "hold", "execution_enabled": False, "source": "store",
                      "error": "unexpected workspace store entry: junk"}


def test_status_names_a_store_path_that_is_not_a_store_directory_as_the_source(loop, tmp_path):
    not_a_store = tmp_path / "store-file"
    not_a_store.write_text("x")
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", str(loop.ledger.path), "--store",
                           str(not_a_store), "status"], capture_output=True, text=True, timeout=30)

    assert proc.returncode == 2 and not proc.stderr
    assert json.loads(proc.stdout) == {"state": "hold", "execution_enabled": False, "source": "store",
                                       "error": "workspace store is not initialized"}


def test_status_names_a_refusal_constructing_the_store_as_the_source(loop, monkeypatch, capsysbinary):
    # Store() repeats cli_path's checks today, so only a race could make it refuse; the tag must not depend on that.
    sys.path.insert(0, str(ROOT / "tools"))
    import hierarchy_router

    def refusing(_path):
        raise ValueError("symlink paths are not supported: planted")

    monkeypatch.setattr(hierarchy_router, "Store", refusing)
    code = hierarchy_router.main(["--lifecycle", str(loop.ledger.path), "--store", str(loop.workspace.store), "status"])

    assert code == 2
    assert json.loads(capsysbinary.readouterr().out) == {"state": "hold", "execution_enabled": False, "source": "store",
                                                         "error": "symlink paths are not supported: planted"}


def test_status_names_a_bad_argument_as_the_source_of_its_refusal(loop):
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--lifecycle", "lifecycle", "--store",
                           str(loop.workspace.store), "status"], capture_output=True, text=True, timeout=30)

    assert proc.returncode == 2 and not proc.stderr
    assert json.loads(proc.stdout) == {"state": "hold", "execution_enabled": False, "source": "arguments",
                                       "error": "--lifecycle must be absolute without traversal: got 'lifecycle'"}


@pytest.mark.parametrize("flag", ["--lifecycle", "--store", "--recipes", "--state-dir"])
@pytest.mark.parametrize("invalid", ["relative", "traversal"])
def test_privacy_preflight_preserves_the_loops_argument_refusal(tmp_path, flag, invalid):
    paths = {name: str(tmp_path / name[2:]) for name in ("--lifecycle", "--store", "--recipes", "--state-dir")}
    value = "relative" if invalid == "relative" else str(tmp_path / "parent" / ".." / "input")
    paths[flag] = value
    arguments = [argument for name, path in paths.items() for argument in (name, path)]
    for _ in range(2):
        proc = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/hierarchy_loop.py"),
            *arguments, "once"], capture_output=True, text=True, timeout=30)
        assert proc.returncode == 2 and not proc.stderr, proc.stdout + proc.stderr
        assert json.loads(proc.stdout) == {"error": flag + " must be absolute without traversal: got " + repr(value)}
    assert list(tmp_path.iterdir()) == []


def test_a_route_refusal_carries_no_source(loop):
    (Path(loop.workspace.store) / "events" / "junk").write_text("x")

    assert "source" not in loop.route(expect=2)


@pytest.mark.parametrize("home_kind", ["CODEX_HOME", "CLAUDE_CONFIG_DIR", "TEST_EXTRA_PRIVATE_HOME", "default-codex", "default-claude", "unrelated"])
@pytest.mark.parametrize("command", ["status", "dispatch"])
def test_r12_public_router_private_roots_refuse_before_discovery(tmp_path, home_kind, command):
    """Refuse before private content discovery; trusted root identity metadata stays bounded."""
    import shutil
    world = Loop(tmp_path)
    home = tmp_path / "modelled-account"
    home.mkdir()
    private = home / (".codex" if home_kind == "default-codex" else ".claude") if home_kind.startswith("default-") else tmp_path / "relocated-private"
    private.mkdir()
    target = private / "journal" if home_kind != "unrelated" else tmp_path / "public-journal"
    shutil.copytree(world.ledger.path, target)
    script = r"""
import importlib.util, json, os, pwd, sys
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('hierarchy_router',sys.argv[1])
router=importlib.util.module_from_spec(spec);sys.modules['hierarchy_router']=router;spec.loader.exec_module(router)
import hierarchy_hosts
pwd.getpwuid=lambda uid: SimpleNamespace(pw_dir=sys.argv[2])
if sys.argv[3]=='TEST_EXTRA_PRIVATE_HOME':
    data=hierarchy_hosts.describe()
    data['hosts']['fixture-extra']={**next(iter(data['hosts'].values())),
        'home':{'variable':'TEST_EXTRA_PRIVATE_HOME','owner_folder':'.fixture-private','run_folder':'fixture-home'}}
    hierarchy_hosts.describe=lambda:data
for host in hierarchy_hosts.describe()['hosts'].values(): os.environ.pop(host['home']['variable'],None)
if not sys.argv[3].startswith('default-'): os.environ[sys.argv[3] if sys.argv[3]!='unrelated' else 'CODEX_HOME']=sys.argv[4]
private=Path(sys.argv[4]); accesses=[]; operations=[]; active=None; fd_paths={}
import hierarchy_fresh_brief as fresh
original_init=fresh._Operation.__init__
def initialized(self,*args,**kwargs):
    original_init(self,*args,**kwargs)
    operations.append(self)
fresh._Operation.__init__=initialized
original_identities=router._CapturedPathGuard.identities
def identities(self):
    global active
    owner=next((i for i,operation in enumerate(operations) if operation.path_guard is self),None)
    frame=sys._getframe(1)
    while frame is not None:
        candidate=frame.f_locals.get('operation',frame.f_locals.get('_operation'))
        if candidate in operations:owner=operations.index(candidate)
        frame=frame.f_back
    previous,active=active,owner
    try:return original_identities(self)
    finally:active=previous
router._CapturedPathGuard.identities=identities
def actual(path,kw):
    if isinstance(path,int):return fd_paths.get(path)
    if not isinstance(path,(str,bytes,os.PathLike)):return None
    value=Path(os.fsdecode(path))
    return fd_paths[kw['dir_fd']]/value if not value.is_absolute() and kw.get('dir_fd') in fd_paths else value
def observe(path,kind,kw=None):
    value=actual(path,kw or {})
    if value is not None and (value==private or private in value.parents):
        accesses.append({'path':str(value),'kind':kind,'operation':active})
old_stat,old_lstat,old_open,old_close=os.stat,os.lstat,os.open,os.close
def checked_stat(path,*a,**kw): observe(path,'stat',kw);return old_stat(path,*a,**kw)
def checked_lstat(path,*a,**kw): observe(path,'lstat',kw);return old_lstat(path,*a,**kw)
def opened(path,*a,**kw):
    value=actual(path,kw);observe(path,'open',kw);fd=old_open(path,*a,**kw)
    if value is not None:fd_paths[fd]=value
    return fd
def closed(fd):fd_paths.pop(fd,None);return old_close(fd)
os.stat,os.lstat,os.open,os.close=checked_stat,checked_lstat,opened,closed
sys.addaudithook(lambda event,args: observe(args[0],event) if event in {'open','os.scandir','os.listdir','os.mkdir'} and args else None)
try: code=router.main(sys.argv[6:])
finally: Path(sys.argv[5]).write_text(json.dumps(accesses))
sys.exit(code)
"""
    telemetry = tmp_path / "r12-private-accesses.json"
    args = ["--lifecycle", str(target), "--store", str(world.workspace.store), command]
    if command == "dispatch": args += ["--recipes", str(tmp_path / "absent-recipes"), "--evidence-only"]
    before = world.ledger.files(), tuple((p.relative_to(target).as_posix(), p.read_bytes()) for p in target.rglob("*") if p.is_file())
    process = subprocess.run([sys.executable,"-I","-B","-c",script,str(TOOL),str(home),home_kind,
        str(private),str(telemetry),*args],env=os.environ.copy(),capture_output=True,text=True,timeout=20)
    assert process.stderr == "", process.stdout + process.stderr
    answer = json.loads(process.stdout)
    accesses = json.loads(telemetry.read_text())
    if home_kind == "unrelated":
        assert all(row["path"] == str(private) and row["kind"] in {"stat", "lstat"}
                   and row["operation"] is not None for row in accesses), (accesses, answer)
        assert len({(row["path"], row["operation"]) for row in accesses}) == len(accesses), accesses
    else:
        assert accesses == [], answer
    if home_kind == "unrelated":
        assert process.returncode == 0, answer
    else:
        assert process.returncode == 2 and answer["error"] == "owner-private host directory is not an input", answer
    assert (world.ledger.files(), tuple((p.relative_to(target).as_posix(),p.read_bytes()) for p in target.rglob("*") if p.is_file())) == before


def test_r12_case_variant_private_root_on_case_insensitive_filesystem(tmp_path):
    # Probe the actual owned fixture filesystem; this is not native macOS/Windows qualification.
    sentinel = tmp_path / "CaseProbe"
    sentinel.write_text("modelled public sibling")
    if not (tmp_path / "cASEpROBE").exists():
        pytest.skip("owned fixture filesystem is case-sensitive; case-insensitive behavior requires that filesystem")
    world = Loop(tmp_path)
    private = tmp_path / "PrivateHome"
    private.mkdir()
    import shutil
    shutil.copytree(world.ledger.path, private / "journal")
    env = {**os.environ, "CODEX_HOME": str(private)}
    p = subprocess.run([sys.executable,"-I","-B",str(TOOL),"--lifecycle",str(tmp_path / "pRIVATEhOME/journal"),
        "--store",str(world.workspace.store),"status"],env=env,capture_output=True,text=True,timeout=20)
    assert p.returncode == 2 and json.loads(p.stdout)["error"] == "owner-private host directory is not an input", p.stdout


@pytest.mark.parametrize("insensitive", [False, True])
def test_r12_case_probe_is_read_only_outside_private_roots(tmp_path, insensitive):
    """Case probing never discovers private content; each operation may snapshot root metadata once."""
    import shutil
    # Resolve only the owned fixture root (/var and /tmp may be links on macOS).
    tmp_path = tmp_path.resolve()
    world=Loop(tmp_path)
    private=tmp_path / "PrivateHome";private.mkdir()
    candidate=tmp_path / "pRIVATEhOME"
    if candidate.exists():
        pytest.skip("distinct public/private case spellings require a case-sensitive fixture volume; the native case-insensitive guard is tested separately")
    candidate.mkdir()
    shutil.copytree(world.ledger.path,candidate / "journal")
    telemetry=tmp_path / "r12-case-io.json"
    script=r"""
import importlib.util,json,os,pwd,sys
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('hierarchy_router',sys.argv[1]);router=importlib.util.module_from_spec(spec);sys.modules['hierarchy_router']=router;spec.loader.exec_module(router)
pwd.getpwuid=lambda uid:SimpleNamespace(pw_dir=sys.argv[2])
private=Path(sys.argv[3]);os.environ['CODEX_HOME']=str(private)
insensitive=sys.argv[4]=='True';seen={'case_probes':0,'private':[]};operations=[];active=None
import hierarchy_fresh_brief as fresh
original_init=fresh._Operation.__init__
def initialized(self,*args,**kwargs):
    original_init(self,*args,**kwargs)
    operations.append(self)
fresh._Operation.__init__=initialized
original_identities=router._CapturedPathGuard.identities
def identities(self):
    global active
    owner=next((i for i,operation in enumerate(operations) if operation.path_guard is self),None)
    frame=sys._getframe(1)
    while frame is not None:
        candidate=frame.f_locals.get('operation',frame.f_locals.get('_operation'))
        if candidate in operations:owner=operations.index(candidate)
        frame=frame.f_back
    previous,active=active,owner
    try:return original_identities(self)
    finally:active=previous
router._CapturedPathGuard.identities=identities
aliases={p.name.swapcase():p for p in private.parent.iterdir() if p.name.casefold()!=private.name.casefold()}
old_stat,old_lstat,old_open,old_close=os.stat,os.lstat,os.open,os.close
fd_paths={}
def actual(path,kw):
    if isinstance(path,int):return fd_paths.get(path)
    value=Path(os.fsdecode(path))
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        parent=fd_paths.get(kw['dir_fd'])
        assert parent is not None, 'untracked fixture directory descriptor'
        value=parent/value
    return value
def record(path,kw,kind):
    value=actual(path,kw)
    if value is not None and (str(value).casefold()==str(private).casefold() or str(value).casefold().startswith(str(private).casefold()+'/')):
        seen['private'].append({'path':str(value),'kind':kind,'operation':active})
    return value
def inspected(path,*a,**kw):
    value=record(path,kw,'stat')
    if value is not None and value.parent==private.parent and value.name in aliases:
        seen['case_probes']+=1
        if insensitive:return old_stat(aliases[value.name],follow_symlinks=False)
    return old_stat(path,*a,**kw)
def linspected(path,*a,**kw):record(path,kw,'lstat');return old_lstat(path,*a,**kw)
def opened(path,*a,**kw):
    value=record(path,kw,'open');fd=old_open(path,*a,**kw)
    if value is not None:fd_paths[fd]=value
    return fd
def closed(fd):fd_paths.pop(fd,None);return old_close(fd)
os.stat,os.lstat,os.open,os.close=inspected,linspected,opened,closed
sys.addaudithook(lambda event,args: record(args[0],{},event) if event in {'open','os.scandir','os.listdir'} and args else None)
try:code=router.main(sys.argv[6:])
finally:Path(sys.argv[5]).write_text(json.dumps(seen))
sys.exit(code)
"""
    p=subprocess.run([sys.executable,"-I","-B","-c",script,str(TOOL),str(tmp_path / "account"),str(private),str(insensitive),str(telemetry),
        "--lifecycle",str(candidate / "journal"),"--store",str(world.workspace.store),"status"],
        env=os.environ.copy(),capture_output=True,text=True,timeout=20)
    assert not p.stderr,p.stdout+p.stderr
    seen=json.loads(telemetry.read_text());answer=json.loads(p.stdout)
    assert seen['case_probes']>0,(seen,answer)
    if insensitive:
        assert p.returncode==2 and answer['error']=='owner-private host directory is not an input',answer
    else:assert p.returncode==0,answer
    accesses = seen['private'] if insensitive else [row for row in seen['private']
        if row['path'] == str(private) or str(private) + os.sep in row['path']]
    assert all(row['path'] == str(private) and row['kind'] in {'stat', 'lstat'}
               and row['operation'] is not None for row in accesses), seen
    assert len({(row['path'], row['operation']) for row in accesses}) == len(accesses), seen
