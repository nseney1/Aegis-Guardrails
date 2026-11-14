"""R4 dispatcher through public CLIs. Hosts are modelled; no activation credit."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

if os.name == "posix":
    import pwd

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="dispatcher job settlement observes Linux process evidence")

from tests.integration.test_hierarchy_lifecycle import Ledger, raw_request, request
from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke, mailbox_snapshot
from tests.integration.test_hierarchy_router import Loop, deliver_without_recording
from tests.integration.test_hierarchy_small_change_admission import SmallChange


ROUTER = ROOT / "tools/hierarchy_router.py"


@pytest.mark.parametrize("planned", [False,True])
def test_round13_row_target_error_retains_its_baseline_hold(tmp_path,planned):
    from tests.integration.test_hierarchy_fresh_brief import r13_consumer_probe,R13_CONSUMER_GOLDENS
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    assert r13_consumer_probe(tmp_path,"row",planned)==R13_CONSUMER_GOLDENS[("row",planned,"inputs")]
JOBS = ROOT / "tools/hierarchy_jobs.py"


@pytest.mark.parametrize("entry", ["prove", "project", "plan", "refresh", "path", "store"])
def test_round6_dispatch_request_owns_all_helper_probes(tmp_path, monkeypatch, entry):
    from types import SimpleNamespace
    import hierarchy_router as router
    import hierarchy_fresh_brief as fresh
    import hierarchy_small_change_dispatch as dispatch
    import hierarchy_loop as loop
    import hierarchy_lifecycle as life
    import hierarchy_workspace as workspace
    world = DispatchWorld(tmp_path)
    private = tmp_path / "private"
    private.mkdir()
    real_os, calls = router.os, []
    def stated(path, *args, **kwargs):
        if not isinstance(path, int) and Path(path) == private: calls.append(path)
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND6_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated,
        "environ": {**os.environ, "ROUND6_HOME": str(private)}}))
    for _ in range(2):
        calls.clear()
        if entry == "store":
            (Path(world.workspace.store) / "events/.pending-round6").write_text("inert pending data")
            captured = dispatch._CapturedStore(world.workspace.store, fresh._Operation())
            captured.load()
        elif entry == "path": dispatch.checked_path(world.root)
        elif entry == "prove":
            operation = fresh._Operation()
            def verification():
                dispatch.checked_path(world.root)
                dispatch.checked_path(world.checkout)
                operation.exists(world.recipes_path)
            operation.prove(verification)
        elif entry == "project":
            result = dispatch.project(life.Lifecycle(world.ledger.path), workspace.Store(world.workspace.store),
                                      recipes=world.recipes_path)
            assert result["small_changes"][0]["state"] == "writer_ready", result
        else:
            work = loop.Pass(SimpleNamespace(dispatcher_host_plan=world.dispatcher_plan,
                lifecycle=world.ledger.path, store=world.workspace.store, recipes=world.recipes_path))
            if entry == "plan": work.validate_dispatcher_plan()
            else: assert work.refresh_planning(), work.holds
        assert calls == [private], calls


@pytest.mark.parametrize("field", ["worktree", "scan_workspace"])
@pytest.mark.parametrize("consumed", [False, True])
def test_round6_stored_readiness_identity_refusal_does_not_poison_dispatch(tmp_path, field, consumed):
    _round7_stored_readiness_probe(tmp_path, field, consumed)


@pytest.mark.parametrize("field", ["worktree", "scan_workspace"])
@pytest.mark.parametrize("consumed", [False, True])
@pytest.mark.parametrize("walk_failure", ["not-directory", "denied", "changed"])
def test_round7_stored_readiness_walk_refusal_does_not_poison_dispatch(tmp_path, field, consumed, walk_failure):
    _round7_stored_readiness_probe(tmp_path, field, consumed, walk_failure)


@pytest.mark.parametrize("consumed", [False, True])
def test_round8_private_symlink_readiness_remains_quarantined(tmp_path, consumed):
    _round7_stored_readiness_probe(tmp_path, "worktree", consumed, "private-symlink")


@pytest.mark.parametrize("spelling", ["private-home-suffix", "private-alias-target", "private-two-hop"])
@pytest.mark.parametrize("consumed", [False, True])
def test_round9_private_link_chain_readiness_is_message_local(tmp_path, consumed, spelling):
    _round7_stored_readiness_probe(tmp_path, "worktree", consumed, spelling)


def test_round8_public_symlink_readiness_stays_global(tmp_path):
    from tests.conftest import symlink_or_skip
    from hierarchy_mailbox import Mailbox
    import hierarchy_fresh_brief as fresh
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    ack = next(row for row in world.messages("ack") if "readiness" in row["message"])
    public, linked = tmp_path / "public", tmp_path / "linked"
    public.mkdir()
    linked.mkdir()
    rewrite_message(ack, lambda value: value["readiness"].update(worktree=str(linked), scan_workspace=str(linked)))
    linked.rmdir()
    symlink_or_skip(public, linked, target_is_directory=True)
    with pytest.raises(ValueError) as pinned:
        Mailbox(world.root).messages()
    expected = "malformed mailbox message: " + str(ack["path"]) + ": symlink paths are not supported: " + str(linked)
    assert str(pinned.value).encode() == expected.encode()
    def probe():
        mailbox = fresh._CapturedMailbox(world.root)
        with pytest.raises(ValueError) as captured:
            mailbox.messages()
        assert str(captured.value).encode() == expected.encode()
        result = subprocess.run([sys.executable, "-I", "-B", str(ROUTER), "--lifecycle", str(world.ledger.path),
            "--store", str(world.workspace.store), "status", "--recipes", str(world.recipes_path), "--wait", "5"],
            capture_output=True, text=True, timeout=30)
        assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
        row = json.loads(result.stdout)["small_changes"][0]
        assert (row["state"], row["reason"]) == ("held", "small_change_result_invalid")
        assert row["detail"].encode() == expected.encode()
        assert not row.get("mailbox_history_verified")
    probe()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in (pool.submit(probe), pool.submit(probe)): future.result(timeout=30)


def _round7_stored_readiness_probe(tmp_path, field, consumed, walk_failure="identity"):
    world = DispatchWorld(tmp_path)
    manifest = json.loads((world.root / "manifest.json").read_text())
    manifest["endpoints"]["engine/lane/historical"] = {"kind": "implementer"}
    (world.root / "manifest.json").write_text(json.dumps(manifest))
    world.dispatch()
    world.finish_writer()
    ack = next(row for row in world.messages("ack") if "readiness" in row["message"])
    # Keep this historical exchange unrelated to the current row, while preserving a valid ACK shape.
    def rewrite(value):
        value["message_id"] = "historical-ack"
        value["in_reply_to"] = "historical-dispatch"
    old_dispatch = world.messages("dispatch")[0]
    historical = copy.deepcopy(old_dispatch["message"])
    historical["message_id"] = "historical-dispatch"
    historical["to"] = "engine/lane/historical"
    historical_path = world.root / "engine/lane/historical-dispatch.md"
    historical_path.write_text("---\n" + json.dumps({k: v for k, v in historical.items() if k != "body"})
                               + "\n---\n\n" + historical["body"])
    original_ack = copy.deepcopy(ack["message"])
    ack_path = Path(ack["path"]).with_name("historical-ack.md")
    rewrite(original_ack)
    original_ack["from"] = "engine/lane/historical"
    private = tmp_path / "owner-home/.codex" if walk_failure == "private-home-suffix" else tmp_path / "private"
    target = (tmp_path / "alias" if walk_failure == "identity" else
              tmp_path / "alias/.codex/child" if walk_failure == "private-home-suffix" else tmp_path / "alias/child")
    original_ack["readiness"]["worktree"] = str(target)
    original_ack["readiness"]["scan_workspace"] = str(target)
    ack_path.write_text("---\n" + json.dumps({k: v for k, v in original_ack.items() if k != "body"})
                        + "\n---\n\n" + original_ack["body"])
    (tmp_path / "alias").mkdir()
    private.mkdir(parents=True)
    (tmp_path / "ordinary").write_text("regular file")
    if walk_failure.startswith("private-"):
        from tests.conftest import symlink_or_skip
        (tmp_path / "alias").rmdir()
        destination = private
        if walk_failure == "private-home-suffix": destination = private.parent
        if walk_failure == "private-alias-target":
            destination = tmp_path / "platform-alias"
            destination.mkdir()
        if walk_failure == "private-two-hop":
            destination = tmp_path / "second-link"
            symlink_or_skip(private, destination, target_is_directory=True)
        symlink_or_skip(destination, tmp_path / "alias", target_is_directory=True)
    if consumed:
        rewrite_message(ack, lambda value: value["readiness"].update(
            worktree=str(target), scan_workspace=str(target)))
    injection = r'''
import hierarchy_fresh_brief as fresh, hierarchy_router as canonical_router
private = Path(os.environ['ROUND6_PRIVATE'])
alias = Path(os.environ['ROUND6_ALIAS'])
failure = os.environ['ROUND7_WALK_FAILURE']
os.environ['CODEX_HOME'] = str(private)
if failure == 'private-home-suffix': canonical_router._owner_home = lambda: private.parent
identity = private.stat()
original_stat = os.stat
original_open = os.open
seen['alias_checks'] = 0
seen['forbidden'] = []
def actual(path, kwargs):
    value = Path(path)
    return value if value.is_absolute() else Path(os.readlink('/proc/self/fd/%d' % kwargs['dir_fd'])) / value
def stated(path, *args, **kwargs):
    value = actual(path, kwargs)
    platform_alias = alias.parent / 'platform-alias'
    if private in value.parents or platform_alias in value.parents:
        seen['forbidden'].append(str(value))
        raise AssertionError('private descendant metadata')
    if failure == 'private-alias-target' and value == platform_alias: return identity
    if value == alias:
        frame = sys._getframe(1)
        while frame is not None:
            if frame.f_code.co_name == 'readiness' and frame.f_code.co_filename.endswith('hierarchy_mailbox.py'):
                selected = 'scan_workspace' if 'worktree' in frame.f_locals else 'worktree'
                if selected == os.environ['ROUND6_FIELD']:
                    seen['alias_checks'] += 1
                    if failure == 'not-directory': return original_stat(alias.parent / 'ordinary')
                    if failure == 'denied': raise PermissionError(13, 'Permission denied', str(alias))
                    if failure == 'changed': raise ValueError('reference parent changed while opening')
                    if failure.startswith('private-'): return original_stat(path, *args, **kwargs)
                    return identity
            frame = frame.f_back
    return original_stat(path, *args, **kwargs)
def opened(path, *args, **kwargs):
    value = actual(path, kwargs)
    if value == private or private in value.parents or value == alias.parent / 'platform-alias':
        seen['forbidden'].append(str(value))
        raise AssertionError('private directory open')
    return original_open(path, *args, **kwargs)
fresh.os = SimpleNamespace(**{**vars(os), 'stat': stated, 'open': opened})
'''
    from concurrent.futures import ThreadPoolExecutor
    before = world.ledger.files(), mailbox_snapshot(world.root)
    def probe(index):
        return r7_router_probe(world, injection, command="status", extra=("--wait", "5"),
            telemetry=tmp_path / ("round6-readiness-%d.json" % index), environ={**os.environ,
            "ROUND6_PRIVATE": str(private), "ROUND6_ALIAS": str(tmp_path / "alias"), "ROUND6_FIELD": field,
            "ROUND7_WALK_FAILURE": walk_failure})
    outcomes = [probe(0)]
    with ThreadPoolExecutor(max_workers=2) as pool: outcomes += list(pool.map(probe, (1, 2)))
    for answer, _seen in outcomes:
        assert _seen["alias_checks"] > 0, (_seen, answer["small_changes"])
        assert not _seen["forbidden"]
        row = answer["small_changes"][0]
        if consumed or walk_failure in {"denied", "changed"}:
            reason = "small_change_configuration" if walk_failure in {"denied", "not-directory"} else "small_change_result_invalid"
            assert (row["state"], row["reason"]) == ("held", reason), row
            expected = {"identity": "owner-private host directory is not an input", "not-directory": "checkout is not registered",
                        "denied": "Permission denied", "changed": "reference parent changed while opening",
                        "private-symlink": "symlink paths are not supported: " + str(tmp_path / "alias")}.get(walk_failure,
                            "symlink paths are not supported: " + str(tmp_path / "alias"))
            assert expected in row["detail"], row
            assert "writer_publication_verified" not in row
        else:
            assert row["state"] == "checking", row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def assert_private_root_probes(roots, accesses):
    """Privacy checks permit only one metadata identity probe per trusted root/capture."""
    trusted, seen = {str(Path(root)) for root in roots}, set()
    for row in accesses:
        if (not isinstance(row, dict) or not isinstance(row.get("path"), str)
                or row["path"] not in trusted or row.get("kind") not in {"stat", "lstat"}
                or type(row.get("operation")) is not int or row["operation"] < 0):
            raise AssertionError("private access must be a single root identity probe")
        key = row["path"], row["operation"]
        if key in seen:
            raise AssertionError("private access must be a single root identity probe")
        seen.add(key)


# These spies run only in their owned subprocess, never in a pytest worker's OS module.
# All four privacy helpers emit the same observations for the predicate above.
PRIVATE_ROOT_PROBE = r'''
import hierarchy_router as _probe_router
_probe_roots = tuple(sorted(map(str, _probe_router._private_roots(
    _probe_router._owner_home(), _probe_router._home_declarations()))))
_probe_root_paths = tuple(map(Path, _probe_roots))
_probe_accesses, _probe_operations, _probe_fds = [], [], {}
import hierarchy_fresh_brief as _probe_fresh
_probe_init = _probe_fresh._Operation.__init__
def _probe_initialized(self, *args, **kwargs):
    _probe_init(self, *args, **kwargs)
    _probe_operations.append(self)
_probe_fresh._Operation.__init__ = _probe_initialized
_probe_active_operation = None
def _probe_bind(original):
    def identities(self):
        global _probe_active_operation
        owner = next((i for i, operation in enumerate(_probe_operations) if operation.path_guard is self), None)
        # Attribute fallback guards to their outer request, rather than granting
        # a new allowance simply because a helper constructed another object.
        frame = sys._getframe(1)
        while frame is not None:
            candidate = frame.f_locals.get('operation', frame.f_locals.get('_operation'))
            if candidate in _probe_operations:
                owner = _probe_operations.index(candidate)
            frame = frame.f_back
        previous, _probe_active_operation = _probe_active_operation, owner
        try: return original(self)
        finally: _probe_active_operation = previous
    return identities
for _probe_class in {router._CapturedPathGuard, _probe_router._CapturedPathGuard}:
    _probe_class.identities = _probe_bind(_probe_class.identities)
def _probe_actual(value, kwargs):
    if isinstance(value, int): return _probe_fds.get(value)
    if not isinstance(value, (str, bytes, os.PathLike)): return None
    path = Path(os.fsdecode(value))
    if not path.is_absolute() and kwargs.get('dir_fd') is not None:
        parent = _probe_fds.get(kwargs['dir_fd'])
        if parent is None: parent = Path(os.readlink('/proc/self/fd/%d' % kwargs['dir_fd']))
        path = parent/path
    return path
def _probe_record(kind, value, kwargs=None):
    path = _probe_actual(value, kwargs or {})
    if path is not None and any(path == root or root in path.parents for root in _probe_root_paths):
        _probe_accesses.append({'path': str(path), 'kind': kind, 'operation': _probe_active_operation})
    return path
_probe_stat, _probe_lstat, _probe_open, _probe_close, _probe_read = os.stat, os.lstat, os.open, os.close, os.read
def _probe_stated(path, *args, **kwargs):
    _probe_record('stat', path, kwargs)
    return _probe_stat(path, *args, **kwargs)
def _probe_lstated(path, *args, **kwargs):
    _probe_record('lstat', path, kwargs)
    return _probe_lstat(path, *args, **kwargs)
def _probe_opened(path, *args, **kwargs):
    actual = _probe_record('open', path, kwargs)
    descriptor = _probe_open(path, *args, **kwargs)
    if actual is not None: _probe_fds[descriptor] = actual
    return descriptor
def _probe_closed(descriptor):
    _probe_fds.pop(descriptor, None)
    return _probe_close(descriptor)
def _probe_consumed(descriptor, amount):
    _probe_record('read', descriptor)
    return _probe_read(descriptor, amount)
os.stat, os.lstat, os.open, os.close, os.read = _probe_stated, _probe_lstated, _probe_opened, _probe_closed, _probe_consumed
sys.addaudithook(lambda event, args: _probe_record(event, args[0])
    if args and event in {'open', 'os.scandir', 'os.listdir', 'os.mkdir'} else None)
'''


# The reader's portable backend is independent of the new descriptor-only lock.
# This shim belongs to the isolated child and preserves the real lock capability.
PORTABLE_REFERENCE_PROBE = r'''
import hierarchy_fresh_brief as fresh
_native_reference_descriptors = fresh._reference_descriptors
def portable_reference_support():
    frame = sys._getframe()
    while frame is not None:
        if frame.f_code.co_name == 'writer_lock' and frame.f_code.co_filename == router.__file__:
            return _native_reference_descriptors()
        frame = frame.f_back
    return False
fresh._reference_descriptors = portable_reference_support
'''


@pytest.mark.parametrize("case", ["none", "stat", "lstat", "two-roots", "two-captures"])
def test_private_probe_policy_accepts_only_bounded_identity_metadata(tmp_path, case):
    roots = [tmp_path / "private", tmp_path / "other-private"]
    accesses = []
    if case != "none":
        accesses.append({"path": str(roots[0]), "kind": "lstat" if case == "lstat" else "stat", "operation": 0})
    if case in {"two-roots", "two-captures"}:
        accesses.append({"path": str(roots[1] if case == "two-roots" else roots[0]),
                         "kind": "stat", "operation": 0 if case == "two-roots" else 1})
    assert_private_root_probes(roots, accesses)


@pytest.mark.parametrize("case", ["below-stat", "root-open", "root-listdir", "duplicate-stat",
                                  "root-read", "root-scandir", "root-iterdir", "unbound-operation"])
def test_private_probe_policy_refuses_content_and_repeated_identity_access(tmp_path, case):
    root = tmp_path / "private"
    row = {"path": str(root / "record" if case == "below-stat" else root),
           "kind": {"root-open": "open", "root-listdir": "os.listdir", "root-read": "read",
                    "root-scandir": "os.scandir", "root-iterdir": "iterdir"}.get(case, "stat"),
           "operation": None if case == "unbound-operation" else 0}
    accesses = [row, dict(row)] if case == "duplicate-stat" else [row]
    with pytest.raises(AssertionError, match="^private access must be a single root identity probe$"):
        assert_private_root_probes([root], accesses)


class DispatchWorld(Loop):
    def __init__(self, tmp_path, *, writer_kind="implementer", reviewers=1, checks=1, expires=None,
                 recipe_changes=None, mismatched_check=False, private_evidence=False):
        seed = Ledger(tmp_path, initialize=False)
        actors = {**seed.policy["actors"], "router-2": {**seed.policy["actors"]["router-1"], "generation": 2}}
        super().__init__(tmp_path, policy_changes={"actors": actors,
                         "successors": {**seed.policy["successors"], "router-1": "router-2"}})
        self.dispatcher_plan = modelled_loop_plan(tmp_path)
        self.root = tmp_path / "engine/mailbox"
        self.root.parent.mkdir(parents=True)
        endpoints = {"engine/" + e: {} for e in ("front-door", "orchestrator", "root", "router", "decider")}
        endpoints["engine/lane/fix"] = {"kind": writer_kind}
        endpoints.update({"engine/lane/review" + str(n): {"kind": "reviewer"} for n in range(reviewers)})
        invoke(self.root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints,
                                   "counterparts": [], "writer_limit": 3})
        for endpoint in endpoints:
            invoke(self.root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                                       "expected_generation": 0})
        self.mailboxes["engine"] = self.root
        self.checkout = tmp_path / "checkout"
        self.checkout.mkdir()
        git(self.checkout, "init", "-q", "-b", "candidate")
        (self.checkout / "app.txt").write_text("candidate\n")
        git(self.checkout, "add", "app.txt")
        git(self.checkout, "commit", "-qm", "candidate")
        self.revision = git(self.checkout, "rev-parse", "HEAD")
        self.tree = git(self.checkout, "rev-parse", "HEAD^{tree}")
        self.workspace.register("engine", mailbox_root=str(self.root), checkouts=[str(self.checkout)])
        self.recipes = {"schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable,
                        "path": ["/usr/bin", "/bin"], "recipes": {
                            "focused": {"kind": "command", "heavy": False, "require_clean": True,
                                        "sandbox": "none", "timeout_seconds": 10,
                                        "steps": [["$python", "-c", "print('checked')"]]}}}
        self.recipes_path = tmp_path / "recipes.json"
        self.recipes["recipes"]["focused"].update(recipe_changes or {})
        self.save_recipes()
        value = request()
        if expires:
            value["continuation"]["expires_at"] = expires
        self.change = SmallChange(self.ledger, value)
        self.change.plan["plan"]["checks"] = ["check-" + str(n) for n in range(checks)]
        self.change.register()
        self.change.decide()
        admission = self.change.admission()
        admission["checks"] = [{"check": c, "recipe": "focused", "recipes_sha256": self.recipe_hash,
                                "evidence": self.ledger.evidence} for c in self.change.plan["plan"]["checks"]]
        if mismatched_check:
            admission["checks"][-1]["recipes_sha256"] = "e" * 64
        if private_evidence:
            private = tmp_path / "home/.codex/evidence"
            private.parent.mkdir(parents=True)
            private.write_text("modelled private file; dispatcher must not open it")
            admission["gates"]["capability"] = [{"path": str(private), "sha256": hashlib.sha256(private.read_bytes()).hexdigest()}]
        self.change.admit(admission)

    def save_recipes(self):
        self.recipes_path.write_text(json.dumps(self.recipes))
        self.recipe_hash = hashlib.sha256(self.recipes_path.read_bytes()).hexdigest()

    def dispatch(self, *, fault=None, expect=0, command="dispatch", timeout=40):
        args = ["--lifecycle", str(self.ledger.path), "--store", str(self.workspace.store), command,
                "--recipes", str(self.recipes_path), "--wait", "0.1"]
        if command == "dispatch":
            args.append("--evidence-only")
        if fault == "batch-deny":
            actor = self.ledger.root_actor
            generation = self.ledger.policy["actors"][actor]["generation"]
            envelope = {"id": "owner-mid-batch-deny", "actor": actor, "generation": generation,
                "custody": {"cid": actor, "generation": generation}, "event": {"type": "decision",
                  **self.ledger.target(self.change.value), "decision": "deny", "reason": "owner denial during publication"}}
            (self.tmp / "mid-batch-deny.json").write_text(json.dumps(envelope))
        argv = [sys.executable, "-I", "-B", str(ROUTER)]
        if fault:
            # Fault only at the OS publication boundary, keeping the public command unchanged.
            script = """
import importlib.util, json, os, sys
import datetime
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_router', sys.argv[1])
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
original = os.link
count = 0
class Future(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return super().now(tz) + datetime.timedelta(days=36500)
if sys.argv[2] == 'future':
    # The host wall clock is an OS boundary; business validation stays real.
    import hierarchy_mailbox
    hierarchy_mailbox.datetime = Future
if sys.argv[2] == 'private':
    import pwd
    home = Path(sys.argv[sys.argv.index('--lifecycle')+1]).parent / 'home'
    original_user = pwd.getpwuid(os.getuid())
    pwd.getpwuid = lambda uid: pwd.struct_passwd((*original_user[:5], str(home), original_user.pw_shell))
def link(src, dst, *args, **kwargs):
    global count
    path = Path(dst)
    if sys.argv[2] == 'route' and path.parent.name == 'events':
        event = json.loads(Path(src).read_text())['envelope']['event']
        if event['type'] == 'route': raise OSError('injected route append failure')
    if sys.argv[2] == 'route-committed' and path.parent.name == 'events':
        event = json.loads(Path(src).read_text())['envelope']['event']
        if event['type'] == 'route':
            original(src, dst, *args, **kwargs)
            raise OSError('injected lost committed route reply')
    if sys.argv[2] == 'batch' and path.suffix == '.md' and path.parent.name == 'root':
        count += 1
        if count == 2: raise OSError('injected second job publication failure')
    if sys.argv[2] in {'batch-drift', 'batch-deny', 'batch-expiry'} and path.suffix == '.md' and path.parent.name == 'root':
        count += 1
        answer = original(src, dst, *args, **kwargs)
        if count == 1:
            if sys.argv[2] == 'batch-drift':
                recipes = Path(sys.argv[sys.argv.index('--recipes')+1])
                recipes.write_bytes(recipes.read_bytes()+bytes([10]))
            elif sys.argv[2] == 'batch-expiry':
                import hierarchy_mailbox
                hierarchy_mailbox.datetime = Future
            else:
                import subprocess
                lifecycle = Path(sys.argv[sys.argv.index('--lifecycle')+1])
                result = subprocess.run([sys.executable, '-I', '-B', str(Path(sys.argv[1]).with_name('hierarchy_lifecycle.py')),
                    '--root', str(lifecycle), 'record', '--event', str(lifecycle.parent/'mid-batch-deny.json'), '--evidence-only'],
                    capture_output=True, text=True, env=os.environ.copy())
                if result.returncode: raise RuntimeError(result.stdout+result.stderr)
        return answer
    if sys.argv[2] == 'late-route' and path.suffix == '.md' and path.parent.name == 'lane':
        answer = original(src, dst, *args, **kwargs)
        import hierarchy_mailbox
        hierarchy_mailbox.datetime = Future
        return answer
    return original(src, dst, *args, **kwargs)
os.link = link
sys.exit(module.main(sys.argv[3:]))
"""
            argv = [sys.executable, "-I", "-B", "-c", script, str(ROUTER), fault]
        proc = subprocess.run(argv + args, env=os.environ.copy(), capture_output=True, text=True, timeout=timeout)
        assert proc.returncode == expect, proc.stdout + proc.stderr
        assert not proc.stderr, proc.stderr
        return json.loads(proc.stdout)

    def projection(self):
        return self.run("status", "--recipes", str(self.recipes_path), "--wait", "0.1")["small_changes"][0]

    def messages(self, kind=None):
        from tools.hierarchy_mailbox import Mailbox
        return [r for r in Mailbox(self.root).messages().values()
                if kind is None or r["message"]["type"] == kind]

    def publish_lane(self, endpoint, parent, kind, **extra):
        return invoke(self.root, "publish", {"message_id": kind + "-" + endpoint.rsplit("/", 1)[1],
            "from": endpoint, "to": "engine/orchestrator", "host": "host-one", "session": endpoint,
            "binding_generation": 1, "type": kind, "in_reply_to": parent, "body": "fixture evidence", **extra})

    def finish_writer(self, *, order="terminal-first", reference=None, outcome="passed", evidence=None):
        message = self.messages("dispatch")[0]["message"]
        readiness = {"worktree": str(self.checkout), "branch": "candidate", "base_revision": self.revision,
                     "lease_ref": "refs/aegis/lanes/fixture", "lease_oid": "a" * 40,
                     "lease_expires_at": "2099-01-01T00:00:00Z", "owned_paths": ["app.txt"],
                     "scan_workspace": str(self.checkout), "scan_evidence": "fixture scan",
                     "enforcement_tier": "advisory", "hook_evidence": "fixture hooks"}
        self.publish_lane("engine/lane/fix", message["message_id"], "ack", acknowledgment="accepted", readiness=readiness)
        self.ledger.intent(self.change.value)
        self.ledger.event("start", actor=self.ledger.operator, intent_id="attempt-1", **self.ledger.target(self.change.value))
        result = {"request_sha256": self.ledger.target(self.change.value)["request_sha256"], "intent_id": "attempt-1",
                  "outcome": outcome, "exit_code": None if outcome == "unknown" else 0 if outcome == "passed" else 7,
                  "source": self.change.value["source"], "evidence": self.ledger.evidence if evidence is None else evidence}
        raw = raw_request(result)
        completion = {"source_revision": self.revision, "source_tree": self.tree,
                      "lane_check": reference or "lifecycle-terminal:" + raw["sha256"],
                      "checks": [{"check": "writer", "outcome": "pass", "reference": "fixture check"}]}
        def terminal():
            self.ledger.event("terminal", actor=self.ledger.operator, result=raw, **self.ledger.target(self.change.value))
        if order == "terminal-first":
            terminal()
        self.publish_lane("engine/lane/fix", message["message_id"], "result", result=completion)
        if order == "result-first":
            terminal()

    def run_jobs(self, expect=0):
        proc = subprocess.run([sys.executable, "-I", "-B", str(JOBS), "--store", str(self.workspace.store),
                               "--recipes", str(self.recipes_path), "run-open"], env=os.environ.copy(),
                              capture_output=True, text=True, timeout=60)
        assert proc.returncode == expect, proc.stdout + proc.stderr
        assert not proc.stderr, proc.stderr
        return json.loads(proc.stdout)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    original = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: pwd.struct_passwd((*original[:5], str(home), original.pw_shell)))
    for key in tuple(os.environ):
        if key in {"CLAUDECODE", "CLAUDE_PID"} or key.startswith("CLAUDE_CODE_"):
            monkeypatch.delenv(key)


def held(world, kind):
    row = world.projection()
    assert row["state"] == "held", row
    assert row["reason"] == kind, row
    return row


def test_ready_projection_is_separate_from_canonical_routes_and_plan_decisions(tmp_path):
    world = DispatchWorld(tmp_path)
    before = world.ledger.files()
    status = world.run("status")
    assert status["requests"] == []
    assert status["small_changes"][0]["state"] == "writer_ready"
    assert world.route()["routed"] == []
    assert world.inbox("engine") == []
    assert world.ledger.files() == before


@pytest.mark.parametrize("order", ["terminal-first", "result-first"])
def test_complete_public_progression_drafts_owner_closure_without_recording_it(tmp_path, order):
    world = DispatchWorld(tmp_path)
    initial = world.ledger.status()
    world.dispatch()
    writer = world.messages("dispatch")[0]
    assert writer["message"]["from"] == "engine/orchestrator"
    assert writer["message"]["to"] == "engine/lane/fix"
    assert writer["message"]["message_id"] == "scw-" + raw_request(world.change.plan)["sha256"]
    brief = Path(writer["message"]["brief"]["path"]).read_text()
    assert all("## " + name in brief for name in ("Role contract", "Approved scope", "Source identity",
               "Open obligations", "Dependencies", "Unread work", "Evidence references"))
    snapshot = mailbox_snapshot(world.root)
    world.dispatch()
    assert mailbox_snapshot(world.root) == snapshot
    world.finish_writer(order=order)
    world.dispatch()
    assert len(world.messages("job_request")) == 1
    world.run_jobs()
    world.dispatch()
    review = [r["message"] for r in world.messages("dispatch") if r["message"]["to"].endswith("review0")][0]
    world.publish_lane("engine/lane/review0", review["message_id"], "ack", acknowledgment="accepted")
    world.ledger.event("review", actor="reviewer-1", result_sha256=world.change.row()["terminal"]["sha256"],
        source=world.change.value["source"], verdict="accept", evidence=world.ledger.evidence,
        **world.ledger.target(world.change.value))
    world.publish_lane("engine/lane/review0", review["message_id"], "review", result={
        "source_revision": world.revision, "source_tree": world.tree,
        "checks": [{"check": "review", "outcome": "pass", "reference": "fixture acceptance"}]})
    before = world.ledger.files()
    world.dispatch()
    row = held(world, "small_change_close_due")
    assert world.ledger.files() == before
    assert world.change.row()["delivery"] is None
    for envelope in row["drafts"]:
        path = tmp_path / "owner-event.json"
        path.write_text(json.dumps(envelope))
        world.ledger.cli("record", "--event", str(path), "--evidence-only")
    assert world.ledger.status()["work_complete"] is True
    assert world.projection()["state"] == "complete"
    assert world.run("status")["planning_exclusions"] == []
    assert world.ledger.status()["meters"]["root-1"] == initial["meters"]["root-1"]
    assert world.ledger.status()["consumed"] == {world.change.value["id"]: 1}


@pytest.mark.parametrize("writer_kind,reviewers", [("reviewer", 1), ("reviewer", 0), ("implementer", 0), ("implementer", 2)])
def test_invalid_lane_selection_holds_without_messages_or_journal(tmp_path, writer_kind, reviewers):
    world = DispatchWorld(tmp_path, writer_kind=writer_kind, reviewers=reviewers)
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_configuration")
    assert world.messages() == [] and world.ledger.files() == before


@pytest.mark.parametrize("fault", ["route"])
@pytest.mark.parametrize("succession", ["router", "root", None])
def test_publish_append_crash_recovers_under_current_custody_without_duplicate(tmp_path, fault, succession):
    world = DispatchWorld(tmp_path)
    world.dispatch(fault=fault)
    held(world, "delivered_unrecorded")
    original = world.messages("dispatch")[0]
    if succession:
        checkpoint = world.ledger.cli("checkpoint")
        world.ledger.event("succeed", actor=succession + "-2", predecessor=succession + "-1",
                           checkpoint_sha256=checkpoint["sha256"])
        if succession == "root":
            world.ledger.root_actor = "root-2"
    world.dispatch()
    assert world.messages("dispatch") == [original]
    receipt = world.ledger.status()["receipts"][original["message"]["message_id"]]
    before = world.ledger.files()
    world.dispatch()
    assert world.ledger.files() == before
    assert world.ledger.status()["receipts"][receipt["event_id"]] == receipt


@pytest.mark.parametrize("outcome,reference,reason", [("unknown", None, "small_change_unknown_effect"),
    ("failed", None, "small_change_check_failed"), ("passed", "lifecycle-terminal:" + "0" * 64, "small_change_result_invalid")])
def test_unknown_failed_or_unbound_writer_never_creates_jobs(tmp_path, outcome, reference, reason):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer(outcome=outcome, reference=reference)
    for _ in range(2):
        world.dispatch()
        held(world, reason)
    assert world.messages("job_request") == []
    assert world.ledger.status()["consumed"] == {world.change.value["id"]: 1}


def test_partial_check_batch_resumes_only_original_missing_ids(tmp_path):
    world = DispatchWorld(tmp_path, checks=3)
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    original = world.messages("job_request")
    assert len(original) == 1
    world.dispatch()
    assert len(world.messages("job_request")) == 3
    assert original[0] in world.messages("job_request")
    world.dispatch()
    assert len(world.messages("job_request")) == 3


def test_live_deny_after_writer_blocks_checks_and_reviewer(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.ledger.event("decision", actor=world.ledger.root_actor, decision="deny", reason="revoked",
                       **world.ledger.target(world.change.value))
    world.dispatch()
    held(world, "small_change_revoked")
    assert world.messages("job_request") == [] and len(world.messages("dispatch")) == 1


def test_expiry_margin_refuses_writer_before_any_publish(tmp_path):
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    world = DispatchWorld(tmp_path, expires=expiry)
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_expired")
    assert world.messages() == [] and world.ledger.files() == before


def test_recipe_drift_is_a_row_hold_and_never_replaces_job_identity(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.recipes["recipes"]["focused"]["steps"][0][-1] = "print('changed')"
    world.save_recipes()
    world.dispatch()
    held(world, "small_change_recipe_mismatch")
    assert world.messages("job_request") == []


def test_recipe_drift_after_publication_never_accepts_current_recipes_as_admitted(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.recipes["recipes"]["focused"]["steps"][0][-1] = "print('changed after publish')"
    world.save_recipes()
    world.run_jobs()
    original = world.messages("job_request")
    world.dispatch()
    held(world, "small_change_recipe_mismatch")
    assert world.messages("job_request") == original
    assert len(world.messages("dispatch")) == 1


@pytest.mark.parametrize("unsupported", ["paths", "unclean"])
def test_all_check_preflight_refuses_unsupported_recipe_without_partial_publication(tmp_path, unsupported):
    changes = {"require_clean": False} if unsupported == "unclean" else {
        "steps": [["$python", "-c", "print('paths')", "$paths"]]}
    world = DispatchWorld(tmp_path, checks=2, recipe_changes=changes)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    held(world, "small_change_configuration")
    assert world.messages("job_request") == []


def test_missing_published_writer_message_is_never_recreated_from_route_receipt(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    record = world.messages("dispatch")[0]
    Path(record["path"]).unlink()
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_message_lost")
    assert world.messages() == [] and world.ledger.files() == before


def test_corrupt_stored_brief_is_not_recomposed_or_republished(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    record = world.messages("dispatch")[0]
    Path(record["message"]["brief"]["path"]).write_text("corrupt")
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_message_conflict")
    assert mailbox_snapshot(world.root) == before


def test_failed_check_is_terminal_evidence_not_permission_to_reissue(tmp_path):
    world = DispatchWorld(tmp_path, recipe_changes={"steps": [["$python", "-c", "import sys; sys.exit(7)"]]})
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    original = world.messages("job_request")
    world.run_jobs()
    world.dispatch()
    held(world, "small_change_check_failed")
    world.dispatch()
    assert world.messages("job_request") == original and len(world.messages("dispatch")) == 1


def test_plan_pending_is_separate_and_canonical_arguments_are_byte_compatible(tmp_path):
    world = Loop(tmp_path)
    change = SmallChange(world.ledger)
    script = """
import json, sys
sys.path.insert(0, sys.argv[1])
from hierarchy_lifecycle import Lifecycle
from hierarchy_team_view import pending
print(json.dumps(pending(Lifecycle(sys.argv[2]))))
"""
    def pending():
        result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools"), str(world.ledger.path)],
                                capture_output=True, text=True, env=os.environ.copy(), timeout=15)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    before = pending()
    change.register()
    after = pending()
    assert after["pending"] == before["pending"]
    assert after["small_change_pending"][0]["plan_sha256"] == raw_request(change.plan)["sha256"]
    assert "root_decide" not in after["small_change_pending"][0]


def test_loop_exclusions_are_durable_separate_from_start_failing_and_lift_on_owned_hold(tmp_path):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    world.add_role("pilot/lane/f2", cwd=str(tmp_path))
    world.add_role("pilot/lane/review", cwd=str(tmp_path))
    change = SmallChange(world.ledger, request(team="pilot"))
    change.plan["plan"]["writing_lanes"][0]["lane"] = "f2"
    change.register()
    change.decide()
    change.admit()
    first = world.once(expect=3)
    assert [r["step"] for r in first["steps"]] == ["router_status", "route", "dispatch", "sweep", "run_open"]
    assert "pilot/orchestrator" not in world.woken() and "pilot/decider" not in world.woken()
    writer = first["small_changes"][0]
    world.send("pilot/lane/f2", "pilot/orchestrator", "retained-dispatcher-info",
               in_reply_to="scw-" + writer["plan_sha256"])
    world.status_path.unlink()
    second = world.once(expect=3)
    assert "pilot/orchestrator" not in world.woken()
    skipped = [r for r in second["holds"] if r["kind"] == "small_change_planning_skipped"]
    assert any(r.get("endpoint") == "pilot/orchestrator" for r in skipped)
    assert not any(r["kind"] == "start_failing" for r in second["holds"])
    assert second["small_changes"][0]["retained_replies"][0]["unread"] is True
    world.ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "owner",
        "next_decision": "review", "condition": "explicit owner custody", "evidence": world.ledger.evidence},
        **world.ledger.target(change.value))
    final = world.once()
    assert final["holds"] == []
    assert "pilot/orchestrator" in world.woken()
    assert final["small_changes"][0]["state"] == "owned_hold"


def rewrite_message(record, change):
    path = Path(record["path"])
    header, body = path.read_text()[4:].split("\n---\n\n", 1)
    value = json.loads(header)
    change(value)
    path.write_text("---\n" + json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n---\n\n" + body)


@pytest.mark.parametrize("damage", ["duplicate-check", "bad-tree"])
def test_malformed_stored_writer_evidence_holds_without_any_check_replay(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    result = world.messages("result")[0]
    if damage == "duplicate-check":
        rewrite_message(result, lambda m: m["result"]["checks"].append(copy.deepcopy(m["result"]["checks"][0])))
    else:
        rewrite_message(result, lambda m: m["result"].update(source_tree="malformed"))
    before = world.ledger.files()
    for _ in range(2):
        world.dispatch()
        held(world, "small_change_result_invalid")
    assert world.ledger.files() == before
    assert len(list((world.root / "engine/root").glob("*.md"))) == 0


@pytest.mark.parametrize("damage", ["bad-receipt", "bad-source", "bad-claim", "bad-result-hash", "bad-recipe"])
def test_bad_check_receipt_or_retained_provenance_never_dispatches_reviewer(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    message = world.messages("job_request")[0]["message"]
    world.run_jobs()
    folder = world.workspace.store / "jobs/engine" / message["message_id"]
    if damage == "bad-receipt":
        receipt = [r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed"][0]
        rewrite_message(receipt, lambda m: m["receipt"].update(exit_code=7))
    elif damage in {"bad-source", "bad-result-hash", "bad-recipe"}:
        path = folder / "result.json"
        result = json.loads(path.read_text())
        if damage == "bad-source":
            result["after"]["source_tree"] = "e" * 40
        elif damage == "bad-result-hash":
            result["recipes_sha256"] = "e" * 64
        else:
            result["recipe"] = "other-recipe"
        path.write_text(json.dumps(result))
        receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
        rewrite_message(receipt, lambda m: [ref.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                        for ref in m["receipt"]["evidence"] if ref["path"] == str(path)])
    else:
        path = folder / "claim.json"
        claim = json.loads(path.read_text())
        claim["recipes_sha256"] = "e" * 64
        path.write_text(json.dumps(claim))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    row = world.projection()
    assert row["reason"] == ("small_change_recipe_mismatch" if damage in {"bad-claim", "bad-result-hash"}
                             else "small_change_receipt_invalid"), row
    assert mailbox_snapshot(world.root) == before


def test_lost_job_receipt_is_recovered_by_existing_runner_without_reexecuting(tmp_path):
    counter = tmp_path / "executions"
    program = "from pathlib import Path; p=Path(%r); p.write_text(p.read_text()+'run\\n' if p.exists() else 'run\\n')" % str(counter)
    world = DispatchWorld(tmp_path, recipe_changes={"steps": [["$python", "-c", program]]})
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    terminal = [r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed"][0]
    Path(terminal["path"]).unlink()
    world.dispatch()
    assert len(world.messages("dispatch")) == 1
    world.run_jobs()
    world.dispatch()
    assert counter.read_text().splitlines() == ["run"]
    assert len(world.messages("dispatch")) == 2
    assert len([r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed"]) == 1


def test_mixed_team_is_held_but_other_canonical_routing_keeps_progressing(tmp_path):
    world = DispatchWorld(tmp_path)
    world.ledger.publish(request("canonical"))
    world.team("docs")
    world.approved(request("other", team="docs"))
    result = world.route()
    assert [r["request_id"] for r in result["routed"]] == ["other"]
    world.dispatch()
    held(world, "small_change_mixed_queue")
    assert world.messages() == []
    assert len(world.inbox("docs")) == 1


def test_changed_small_change_recipe_does_not_gate_unrelated_canonical_jobs(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.recipes["recipes"]["focused"]["steps"][0][-1] = "print('owner current recipe')"
    world.save_recipes()
    root = world.team("docs")
    world.workspace.run("update", {"initiative": "docs", "source": "owner", "checkouts": [str(world.checkout)]})
    packet = tmp_path / "docs/canonical.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "focused",
        "checkout": str(world.checkout), "commit": world.revision, "tree": world.tree}))
    invoke(root, "publish", {"message_id": "canonical-check", "from": "docs/orchestrator", "to": "docs/root",
        "host": "host-one", "session": "docs-orchestrator", "binding_generation": 1,
        "type": "job_request", "body": "owner canonical check", "brief": {
            "path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}})
    results = world.run_jobs()
    assert any(r["job"] == "docs/canonical-check" and r["state"] == "completed" for r in results["rows"])
    world.dispatch()
    held(world, "small_change_recipe_mismatch")


def test_foreign_reviewer_dispatch_holds_instead_of_starting_another_assignment(tmp_path):
    world = DispatchWorld(tmp_path)
    brief = tmp_path / "engine/manual.md"
    brief.write_text("Owner-created foreign review assignment\n")
    invoke(world.root, "publish", {"message_id": "manual-review", "from": "engine/orchestrator", "to": "engine/lane/review0",
        "host": "host-one", "session": "engine/orchestrator", "binding_generation": 1,
        "type": "dispatch", "body": "owner-created assignment", "brief": {
            "path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}})
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_mixed_queue")
    assert world.ledger.files() == before
    assert [r["message"]["message_id"] for r in world.messages("dispatch")] == ["manual-review"]


@pytest.mark.parametrize("condition", ["unadmitted", "admitted", "denied", "expired", "binding-changed",
                                        "orchestrator-changed", "conflict"])
def test_legacy_delivery_precedes_configuration_and_never_replays(tmp_path, condition):
    world = Loop(tmp_path)
    root = world.team("engine")
    change = SmallChange(world.ledger)
    published = deliver_without_recording(world, change.value)
    change.register()
    if condition == "admitted":
        change.decide()
        change.admit()
    if condition == "denied":
        world.ledger.event("decision", actor=world.ledger.root_actor, decision="deny", reason="owner deny",
                           **world.ledger.target(change.value))
    records = invoke(root, "inbox", endpoint="engine/orchestrator")["messages"]
    record = records[0]
    if condition in {"binding-changed", "orchestrator-changed"}:
        checkpoint = root.parent / "checkpoint.md"
        checkpoint.write_text("owner checkpoint")
        endpoint = "engine/router" if condition == "binding-changed" else "engine/orchestrator"
        invoke(root, "bind", {"endpoint": endpoint, "host": "new-host", "session": "new-router",
               "expected_generation": 1, "checkpoint": {"outgoing_stopped": True,
                 "briefs": [{"path": str(checkpoint), "sha256": hashlib.sha256(checkpoint.read_bytes()).hexdigest()}],
                 "sources": [], "lease_refs": [], "completed_checks": [], "pending_message_ids": [published],
                 "last_acknowledgment_ids": []}})
    if condition == "conflict":
        path = Path(record["path"])
        header, _body = path.read_text()[4:].split("\n---\n\n", 1)
        path.write_text("---\n" + header + "\n---\n\nconflicting legacy body")
    journal, mailbox = world.ledger.files(), mailbox_snapshot(root)
    reason = "route_message_conflict" if condition == "conflict" else "small_change_legacy_delivery"
    world.recipes_path = tmp_path / "absent-recipes.json"
    for _ in range(2):
        status = (DispatchWorld.dispatch(world, fault="future", command="status") if condition == "expired"
                  else world.run("status"))
        assert status["requests"] == []
        row = status["small_changes"][0]
        assert (row["state"], row["reason"]) == ("held", reason), row
        assert row["legacy_delivery"]["message_id"] == published
        assert row["legacy_delivery"]["evidence"]["path"] == record["path"]
        result = (DispatchWorld.dispatch(world, fault="future") if condition == "expired" else
                  world.run("dispatch", "--recipes", str(world.recipes_path), "--evidence-only"))
        assert result["small_changes"][0]["reason"] == reason
        assert result["planning_exclusions"] == ["engine/decider", "engine/orchestrator"]
        assert world.ledger.files() == journal and mailbox_snapshot(root) == mailbox
    assert [m["message"]["message_id"] for m in world.inbox("engine")] == [published]


@pytest.mark.parametrize("condition", ["denied", "drift", "expired"])
def test_partial_batch_retains_original_and_holds_missing_after_precondition_loss(tmp_path, condition):
    world = DispatchWorld(tmp_path, checks=3)
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    original = world.messages("job_request")
    if condition == "denied":
        world.ledger.event("decision", actor=world.ledger.root_actor, decision="deny", reason="owner deny",
                           **world.ledger.target(world.change.value))
    elif condition == "drift":
        world.recipes["recipes"]["focused"]["steps"][0][-1] = "print('changed')"
        world.save_recipes()
    for _ in range(2):
        result = world.dispatch(fault="future" if condition == "expired" else None)
        row = result["small_changes"][0]
        assert row["state"] == "held", row
        assert row["reason"] == {"denied": "small_change_revoked", "drift": "small_change_recipe_mismatch",
                                  "expired": "small_change_expired"}[condition], row
        assert world.messages("job_request") == original and len(original) == 1
        assert len(world.messages("dispatch")) == 1


def test_current_planning_wake_holds_before_any_writer_publication(tmp_path):
    world = DispatchWorld(tmp_path)
    marker = world.root / ".wake-engine%2Forchestrator.lock"
    marker.write_text("owner must reconcile an active or abandoned wake")
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_configuration")
    assert world.messages() == [] and world.ledger.files() == before
    assert marker.exists()


@pytest.mark.parametrize("stage", ["before-writer", "after-review"])
def test_next_disposition_cannot_substitute_for_d7_skip_release(tmp_path, stage):
    world = DispatchWorld(tmp_path)
    if stage == "after-review":
        reviewer = ready_reviewer(world)
        review_result(world, reviewer)
    world.ledger.event("disposition", status="FINAL", resolution={"kind": "next",
        "request": raw_request(request("owner-next", team="other")), "evidence": world.ledger.evidence},
        **world.ledger.target(world.change.value))
    status = world.run("status")
    assert status["small_changes"][0]["state"] == "held"
    expected = ["engine/decider", "engine/orchestrator"]
    if stage == "after-review":
        # The next-disposition refusal precedes route verification, so its writer remains excluded too.
        expected.insert(1, "engine/lane/fix")
    assert status["planning_exclusions"] == expected


def test_lost_check_message_with_claim_is_held_without_republication(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    original = world.messages("job_request")[0]
    world.run_jobs()
    for receipt in world.messages("job_receipt"):
        Path(receipt["path"]).unlink()
    Path(original["path"]).unlink()
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_message_lost")
    assert mailbox_snapshot(world.root) == before


def test_malformed_retained_result_has_receipt_hold_without_new_work(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    message = world.messages("job_request")[0]["message"]
    result = world.workspace.store / "jobs/engine" / message["message_id"] / "result.json"
    result.write_text("{}")
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_receipt_invalid")
    assert mailbox_snapshot(world.root) == before


def ready_reviewer(world):
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    world.dispatch()
    return next(r["message"] for r in world.messages("dispatch") if r["message"]["to"].endswith("review0"))


def review_result(world, reviewer, verdict="accept"):
    world.publish_lane("engine/lane/review0", reviewer["message_id"], "ack", acknowledgment="accepted")
    world.ledger.event("review", actor="reviewer-1", result_sha256=world.change.row()["terminal"]["sha256"],
        source=world.change.value["source"], verdict=verdict, evidence=world.ledger.evidence,
        **world.ledger.target(world.change.value))
    world.publish_lane("engine/lane/review0", reviewer["message_id"], "review", result={
        "source_revision": world.revision, "source_tree": world.tree,
        "checks": [{"check": "review", "outcome": "pass", "reference": "fixture review"}]})


def record_drafts(world, row):
    assert row["drafts"], row
    for envelope in row["drafts"]:
        path = world.tmp / "owner-envelope.json"
        path.write_text(json.dumps(envelope))
        world.ledger.cli("record", "--event", str(path), "--evidence-only")


@pytest.mark.parametrize("endpoint", ["engine/lane/fix", "engine/lane/review0", "engine/orchestrator"])
def test_unacknowledged_binding_never_starts_writer(tmp_path, endpoint):
    world = DispatchWorld(tmp_path)
    brief = world.root.parent / "handoff.md"
    brief.write_text("Owner stopped outgoing session")
    checkpoint = {"outgoing_stopped": True, "briefs": [{"path": str(brief),
        "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}], "sources": [], "lease_refs": [],
        "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
    invoke(world.root, "bind", {"endpoint": endpoint, "host": "next-host", "session": "next-session",
                               "expected_generation": 1, "checkpoint": checkpoint})
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_binding_changed")
    assert world.messages() == [] and world.ledger.files() == before


def test_all_check_hashes_are_checked_before_any_publication(tmp_path):
    world = DispatchWorld(tmp_path, checks=2, mismatched_check=True)
    world.dispatch()
    world.finish_writer()
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_recipe_mismatch")
    assert world.messages("job_request") == [] and world.ledger.files() == before


def test_wrong_historical_result_actor_is_not_accepted(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    rewrite_message(world.messages("result")[0], lambda m: m.update(session="forged-session"))
    world.dispatch()
    held(world, "small_change_binding_changed")
    assert world.messages("job_request") == []


@pytest.mark.parametrize("damage", ["duplicate-result", "missing-reference", "failed-lane-check"])
def test_duplicate_or_nonpassing_writer_completion_never_publishes_jobs(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    record = world.messages("result")[0]
    if damage == "duplicate-result":
        path = Path(record["path"]).with_name("duplicate.md")
        path.write_bytes(Path(record["path"]).read_bytes())
        rewrite_message({"path": str(path)}, lambda m: m.update(message_id="duplicate-result"))
    elif damage == "missing-reference":
        rewrite_message(record, lambda m: m["result"].pop("lane_check"))
    else:
        rewrite_message(record, lambda m: m["result"]["checks"][0].update(outcome="fail"))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_check_failed" if damage == "failed-lane-check" else "small_change_result_invalid")
    assert mailbox_snapshot(world.root) == before
    assert list((world.root / "engine/root").glob("*.md")) == []


def test_duplicate_terminal_receipt_is_corruption_not_another_success(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    record = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    path = Path(record["path"]).with_name("duplicate.md")
    path.write_bytes(Path(record["path"]).read_bytes())
    rewrite_message({"path": str(path)}, lambda m: m.update(message_id="duplicate-receipt"))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_receipt_invalid")
    assert mailbox_snapshot(world.root) == before


@pytest.mark.parametrize("state", ["unknown", "refused"])
def test_unknown_or_refused_check_never_reissues_or_dispatches_reviewer(tmp_path, state):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    job = world.messages("job_request")[0]["message"]
    invoke(world.root, "publish", {"message_id": "owner-check-" + state, "from": "engine/root",
        "to": "engine/orchestrator", "host": "host-one", "session": "engine/root", "binding_generation": 1,
        "type": "job_receipt", "in_reply_to": job["message_id"], "body": "original check unresolved",
        "receipt": {"state": state, "reason": "owner retains original uncertain or refused check"}})
    original = world.messages("job_request")
    for _ in range(2):
        world.dispatch()
        held(world, "small_change_unknown_effect" if state == "unknown" else "small_change_check_failed")
        assert world.messages("job_request") == original and len(world.messages("dispatch")) == 1


def test_denial_after_checks_prevents_reviewer_publication(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    world.ledger.event("decision", actor=world.ledger.root_actor, decision="deny", reason="owner denied review",
                       **world.ledger.target(world.change.value))
    world.dispatch()
    held(world, "small_change_revoked")
    assert len(world.messages("dispatch")) == 1


def test_rejected_review_only_drafts_owned_hold_and_never_replays(tmp_path):
    world = DispatchWorld(tmp_path)
    reviewer = ready_reviewer(world)
    review_result(world, reviewer, "reject")
    original = world.messages("dispatch")
    world.dispatch()
    row = held(world, "small_change_review_rejected")
    assert all(e["event"]["type"] == "disposition" and e["event"]["status"] == "HOLD" for e in row["drafts"])
    record_drafts(world, row)
    assert world.projection()["state"] == "owned_hold"
    assert world.run("status")["planning_exclusions"] == []
    world.dispatch()
    assert world.messages("dispatch") == original and not world.ledger.status()["work_complete"]


def test_owner_can_resolve_owned_blocker_with_exact_drafted_evidence(tmp_path):
    world = DispatchWorld(tmp_path)
    reviewer = ready_reviewer(world)
    world.ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "owner",
        "next_decision": "review", "condition": "owner waiting for independent review", "evidence": world.ledger.evidence},
        **world.ledger.target(world.change.value))
    review_result(world, reviewer)
    world.dispatch()
    row = world.projection()
    assert row["state"] == "owned_hold" and row["reason"] == "small_change_close_due", row
    assert [e["event"]["type"] for e in row["drafts"]] == ["delivery", "resolve"]
    record_drafts(world, row)
    assert world.ledger.status()["work_complete"] is True
    # Losing evidence after owner completion is visible; no replacement assignment is sent.
    before = mailbox_snapshot(world.root)
    result = world.messages("review")[0]
    Path(result["path"]).unlink()
    world.dispatch()
    held(world, "small_change_closed_unverified")
    assert len(world.messages("dispatch")) == 2
    assert world.ledger.status()["work_complete"] is True


def test_dispatcher_only_passes_preserve_slots_leases_meters_and_cumulative_starts(tmp_path):
    world = DispatchWorld(tmp_path)
    reservation = world.workspace.ask("engine", holder="owner:retained-reservation")
    assert world.workspace.grant()["request_id"] == reservation
    def store_bytes():
        return {str(p.relative_to(world.workspace.store)): p.read_bytes()
                for p in world.workspace.store.rglob("*") if p.is_file()}
    before = store_bytes()
    accounting = world.ledger.status()
    refs = git(world.checkout, "for-each-ref", "refs/aegis/lanes")
    world.dispatch()
    world.dispatch()
    assert store_bytes() == before
    assert world.ledger.status()["meters"] == accounting["meters"]
    assert world.ledger.status()["consumed"] == accounting["consumed"] == {}
    world.finish_writer(outcome="unknown")
    accounting = world.ledger.status()
    for _ in range(2):
        world.dispatch()
    assert store_bytes() == before
    assert world.ledger.status()["meters"] == accounting["meters"]
    assert world.ledger.status()["consumed"] == {world.change.value["id"]: 1}
    assert git(world.checkout, "for-each-ref", "refs/aegis/lanes") == refs


@pytest.mark.parametrize("successor", ["router", "root"])
def test_committed_route_reply_loss_returns_original_receipt_after_succession(tmp_path, successor):
    world = DispatchWorld(tmp_path)
    result = world.dispatch(fault="route-committed")
    assert result["small_changes"][0]["reason"] == "delivered_unrecorded"
    original = world.ledger.status()["receipts"][world.messages("dispatch")[0]["message"]["message_id"]]
    checkpoint = world.ledger.cli("checkpoint")
    world.ledger.event("succeed", actor=successor + "-2", predecessor=successor + "-1", checkpoint_sha256=checkpoint["sha256"])
    if successor == "root":
        world.ledger.root_actor = "root-2"
    before = world.ledger.files(), mailbox_snapshot(world.root)
    world.dispatch()
    assert world.ledger.status()["receipts"][original["event_id"]] == original
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("damage", ["packet", "evidence", "stop-proof", "live-runner", "reservation"])
def test_retained_job_requires_unchanged_evidence_stopped_process_and_settled_slot(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    message = world.messages("job_request")[0]["message"]
    folder = world.workspace.store / "jobs/engine" / message["message_id"]
    if damage == "packet":
        (folder / "packet.md").write_text("changed retained packet")
    elif damage == "evidence":
        next(folder.glob("step-*.log")).write_text("changed retained evidence")
    elif damage == "stop-proof":
        path = folder / "result.json"
        result = json.loads(path.read_text())
        result["process_stopped_confirmed"] = False
        path.write_text(json.dumps(result))
        (folder / "process.json").unlink(missing_ok=True)
        receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
        rewrite_message(receipt, lambda m: [ref.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                        for ref in m["receipt"]["evidence"] if ref["path"] == str(path)])
    elif damage == "live-runner":
        from tools.hierarchy_jobs import process_start
        path = folder / "claim.json"
        claim = json.loads(path.read_text())
        claim.update(pid=os.getpid(), start=process_start(os.getpid()))
        path.write_text(json.dumps(claim))
    else:
        holder = "job:engine/" + message["message_id"]
        reservation = world.workspace.ask("engine", holder=holder)
        assert world.workspace.grant()["request_id"] == reservation
    before = mailbox_snapshot(world.root)
    store = {str(p): p.read_bytes() for p in world.workspace.store.rglob("*") if p.is_file()}
    world.dispatch()
    held(world, "small_change_unknown_effect" if damage == "live-runner" else "small_change_receipt_invalid")
    assert mailbox_snapshot(world.root) == before
    assert {str(p): p.read_bytes() for p in world.workspace.store.rglob("*") if p.is_file()} == store


def test_scoped_loop_skip_keeps_other_team_running_and_reuses_stalled_lane_hold(tmp_path):
    from tests.integration.test_hierarchy_loop import World
    from tests.integration.test_hierarchy_provision import INITIATIVE, provision
    from tests.integration.test_hierarchy_sweep import started
    world = activate_loop(World(tmp_path))
    world.add_role("pilot/lane/f2", cwd=str(tmp_path))
    world.add_role("pilot/lane/review", cwd=str(tmp_path))
    change = SmallChange(world.ledger, request(team="pilot"))
    change.plan["plan"]["writing_lanes"][0]["lane"] = "f2"
    change.register()
    change.decide()
    change.admit()
    parent = "scw-" + raw_request(change.plan)["sha256"]
    readiness = {"worktree": str(world.checkout), "branch": "feature/x", "base_revision": world.head()["commit"],
        "lease_ref": "refs/aegis/lanes/fixture", "lease_oid": "a" * 40, "lease_expires_at": "2099-01-01T00:00:00Z",
        "owned_paths": ["src/app.py"], "scan_workspace": str(world.checkout), "scan_evidence": "fixture scan",
        "enforcement_tier": "advisory", "hook_evidence": "fixture hooks"}
    world.plan({"pilot/lane/f2": {"send": [{"message_id": "accepted-fix", "to": "pilot/orchestrator",
        "type": "ack", "acknowledgment": "accepted", "in_reply_to": parent, "body": "accepted", "readiness": readiness}]}})
    base = tmp_path / "initiatives/docs"
    initialization = world.init_request()
    initialization.update(base=str(base), initiative={**INITIATIVE, "id": "docs"})
    provision("init", initialization)
    for role in ("orchestrator", "root"):
        host = "codex-cli" if role == "root" else "claude-code"
        options = {"session": "docs-root"} if role == "root" else {}
        record = provision("add-role", world.request(base=str(base), endpoint="docs/" + role,
                                                     host=host, cwd=str(tmp_path), **options))
        started(world, host, record["session"])
    world.send("docs/root", "docs/orchestrator", "other-team-work", root=base / "mailbox")
    first = world.once(expect=3)
    second = world.once(expect=3)
    assert "docs/orchestrator" in world.woken()
    assert "pilot/orchestrator" not in world.woken() and "pilot/decider" not in world.woken()
    stalled = [r for r in second["holds"] if r["kind"] == "stalled_dispatch"]
    assert len(stalled) == 1 and stalled[0]["endpoint"] == "pilot/lane/f2", second
    assert stalled[0]["act"] == "root"
    assert second["small_changes"][0]["retained_replies"][0]["unread"] is True


def test_declared_private_evidence_refuses_before_composer_reads_it(tmp_path):
    world = DispatchWorld(tmp_path, private_evidence=True)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ("status", "dispatch"):
        row = world.dispatch(fault="private", command=command)["small_changes"][0]
        assert (row["state"], row["reason"]) == ("held", "small_change_configuration"), row
        assert "owner-private" in row["detail"], row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_brief_output_cannot_overlap_the_actual_store(tmp_path):
    world = DispatchWorld(tmp_path)
    destination = world.root.parent / "briefs"
    world.workspace.store.rename(destination)
    world.workspace.store = destination
    before = {str(p): p.read_bytes() for p in destination.rglob("*") if p.is_file()}
    row = world.dispatch()["small_changes"][0]
    assert (row["state"], row["reason"]) == ("held", "small_change_configuration"), row
    assert "overlaps coordination store" in row["detail"]
    assert {str(p): p.read_bytes() for p in destination.rglob("*") if p.is_file()} == before
    assert world.messages() == []


@pytest.mark.parametrize("fault,reason", [("batch-deny", "small_change_revoked"),
    ("batch-expiry", "small_change_expired"), ("batch-drift", "small_change_recipe_mismatch")])
def test_live_preconditions_are_rechecked_between_each_batch_publication(tmp_path, fault, reason):
    world = DispatchWorld(tmp_path, checks=3)
    world.dispatch()
    world.finish_writer()
    row = world.dispatch(fault=fault)["small_changes"][0]
    assert (row["state"], row["reason"]) == ("held", reason), row
    assert len(world.messages("job_request")) == 1
    assert len(world.messages("dispatch")) == 1


def test_expiry_after_writer_publication_retains_unrecorded_delivery_and_writer_skip(tmp_path):
    world = DispatchWorld(tmp_path)
    row = world.dispatch(fault="late-route")["small_changes"][0]
    assert row["reason"] == "delivered_unrecorded", row
    original = world.messages("dispatch")
    before = world.ledger.files()
    status = world.dispatch(command="status", fault="future")
    assert status["small_changes"][0]["reason"] == "delivered_unrecorded"
    assert "engine/lane/fix" in status["planning_exclusions"]
    assert world.ledger.files() == before and world.messages("dispatch") == original


@pytest.mark.parametrize("stage", ["before-publish", "awaiting-intent", "intent"])
def test_stale_lifecycle_writer_never_restarts_an_assignment(tmp_path, stage):
    world = DispatchWorld(tmp_path)
    if stage != "before-publish":
        world.dispatch()
    if stage == "intent":
        world.ledger.intent(world.change.value)
    checkpoint = world.ledger.cli("checkpoint")
    world.ledger.event("succeed", actor="operator-2", predecessor="operator-1", checkpoint_sha256=checkpoint["sha256"])
    before = world.ledger.files(), mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_unknown_effect" if stage == "intent" else "small_change_binding_changed")
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_intent_without_route_receipt_is_a_protocol_hold_not_retroactive_route(tmp_path):
    world = DispatchWorld(tmp_path)
    world.ledger.intent(world.change.value)
    before = world.ledger.files()
    world.dispatch()
    held(world, "small_change_result_invalid")
    assert world.messages() == [] and world.ledger.files() == before


def test_read_only_reviewer_dispatch_can_finish_valid_checks_after_expiry(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    result = world.dispatch(fault="future")
    assert result["small_changes"][0]["state"] == "reviewing", result
    assert len(world.messages("dispatch")) == 2


@pytest.mark.parametrize("damage", ["identity", "type", "destination", "deep-body", "extra", "target-bool",
                                    "target-zero", "target-unknown", "target-future"])
def test_conflicting_writer_identity_is_not_hidden_by_a_valid_brief(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    record = world.messages("dispatch")[0]
    path = Path(record["path"])
    if damage in {"identity", "extra", "target-bool", "target-zero", "target-unknown", "target-future"}:
        header, body = path.read_text()[4:].split("\n---\n\n", 1)
        metadata = json.loads(body)
        if damage == "identity":
            metadata["plan_sha256"] = "e" * 64
        elif damage == "extra":
            metadata["owner_release"] = True
        else:
            generation = True if damage == "target-bool" else 0 if damage == "target-zero" else 2
            if damage == "target-future":
                invoke(world.root, "bind", {"endpoint": "engine/lane/fix", "host": "next-host", "session": "next-session",
                    "expected_generation": 1, "checkpoint": {"outgoing_stopped": True, "briefs": [record["message"]["brief"]],
                      "sources": [], "lease_refs": [], "completed_checks": [],
                      "pending_message_ids": [record["message"]["message_id"]], "last_acknowledgment_ids": []}})
            metadata["target_generation"] = generation
            brief = Path(record["message"]["brief"]["path"])
            raw = brief.read_bytes().replace(b"Target generation: 1", ("Target generation: " + str(generation)).encode())
            sha = hashlib.sha256(raw).hexdigest()
            replacement = brief.with_name("fresh-" + sha + ".md")
            replacement.write_bytes(raw)
            parsed_header = json.loads(header)
            parsed_header["brief"] = {"path": str(replacement), "sha256": sha}
            header = json.dumps(parsed_header)
        path.write_text("---\n" + header + "\n---\n\n" + json.dumps(metadata))
    elif damage == "type":
        rewrite_message(record, lambda m: m.update(type="info"))
    elif damage == "destination":
        rewrite_message(record, lambda m: m.update(to="engine/lane/review0"))
    else:
        header, _body = path.read_text()[4:].split("\n---\n\n", 1)
        path.write_text("---\n" + header + "\n---\n\n" + "[" * 2000 + "]" * 2000)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_message_conflict")
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_terminal_evidence_hash_must_match_before_any_check_publication(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    terminal_evidence = tmp_path / "terminal-evidence.txt"
    terminal_evidence.write_text("original terminal evidence")
    world.finish_writer(evidence=[{"path": str(terminal_evidence),
                                  "sha256": hashlib.sha256(terminal_evidence.read_bytes()).hexdigest()}])
    terminal_evidence.write_text("changed terminal evidence")
    before = world.ledger.files(), mailbox_snapshot(world.root)
    world.dispatch()
    row = held(world, "small_change_configuration")
    assert row["detail"] == "evidence reference hash mismatch"
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("condition", ["registry", "source"])
def test_fixed_source_and_registered_checkout_are_required_before_check_publish(tmp_path, condition):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    if condition == "registry":
        world.workspace.run("update", {"initiative": "engine", "source": "owner", "checkouts": []})
    else:
        rewrite_message(world.messages("result")[0], lambda m: m["result"].update(source_tree="e" * 40))
    world.dispatch()
    held(world, "small_change_configuration")
    assert world.messages("job_request") == []


def test_reviewer_source_cannot_differ_from_writer_checked_source(tmp_path):
    world = DispatchWorld(tmp_path)
    reviewer = ready_reviewer(world)
    review_result(world, reviewer)
    rewrite_message(world.messages("review")[0], lambda m: m["result"].update(source_tree="e" * 40))
    world.dispatch()
    row = held(world, "small_change_result_invalid")
    assert not any(e["event"].get("resolution", {}).get("kind") == "complete" for e in row["drafts"])


@pytest.mark.parametrize("damage", ["missing-result", "body", "nonoriginal-id"])
def test_completed_receipt_requires_original_identity_body_and_retained_result(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    record = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    if damage == "missing-result":
        job = world.messages("job_request")[0]["message"]["message_id"]
        (world.workspace.store / "jobs/engine" / job / "result.json").unlink()
    elif damage == "body":
        path = Path(record["path"])
        header, _body = path.read_text()[4:].split("\n---\n\n", 1)
        path.write_text("---\n" + header + "\n---\n\nchanged receipt body")
    else:
        rewrite_message(record, lambda m: m.update(message_id="nonoriginal-completed-receipt"))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    row = held(world, "small_change_receipt_invalid")
    if damage == "missing-result":
        assert "missing successful retained job result" in row["detail"]
    assert mailbox_snapshot(world.root) == before


def test_hashed_stored_brief_still_requires_complete_fresh_format(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    record = world.messages("dispatch")[0]
    path = Path(record["message"]["brief"]["path"])
    raw = ("Endpoint: engine/lane/fix\nTarget generation: 1\n" + raw_request(world.change.value)["sha256"]
           + "\n" + raw_request(world.change.plan)["sha256"]).encode()
    sha = hashlib.sha256(raw).hexdigest()
    replacement = path.with_name("fresh-" + sha + ".md")
    replacement.write_bytes(raw)
    rewrite_message(record, lambda m: m.update(brief={"path": str(replacement), "sha256": sha}))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_message_conflict")
    assert mailbox_snapshot(world.root) == before


def test_lost_reviewer_message_with_review_event_is_not_republished(tmp_path):
    world = DispatchWorld(tmp_path)
    reviewer = ready_reviewer(world)
    review_result(world, reviewer)
    for record in world.messages():
        if record["message"]["message_id"] == reviewer["message_id"] or record["message"].get("in_reply_to") == reviewer["message_id"]:
            Path(record["path"]).unlink()
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_message_lost")
    assert mailbox_snapshot(world.root) == before


@pytest.mark.parametrize("endpoint", ["engine/orchestrator", "engine/root"])
def test_publication_rechecks_handoff_after_writer_route(tmp_path, endpoint):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    brief = world.root.parent / "handoff.md"
    brief.write_text("Owner stopped outgoing binding")
    invoke(world.root, "bind", {"endpoint": endpoint, "host": "next-host", "session": "next-session",
        "expected_generation": 1, "checkpoint": {"outgoing_stopped": True, "briefs": [{"path": str(brief),
          "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}], "sources": [], "lease_refs": [],
          "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}})
    before = world.ledger.files(), mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_binding_changed")
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_later_binding_cannot_claim_an_earlier_dispatch_result(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    brief = world.root.parent / "handoff.md"
    brief.write_text("Owner stopped completed writer")
    invoke(world.root, "bind", {"endpoint": "engine/lane/fix", "host": "next-host", "session": "next-session",
        "expected_generation": 1, "checkpoint": {"outgoing_stopped": True, "briefs": [{"path": str(brief),
          "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}], "sources": [], "lease_refs": [],
          "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}})
    for record in world.messages():
        if record["message"]["from"] == "engine/lane/fix":
            rewrite_message(record, lambda m: m.update(host="next-host", session="next-session", binding_generation=2))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_binding_changed")
    assert mailbox_snapshot(world.root) == before


@pytest.mark.parametrize("subject", ["router-1", "coordinator-1"])
def test_journal_dry_run_checks_current_cap_without_publication_or_closure_drafts(tmp_path, subject):
    world = DispatchWorld(tmp_path)
    if subject == "coordinator-1":
        reviewer = ready_reviewer(world)
        review_result(world, reviewer)
    cap = world.ledger.policy["actors"][subject]["cap_seconds"]
    world.ledger.event("meter", actor="operator-1", subject=subject, active_seconds=cap, open_since=None)
    before = world.ledger.files(), mailbox_snapshot(world.root), world.ledger.status()["meters"]
    row = world.dispatch()["small_changes"][0]
    assert row["state"] == "held" and "cap reached" in row["detail"], row
    if subject == "coordinator-1":
        assert row["drafts"] == []
    else:
        assert all(e["event"].get("status") == "HOLD" for e in row["drafts"])
    assert (world.ledger.files(), mailbox_snapshot(world.root), world.ledger.status()["meters"]) == before


def test_busy_mailbox_is_not_unlocked_or_written_by_dispatcher(tmp_path):
    world = DispatchWorld(tmp_path)
    lock = world.root / ".write.lock"
    lock.write_text("owner lock")
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()["small_changes"][0]
    assert row["state"] == "held" and "busy" in row["detail"], row
    assert lock.read_text() == "owner lock"
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("stage", ["writer", "checks"])
def test_record_limit_preflight_leaves_no_partial_dispatch_or_artifact(tmp_path, stage):
    from tools.hierarchy_mailbox import MAX_RECORDS
    world = DispatchWorld(tmp_path, checks=2)
    if stage == "checks":
        world.dispatch()
        world.finish_writer()
    invoke(world.root, "publish", {"message_id": "capacity-seed", "from": "engine/root", "to": "engine/orchestrator",
        "host": "host-one", "session": "engine/root", "binding_generation": 1, "type": "info", "body": "inert fixture history"})
    records = world.messages()
    seed = next(r for r in records if r["message"]["message_id"] == "capacity-seed")
    header, body = Path(seed["path"]).read_text()[4:].split("\n---\n\n", 1)
    target = MAX_RECORDS if stage == "writer" else MAX_RECORDS - 1
    # Model the OS history boundary with copies of a public inert info record, never receipts or authority.
    for index in range(target - len(records)):
        message = json.loads(header)
        message["message_id"] = "capacity-" + str(index)
        Path(seed["path"]).with_name("capacity-%05d.md" % index).write_text(
            "---\n" + json.dumps(message) + "\n---\n\n" + body)
    def bytes_at(path):
        return {str(p.relative_to(path)): p.read_bytes() for p in path.rglob("*") if p.is_file()}
    before = bytes_at(world.root.parent), world.ledger.files()
    # This boundary fixture replays MAX_RECORDS histories under concurrent CI
    # load. Its contract is refusal without partial writes, not a speed bound.
    row = world.dispatch(timeout=120)["small_changes"][0]
    assert (row["state"], row["reason"]) == ("held", "small_change_configuration"), row
    assert (bytes_at(world.root.parent), world.ledger.files()) == before


def test_missing_planning_exclusions_is_a_protocol_refusal_never_an_empty_skip_set(tmp_path):
    from tests.integration.test_hierarchy_loop import World, answering
    world = activate_loop(World(tmp_path))
    change = SmallChange(world.ledger, request(team="pilot"))
    change.register()
    world.send("pilot/root", "pilot/orchestrator", "retained-root-message")
    malformed = answering(world, "incomplete-router.py", {
        "status": (0, {"router": "router-1", "requests": [], "small_changes": []}), "dispatch": (0, {})})
    result = world.once(expect=3, swap=("router", malformed))
    assert any(row["step"] == "router_status" and row["kind"] == "child_failed" for row in result["holds"])
    assert any(row["step"] == "dispatch" and row["kind"] == "dispatch_error" for row in result["holds"])
    assert not any(row["kind"] == "planning_exclusions_unavailable" for row in result["holds"])
    assert result["small_changes"][0]["request_id"] == change.value["id"]
    assert any(row["kind"] == "small_change_planning_skipped" and row.get("endpoint") == "pilot/orchestrator"
               for row in result["holds"])
    assert world.woken() == []
    assert [r["message"]["message_id"] for r in world.inbox("pilot/orchestrator")] == ["retained-root-message"]


@pytest.mark.parametrize("damage", ["schema", "enabled", "authenticated", "missing-rows", "nonstring-skip",
                                    "unknown-state", "missing-row-id", "bad-retained", "bad-reason"])
def test_loop_refuses_invalid_dispatch_protocol_without_waking_planners(tmp_path, damage):
    from tests.integration.test_hierarchy_loop import World, answering
    world = activate_loop(World(tmp_path))
    change = SmallChange(world.ledger, request(team="pilot"))
    change.register()
    status = subprocess.run([sys.executable, "-I", "-B", str(ROUTER), "--lifecycle", str(world.ledger.path),
        "--store", str(world.workspace.store), "status"], capture_output=True, text=True, env=os.environ.copy(), timeout=20)
    assert status.returncode == 0, status.stdout + status.stderr
    value = {"schema": "aegis.small-change-dispatch-run/v1", "execution_enabled": False, "authenticated": False,
             "small_changes": [], "planning_exclusions": ["pilot/orchestrator", "pilot/decider"]}
    if damage == "schema":
        value["schema"] = "unsupported"
    elif damage == "enabled":
        value["execution_enabled"] = True
    elif damage == "authenticated":
        value["authenticated"] = True
    elif damage == "missing-rows":
        value.pop("small_changes")
    elif damage == "nonstring-skip":
        value["planning_exclusions"] = [None]
    else:
        row = json.loads(status.stdout)["small_changes"][0]
        row["state"] = "unexpected" if damage == "unknown-state" else "writer_sent"
        if damage == "missing-row-id":
            row.pop("request_id")
        elif damage == "bad-retained":
            row["retained_replies"] = None
        elif damage == "bad-reason":
            row["reason"] = 7
        value["small_changes"] = [row]
    malformed = answering(world, "bad-dispatch.py", {"status": (0, json.loads(status.stdout)), "dispatch": (0, value)})
    result = world.once(expect=3, swap=("router", malformed))
    assert any(row["kind"] == "dispatch_error" and row["act"] == "owner" for row in result["holds"])
    assert world.woken() == []


def test_loop_children_strip_parent_nested_claude_environment(tmp_path, monkeypatch):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    for key in ("CLAUDECODE", "CLAUDE_PID", "CLAUDE_CODE_FIXTURE"):
        monkeypatch.setenv(key, "parent-only")
    script = world.script("probe-child-environment.py", """
import json, os, sys
if any(k in {'CLAUDECODE', 'CLAUDE_PID'} or k.startswith('CLAUDE_CODE_') for k in os.environ):
    sys.exit(7)
print(json.dumps({'rows': [], 'still_unread': [], 'root_queue': [], 'root_time': []}))
""")
    result = world.once(swap=("sweep", script))
    assert result["holds"] == []


def test_unknown_check_metadata_is_a_closed_schema_refusal(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    record = world.messages("job_request")[0]
    path = Path(record["path"])
    header, body = path.read_text()[4:].split("\n---\n\n", 1)
    value = json.loads(body)
    value["owner_release"] = True
    path.write_text("---\n" + header + "\n---\n\n" + json.dumps(value))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_message_conflict")
    assert mailbox_snapshot(world.root) == before


def test_owned_blocker_resolution_due_is_an_owner_loop_hold(tmp_path):
    world = DispatchWorld(tmp_path)
    reviewer = ready_reviewer(world)
    world.ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "owner",
        "next_decision": "review", "condition": "owner waiting for review", "evidence": world.ledger.evidence},
        **world.ledger.target(world.change.value))
    review_result(world, reviewer)
    process = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/hierarchy_loop.py"),
        "--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store), "--recipes", str(world.recipes_path),
        "--state-dir", str(tmp_path / "loop-state"), "--dispatcher-host-plan", str(world.dispatcher_plan), "once"], capture_output=True, text=True,
        env=os.environ.copy(), timeout=40)
    assert not process.stderr, process.stderr
    assert process.returncode == 3, process.stdout
    value = json.loads(process.stdout)
    assert any(row["kind"] == "small_change_close_due" and row["act"] == "owner" for row in value["holds"])
    assert value["small_changes"][0]["state"] == "owned_hold"
    assert [e["event"]["type"] for e in value["small_changes"][0]["drafts"]] == ["delivery", "resolve"]


def test_stored_attachment_is_a_content_addressed_dispatcher_artifact(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    record = world.messages("dispatch")[0]
    path = Path(record["message"]["brief"]["path"])
    alias = path.with_name("unaddressed.md")
    alias.write_bytes(path.read_bytes())
    rewrite_message(record, lambda m: m["brief"].update(path=str(alias)))
    before = mailbox_snapshot(world.root)
    world.dispatch()
    held(world, "small_change_message_conflict")
    assert mailbox_snapshot(world.root) == before


def test_original_job_receipts_survive_a_later_root_mailbox_binding(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    receipts = world.messages("job_receipt")
    brief = world.root.parent / "root-checkpoint.md"
    brief.write_text("Owner stopped the completed ROOT runner")
    invoke(world.root, "bind", {"endpoint": "engine/root", "host": "next-root-host", "session": "next-root-session",
        "expected_generation": 1, "checkpoint": {"outgoing_stopped": True, "briefs": [{"path": str(brief),
          "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}], "sources": [], "lease_refs": [],
          "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}})
    world.dispatch()
    assert world.projection()["state"] == "reviewing"
    assert world.messages("job_receipt") == receipts
    assert len(world.messages("job_request")) == 1 and len(world.messages("dispatch")) == 2


def test_different_admitted_recipe_hashes_hold_only_the_mismatched_small_change(tmp_path):
    from tools.hierarchy_mailbox import Mailbox
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    original = world.messages("job_request")
    old_hash = world.recipe_hash
    world.recipes["recipes"]["focused"]["steps"][0][-1] = "print('new admitted recipe')"
    world.save_recipes()
    assert world.recipe_hash != old_hash
    root = tmp_path / "docs/mailbox"
    root.parent.mkdir()
    endpoints = {"docs/" + name: {} for name in ("front-door", "orchestrator", "root", "router")}
    endpoints.update({"docs/lane/fix": {"kind": "implementer"}, "docs/lane/review0": {"kind": "reviewer"}})
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [], "writer_limit": 3})
    for endpoint in endpoints:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    world.workspace.register("docs", mailbox_root=str(root), checkouts=[str(world.checkout)])
    second = SmallChange(world.ledger, request("docs-small", team="docs"))
    second.register()
    second.decide()
    admission = second.admission()
    admission["checks"][0]["recipes_sha256"] = world.recipe_hash
    second.admit(admission)
    world.dispatch()
    dispatch = next(r["message"] for r in Mailbox(root).messages().values() if r["message"]["type"] == "dispatch")
    readiness = world.messages("ack")[0]["message"]["readiness"]
    def reply(kind, **extra):
        return invoke(root, "publish", {"message_id": "docs-" + kind, "from": "docs/lane/fix", "to": "docs/orchestrator",
            "host": "host-one", "session": "docs/lane/fix", "binding_generation": 1, "type": kind,
            "in_reply_to": dispatch["message_id"], "body": "modelled participant evidence", **extra})
    reply("ack", acknowledgment="accepted", readiness=readiness)
    world.ledger.intent(second.value, intent_id="docs-attempt")
    world.ledger.event("start", actor=world.ledger.operator, intent_id="docs-attempt", **world.ledger.target(second.value))
    terminal = raw_request({"request_sha256": world.ledger.target(second.value)["request_sha256"], "intent_id": "docs-attempt",
        "outcome": "passed", "exit_code": 0, "source": second.value["source"], "evidence": world.ledger.evidence})
    world.ledger.event("terminal", actor=world.ledger.operator, result=terminal, **world.ledger.target(second.value))
    reply("result", result={"source_revision": world.revision, "source_tree": world.tree,
        "lane_check": "lifecycle-terminal:" + terminal["sha256"],
        "checks": [{"check": "writer", "outcome": "pass", "reference": "modelled participant check"}]})
    world.dispatch()
    world.run_jobs()
    world.dispatch()
    rows = {r["request_id"]: r for r in world.run("status")["small_changes"]}
    assert rows[world.change.value["id"]]["reason"] == "small_change_recipe_mismatch"
    assert rows[second.value["id"]]["state"] == "reviewing"
    assert world.messages("job_request") == original
    assert len([r for r in Mailbox(root).messages().values() if r["message"]["type"] == "job_request"]) == 1
    assert world.ledger.status()["consumed"] == {world.change.value["id"]: 1, second.value["id"]: 1}


PRIVATE_INPUT_ERROR = "owner-private host directory is not an input"
PRIVATE_INPUT_ENTRIES = ("status", "dispatch", "status-api", "projection", "projection-mutate")
PRIVATE_INPUT_PROBE = r"""
import json, os, pwd, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
user = pwd.getpwuid(os.getuid())
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], sys.argv[3], user.pw_shell))
import hierarchy_router as router
import hierarchy_small_change_dispatch as dispatcher
from hierarchy_lifecycle import Lifecycle
from hierarchy_workspace import Store
entry = sys.argv[2]
journal, store_path, recipes = map(Path, sys.argv[4:7])
# API callers supply real objects. Their constructors do not load policy or events.
if entry not in {'status', 'dispatch'}:
    lifecycle, store = Lifecycle(journal), Store(store_path)
accesses = []
descriptors = {}
def canonical(path):
    return Path('/', *path.parts[1:]) if path.anchor == '//' else path
roots = tuple(canonical(root) for root in (journal, store_path))
def observe(operation, value, kwargs=None):
    if isinstance(value, int):
        path = descriptors.get(value)
        if path is None: return
    else:
        if not isinstance(value, (str, bytes, os.PathLike)): return
        path = Path(os.fsdecode(value))
        if not path.is_absolute() and (kwargs or {}).get('dir_fd') is not None:
            parent = (kwargs or {})['dir_fd']
            directory = descriptors.get(parent)
            if directory is None: directory = Path(os.readlink('/proc/self/fd/%d' % parent))
            path = directory/path
    path = canonical(path)
    if any(path == root or root in path.parents for root in roots):
        accesses.append({'operation': operation, 'path': str(path)})
    return path
# Metadata lookup is discovery too: reject CLI private paths before safe_path's lstat.
original_stat, original_lstat = os.stat, os.lstat
if sys.argv[7:] == ['cached-pathlib']:
    # Python 3.9's accessor captures the original OS functions. Reproduce that
    # boundary on newer interpreters so the positive control cannot lose it.
    Path.stat = lambda path, *args, **kwargs: original_stat(path, *args, **kwargs)
    Path.lstat = lambda path, *args, **kwargs: original_lstat(path, *args, **kwargs)
original_path_stat, original_path_lstat = Path.stat, Path.lstat
original_open, original_close, original_fstat, original_read = os.open, os.close, os.fstat, os.read
def stat(path, *args, **kwargs):
    observe('stat', path, kwargs)
    return original_stat(path, *args, **kwargs)
def lstat(path, *args, **kwargs):
    observe('lstat', path, kwargs)
    return original_lstat(path, *args, **kwargs)
os.stat, os.lstat = stat, lstat
def path_stat(path, *args, **kwargs):
    observe('stat', path)
    return original_path_stat(path, *args, **kwargs)
def path_lstat(path, *args, **kwargs):
    observe('lstat', path)
    return original_path_lstat(path, *args, **kwargs)
Path.stat, Path.lstat = path_stat, path_lstat
def opened(path, *args, **kwargs):
    actual = observe('open', path, kwargs)
    descriptor = original_open(path, *args, **kwargs)
    if actual is not None: descriptors[descriptor] = actual
    return descriptor
def closed(descriptor):
    result = original_close(descriptor)
    descriptors.pop(descriptor, None)
    return result
def fstated(descriptor):
    observe('fstat', descriptor)
    return original_fstat(descriptor)
def read(descriptor, size):
    observe('read', descriptor)
    return original_read(descriptor, size)
os.open, os.close, os.fstat, os.read = opened, closed, fstated, read
def audit(event, args):
    if event in {'open', 'os.listdir', 'os.scandir', 'os.mkdir', 'os.remove', 'os.rename'} and args:
        directory = (args[2] if event in {'os.mkdir', 'os.rename'} else args[1]
                     if event == 'os.remove' else None)
        observe(event, args[0], {'dir_fd': directory})
        if event == 'os.rename': observe(event, args[1], {'dir_fd': args[3]})
sys.addaudithook(audit)
if entry in {'status', 'dispatch'}:
    args = ['--lifecycle', str(journal), '--store', str(store_path), entry,
            '--recipes', str(recipes), '--wait', '0.1']
    if entry == 'dispatch':
        args.append('--evidence-only')
    code = router.main(args)
else:
    try:
        if entry == 'status-api':
            result = router.status(lifecycle, store, 0.1, recipes)
        else:
            result = dispatcher.project(lifecycle, store, 0.1, recipes, mutate=entry == 'projection-mutate')
    except ValueError as error:
        print(json.dumps({'exception': type(error).__name__, 'error': str(error)}))
        code = 2
    else:
        print(json.dumps(result))
        code = 0
print(json.dumps({'accesses': accesses}))
sys.exit(code)
"""


def coordination_input_fixture(tmp_path, directory, component, populated, private_root=False):
    # Preserve the modelled password-database home and all runner-owned case evidence.
    (tmp_path / ".keep").write_text("retain private-input refusal evidence\n")
    world = Loop(tmp_path)
    if populated:
        SmallChange(world.ledger).register()
    destination = tmp_path / "home" / directory
    if not private_root:
        destination /= component
    destination.parent.mkdir(parents=True, exist_ok=True)
    if component == "journal":
        world.ledger.path.rename(destination)
        world.ledger.path = destination
    else:
        world.workspace.store.rename(destination)
        world.workspace.store = destination
    recipes = tmp_path / "recipes.json"
    recipes.write_text(json.dumps({"schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable,
        "path": ["/usr/bin", "/bin"], "recipes": {"focused": {"kind": "command", "heavy": False,
        "require_clean": True, "sandbox": "none", "timeout_seconds": 10,
        "steps": [["$python", "-c", "print('modelled check')"]]}}}))
    return world, recipes


def coordination_input_snapshot(root, metadata=False):
    snapshot = {}
    for path in (root, *sorted(root.rglob("*"))):
        info = path.lstat()
        value = (info.st_mode, path.read_bytes() if path.is_file() else None)
        if metadata:
            value += (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        snapshot[str(path.relative_to(root))] = value
    return snapshot


def coordination_input_probe(world, recipes, entry):
    process = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVATE_INPUT_PROBE, str(ROOT / "tools"), entry,
        str(world.tmp / "home"), str(world.ledger.path), str(world.workspace.store), str(recipes)],
        env=os.environ.copy(), capture_output=True, text=True, timeout=20)
    assert process.stderr == "", process.stderr
    lines = process.stdout.splitlines()
    assert len(lines) == 2, process.stdout
    return process.returncode, json.loads(lines[0]), json.loads(lines[1])["accesses"]


@pytest.mark.parametrize("directory", [".codex", ".claude"])
@pytest.mark.parametrize("component", ["journal", "store"])
@pytest.mark.parametrize("entry", PRIVATE_INPUT_ENTRIES)
@pytest.mark.parametrize("populated", [False, True], ids=["empty", "registered-plan"])
def test_private_coordination_inputs_refuse_before_discovery(tmp_path, directory, component, entry, populated):
    world, recipes = coordination_input_fixture(tmp_path, directory, component, populated)
    before = coordination_input_snapshot(tmp_path, metadata=True)
    code, result, accesses = coordination_input_probe(world, recipes, entry)
    assert code == 2, {"result": result, "access_count": len(accesses),
        "lock_accessed": any(Path(a["path"]).name == ".write.lock" for a in accesses),
        "policy_opened": any(a["operation"] == "open" and Path(a["path"]).name == "policy.json" for a in accesses),
        "events_enumerated": any(a["operation"] in {"os.listdir", "os.scandir"}
                                 and Path(a["path"]).name == "events" for a in accesses)}
    if entry in {"status", "dispatch"}:
        expected = {"state": "hold", "execution_enabled": False, "error": PRIVATE_INPUT_ERROR}
        if entry == "status":
            expected["source"] = "arguments"
    else:
        expected = {"exception": "ValueError", "error": PRIVATE_INPUT_ERROR}
    assert result == expected, {"result": result, "accesses": accesses}
    assert accesses == [], "private input must refuse before any coordination-root discovery or lock creation"
    assert coordination_input_snapshot(tmp_path, metadata=True) == before


@pytest.mark.parametrize("directory", [".codex.public", ".claude.public"])
@pytest.mark.parametrize("component", ["journal", "store"])
@pytest.mark.parametrize("entry", PRIVATE_INPUT_ENTRIES)
def test_public_coordination_inputs_remain_readable_with_empty_rows(tmp_path, directory, component, entry):
    world, recipes = coordination_input_fixture(tmp_path, directory, component, False)
    before = coordination_input_snapshot(tmp_path)
    code, result, accesses = coordination_input_probe(world, recipes, entry)
    assert code == 0, result
    assert accesses, "positive control must exercise actual journal/store discovery"
    if entry in {"status", "status-api"}:
        assert result["requests"] == []
    else:
        assert result["small_changes"] == []
    assert coordination_input_snapshot(tmp_path) == before


@pytest.mark.parametrize("directory", [".codex", ".claude"])
@pytest.mark.parametrize("component", ["journal", "store"])
@pytest.mark.parametrize("entry", PRIVATE_INPUT_ENTRIES)
@pytest.mark.parametrize("path_form", ["root", "double-leading-slash"])
def test_private_coordination_root_spelling_refuses_before_discovery(tmp_path, directory, component, entry, path_form):
    # Model the exact private root and POSIX's alternative leading-slash spelling.
    world, recipes = coordination_input_fixture(tmp_path, directory, component, False, private_root=path_form == "root")
    if path_form == "double-leading-slash":
        if component == "journal":
            world.ledger.path = Path("/" + str(world.ledger.path))
        else:
            world.workspace.store = Path("/" + str(world.workspace.store))
    before = coordination_input_snapshot(tmp_path, metadata=True)
    code, result, accesses = coordination_input_probe(world, recipes, entry)
    assert code == 2, {"result": result, "access_count": len(accesses)}
    if entry in {"status", "dispatch"}:
        expected = {"state": "hold", "execution_enabled": False, "error": PRIVATE_INPUT_ERROR}
        if entry == "status":
            expected["source"] = "arguments"
    else:
        expected = {"exception": "ValueError", "error": PRIVATE_INPUT_ERROR}
    assert result == expected
    assert accesses == [], "private root spelling must refuse before coordination-root discovery"
    assert coordination_input_snapshot(tmp_path, metadata=True) == before


def coordination_input_probe_at_home(world, recipes, entry, pwd_home, *, cached_pathlib=False):
    process = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVATE_INPUT_PROBE, str(ROOT / "tools"), entry,
        str(pwd_home), str(world.ledger.path), str(world.workspace.store), str(recipes),
        *(['cached-pathlib'] if cached_pathlib else [])],
        env=os.environ.copy(), capture_output=True, text=True, timeout=20)
    assert process.stderr == "", process.stderr
    lines = process.stdout.splitlines()
    assert len(lines) == 2, process.stdout
    return process.returncode, json.loads(lines[0]), json.loads(lines[1])["accesses"]


def coordination_input_spelling(world, component, spelling):
    if spelling == "double":
        if component == "journal":
            world.ledger.path = Path("/" + str(world.ledger.path))
        else:
            world.workspace.store = Path("/" + str(world.workspace.store))


@pytest.mark.parametrize("entry", PRIVATE_INPUT_ENTRIES)
@pytest.mark.parametrize("component", ["journal", "store"])
def test_coordination_discovery_witness_covers_cached_pathlib_accessors(tmp_path, component, entry):
    world, recipes = coordination_input_fixture(tmp_path, ".codex.public", component, False)
    coordination_input_spelling(world, component, "double")
    before = coordination_input_snapshot(tmp_path)
    code, result, accesses = coordination_input_probe_at_home(
        world, recipes, entry, "/" + str(world.tmp / "home"), cached_pathlib=True)
    assert code == 0, result
    assert accesses, "cached pathlib must not hide real journal/store discovery"
    selected = world.ledger.path if component == "journal" else world.workspace.store
    selected = Path("/", *selected.parts[1:]) if selected.anchor == "//" else selected
    assert any(row["operation"] == "read" and selected in Path(row["path"]).parents for row in accesses), accesses
    assert coordination_input_snapshot(tmp_path) == before


@pytest.mark.parametrize("directory", [".codex", ".claude"])
@pytest.mark.parametrize("component", ["journal", "store"])
@pytest.mark.parametrize("entry", PRIVATE_INPUT_ENTRIES)
@pytest.mark.parametrize("root_form", ["root", "descendant"])
@pytest.mark.parametrize("input_form", ["normal", "double"])
def test_double_pwd_home_refuses_private_inputs_before_discovery(
        tmp_path, directory, component, entry, root_form, input_form):
    # Both pwd and candidate spellings describe real temporary fixtures, never owner-private data.
    world, recipes = coordination_input_fixture(tmp_path, directory, component, False, private_root=root_form == "root")
    coordination_input_spelling(world, component, input_form)
    before = coordination_input_snapshot(tmp_path, metadata=True)
    code, result, accesses = coordination_input_probe_at_home(world, recipes, entry, "/" + str(world.tmp / "home"))
    assert code == 2, {"result": result, "access_count": len(accesses)}
    if entry in {"status", "dispatch"}:
        expected = {"state": "hold", "execution_enabled": False, "error": PRIVATE_INPUT_ERROR}
        if entry == "status":
            expected["source"] = "arguments"
    else:
        expected = {"exception": "ValueError", "error": PRIVATE_INPUT_ERROR}
    assert result == expected
    assert accesses == [], "pwd home and every candidate must be compared before discovery or lock creation"
    assert coordination_input_snapshot(tmp_path, metadata=True) == before


@pytest.mark.parametrize("directory", [".codex.public", ".claude.public"])
@pytest.mark.parametrize("component", ["journal", "store"])
@pytest.mark.parametrize("entry", PRIVATE_INPUT_ENTRIES)
@pytest.mark.parametrize("input_form", ["normal", "double"])
@pytest.mark.parametrize("home_form", ["normal", "double"])
def test_public_inputs_accept_normal_and_double_pwd_home_spellings(
        tmp_path, directory, component, entry, input_form, home_form):
    world, recipes = coordination_input_fixture(tmp_path, directory, component, False)
    coordination_input_spelling(world, component, input_form)
    pwd_home = str(world.tmp / "home")
    if home_form == "double":
        pwd_home = "/" + pwd_home
    before = coordination_input_snapshot(tmp_path)
    code, result, accesses = coordination_input_probe_at_home(world, recipes, entry, pwd_home)
    assert code == 0, result
    assert accesses, "positive control must exercise real journal/store discovery"
    if entry in {"status", "status-api"}:
        assert result["requests"] == []
    else:
        assert result["small_changes"] == []
    assert coordination_input_snapshot(tmp_path) == before


# Canonical child transport and durable planning evidence are independent public boundaries.
def compat_world(tmp_path):
    from tests.integration.test_hierarchy_loop import World
    (tmp_path / ".keep").write_text("retain canonical compatibility evidence\n")
    return activate_loop(World(tmp_path))


def compat_router(world, dispatch_action=""):
    return world.script("compat-router.py", (
        "import json, os, subprocess, sys\nfrom pathlib import Path\n"
        "if 'dispatch' in sys.argv:\n" +
        "".join("    " + line + "\n" for line in (dispatch_action or "pass").splitlines()) +
        "print(json.dumps({'router': False, 'requests': []} if 'status' in sys.argv else {}))\n"))


def compat_add_other_team(world):
    from tests.integration.test_hierarchy_provision import INITIATIVE, provision
    from tests.integration.test_hierarchy_sweep import started
    base = world.tmp / "initiatives/docs"
    initialization = world.init_request()
    initialization.update(base=str(base), initiative={**INITIATIVE, "id": "docs"})
    provision("init", initialization)
    for role in ("orchestrator", "root"):
        host = "codex-cli" if role == "root" else "claude-code"
        options = {"session": "docs-root"} if role == "root" else {}
        record = provision("add-role", world.request(base=str(base), endpoint="docs/" + role,
                                                     host=host, cwd=str(world.tmp), **options))
        started(world, host, record["session"])
    world.send("docs/root", "docs/orchestrator", "independent-canonical-work", root=base / "mailbox")


def test_compat_durable_skips_survive_bad_status_while_other_team_progresses(tmp_path):
    world = compat_world(tmp_path)
    change = SmallChange(world.ledger, request(team="pilot"))
    change.register()
    world.send("pilot/root", "pilot/orchestrator", "retained-planning-mail")
    compat_add_other_team(world)
    journal = world.ledger.files()
    result = world.once(expect=3, swap=("router", compat_router(world)))
    assert any(r["step"] == "router_status" and r["kind"] == "child_failed" for r in result["holds"])
    assert any(r["step"] == "dispatch" and r["kind"] == "dispatch_error" for r in result["holds"])
    assert not any(r["kind"] == "planning_exclusions_unavailable" for r in result["holds"])
    assert "docs/orchestrator" in world.woken()
    assert "pilot/orchestrator" not in world.woken() and "pilot/decider" not in world.woken()
    assert any(r["kind"] == "small_change_planning_skipped" and r.get("endpoint") == "pilot/orchestrator"
               for r in result["holds"])
    assert result["small_changes"][0]["request_id"] == change.value["id"]
    assert [r["message"]["message_id"] for r in world.inbox("pilot/orchestrator")] == ["retained-planning-mail"]
    assert world.ledger.files() == journal


def test_compat_registration_after_status_and_status_loss_reconstruct_fresh_skips(tmp_path):
    world = compat_world(tmp_path)
    change = SmallChange(world.ledger, request(team="pilot"))
    event = {"id": "registration-between-loop-steps", "actor": "coordinator-1", "generation": 1,
        "custody": {"cid": "root-1", "generation": 1},
        "event": {"type": "small_change_plan", "proposal": raw_request(change.plan),
                  "participants": change.participants, **world.ledger.target(change.value)}}
    envelope = tmp_path / "registration.json"
    envelope.write_text(json.dumps(event))
    action = ("p = subprocess.run([sys.executable, '-I', '-B', %r, '--root', %r, 'record', '--event', %r, "
              "'--evidence-only'], env=os.environ.copy(), capture_output=True, text=True)\n"
              "assert p.returncode == 0, p.stdout + p.stderr") % (
                  str(ROOT / "tools/hierarchy_lifecycle.py"), str(world.ledger.path), str(envelope))
    child = compat_router(world, action)
    # A valid but stale first status must not become skip authority after the registration.
    child.write_text(child.read_text().replace("{'router': False, 'requests': []}",
        "{'router': 'router-1', 'requests': [], 'small_changes': [], 'planning_exclusions': []}"))
    world.send("pilot/root", "pilot/orchestrator", "new-plan-retained")
    for tick in range(2):
        if tick:
            world.status_path.unlink()
        result = world.once(expect=3, swap=("router", child))
        assert result["small_changes"][0]["request_id"] == change.value["id"]
        assert any(r["kind"] == "small_change_planning_skipped" and r.get("endpoint") == "pilot/orchestrator"
                   for r in result["holds"])
        assert world.woken() == []
        assert [r["message"]["message_id"] for r in world.inbox("pilot/orchestrator")] == ["new-plan-retained"]


COMPAT_RAW_PASS = r"""
import argparse, importlib.util, json, os, pwd, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_loop', sys.argv[1])
loop = importlib.util.module_from_spec(spec); spec.loader.exec_module(loop)
loop.TOOLS['router'], loop.TOOLS['jobs'] = Path(sys.argv[2]), Path(sys.argv[3])
user = pwd.getpwuid(os.getuid())
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], sys.argv[4], user.pw_shell))
journal, store, recipes, state_dir = map(Path, sys.argv[5:9])
accesses = []
def observe(kind, value):
    if isinstance(value, (str, bytes, os.PathLike)):
        p = Path(os.fsdecode(value))
        if any(p == root or root in p.parents for root in (journal, store)):
            accesses.append({'operation': kind, 'path': str(p)})
stat, lstat = os.stat, os.lstat
def traced_stat(path, *args, **kwargs):
    observe('stat', path)
    return stat(path, *args, **kwargs)
def traced_lstat(path, *args, **kwargs):
    observe('lstat', path)
    return lstat(path, *args, **kwargs)
os.stat, os.lstat = traced_stat, traced_lstat
def audit(event, args):
    if event in {'open', 'os.listdir', 'os.scandir', 'os.mkdir', 'os.remove', 'os.rename'} and args:
        observe(event, args[0])
sys.addaudithook(audit)
args = argparse.Namespace(lifecycle=journal, store=store, recipes=recipes, state_dir=state_dir, max_jobs=None,
                          dispatcher_host_plan=state_dir.parent/'dispatcher-host-plan.json')
code, stopped, report, wrote = loop.one_pass(args, None)
print(json.dumps({'accesses': accesses, 'stopped': stopped, 'wrote': wrote}))
sys.exit(code)
"""


def compat_raw_pass(world, journal, store):
    from tests.integration.test_hierarchy_loop import answering
    world.state_dir.mkdir(exist_ok=True)
    child = compat_router(world)
    jobs = answering(world, "compat-jobs.py", {"run-open": (0, {"rows": []})})
    process = subprocess.run([sys.executable, "-I", "-B", "-c", COMPAT_RAW_PASS,
        str(ROOT / "tools/hierarchy_loop.py"), str(child), str(jobs), str(world.tmp / "modelled-home"),
        str(journal), str(store), str(world.recipes_path), str(world.state_dir)],
        env=world.env(), capture_output=True, text=True, timeout=40)
    assert process.returncode == 3 and process.stderr == "", process.stdout + process.stderr
    lines = process.stdout.splitlines()
    assert len(lines) == 2, process.stdout
    return json.loads(lines[0]), json.loads(lines[1])


@pytest.mark.parametrize("component,damage", [
    ("journal", "busy"), ("journal", "corrupt"), ("store", "corrupt"),
    ("journal", "nested-json"),
    ("journal", "unreadable"), ("store", "unreadable"),
    ("journal", "symlink"), ("store", "symlink"),
    ("journal", ".codex"), ("store", ".codex"), ("journal", ".claude"), ("store", ".claude"),
])
def test_compat_bad_durable_input_blocks_wakes_but_run_open_continues(tmp_path, component, damage):
    world = compat_world(tmp_path)
    world.ledger.publish(request("durable-input-probe", team="pilot"))
    world.send("pilot/root", "pilot/orchestrator", "must-stay-unread")
    journal, store = world.ledger.path, world.workspace.store
    target = journal if component == "journal" else store
    if damage == "busy":
        (target / ".write.lock").write_text("retained fixture lock")
    elif damage in {"corrupt", "nested-json"}:
        first = next((target / "events").iterdir())
        first.write_text("{}" if damage == "corrupt" else "[" * 2000 + "0" + "]" * 2000)
    elif damage == "unreadable":
        assert os.geteuid() != 0, "permission-refusal control requires an unprivileged test runner"
        first = next((target / "events").iterdir())
        first.chmod(0)
    elif damage == "symlink":
        alias = tmp_path / ("linked-" + component)
        alias.symlink_to(target, target_is_directory=True)
        target = alias
    else:
        private = tmp_path / "modelled-home" / damage / component
        private.parent.mkdir(parents=True)
        target.rename(private)
        target = private
    journal, store = (target, store) if component == "journal" else (journal, target)
    if damage in {".codex", ".claude"}:
        before = coordination_input_snapshot(target.parent, metadata=True)
    result, telemetry = compat_raw_pass(world, journal, store)
    owner = [r for r in result["holds"] if r["kind"] == "planning_exclusions_unavailable"]
    assert len(owner) == 1 and owner[0]["act"] == "owner"
    assert {r["step"]: r["state"] for r in result["steps"]}["sweep"] == "skipped"
    assert {r["step"]: r["state"] for r in result["steps"]}["run_open"] == "ok"
    assert world.woken() == []
    assert [r["message"]["message_id"] for r in world.inbox("pilot/orchestrator")] == ["must-stay-unread"]
    assert "router must be str" not in owner[0]["detail"], "transport rejection is not a durable read failure"
    if damage in {".codex", ".claude"}:
        assert owner[0]["detail"] == PRIVATE_INPUT_ERROR
        assert telemetry["accesses"] == [], "raw private paths must refuse before constructors discover them"
        assert coordination_input_snapshot(target.parent, metadata=True) == before
    elif damage == "busy":
        assert "busy" in owner[0]["detail"]
        assert (target / ".write.lock").read_text() == "retained fixture lock"
    elif damage == "unreadable":
        assert "Permission denied" in owner[0]["detail"]
    elif damage == "symlink":
        assert "symlink" in owner[0]["detail"]
    else:
        assert owner[0]["detail"]


def test_compat_unrecorded_writer_is_still_skipped_after_dispatch_child_failure(tmp_path):
    world = compat_world(tmp_path)
    world.add_role("pilot/lane/f2", cwd=str(tmp_path))
    world.add_role("pilot/lane/review", cwd=str(tmp_path))
    change = SmallChange(world.ledger, request(team="pilot"))
    change.plan["plan"]["writing_lanes"][0]["lane"] = "f2"
    change.register()
    change.decide()
    change.admit()
    row = DispatchWorld.dispatch(world, fault="route")["small_changes"][0]
    assert row["reason"] == "delivered_unrecorded"
    writer = world.inbox("pilot/lane/f2")
    assert len(writer) == 1 and writer[0]["message"]["type"] == "dispatch"
    journal, mail = world.ledger.files(), mailbox_snapshot(world.root)
    result = world.once(expect=3, swap=("router", compat_router(world)))
    assert result["small_changes"][0]["reason"] == "delivered_unrecorded"
    assert any(r["kind"] == "small_change_planning_skipped" and r.get("endpoint") == "pilot/lane/f2"
               for r in result["holds"])
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == (journal, mail)
    assert world.inbox("pilot/lane/f2") == writer
    assert world.woken() == []


def test_compat_empty_durable_projection_preserves_canonical_output_omission(tmp_path):
    world = compat_world(tmp_path)
    result = world.once(expect=3, swap=("router", compat_router(world)))
    assert any(r["step"] == "router_status" and r["kind"] == "child_failed" for r in result["holds"])
    assert any(r["step"] == "dispatch" and r["kind"] == "dispatch_error" for r in result["holds"])
    assert not any(r["kind"] == "planning_exclusions_unavailable" for r in result["holds"])
    assert {r["step"]: r["state"] for r in result["steps"]}["sweep"] == "ok"
    assert "small_changes" not in result


# Formal-review repairs: public controls append to the frozen 624-case prefix.
def formal_dispatch(world, *, command="dispatch", watch=None, action="", expect=0):
    script = r"""
import builtins, importlib.util, io, json, os, pwd, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_router', sys.argv[1])
router = importlib.util.module_from_spec(spec); spec.loader.exec_module(router)
home, watched, action = sys.argv[2:5]
user = pwd.getpwuid(os.getuid())
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], home, user.pw_shell))
original = builtins.open
original_io = io.open
def opened(path, *args, **kwargs):
    if watched and isinstance(path, (str, bytes, os.PathLike)) and Path(path) == Path(watched):
        Path(watched + '.opened').write_text('unsafe downstream open attempted')
        if action == 'deny':
            raise OSError('modelled unsafe artifact open refused by test boundary')
    return original(path, *args, **kwargs)
builtins.open = opened
def io_opened(path, *args, **kwargs):
    if watched and isinstance(path, (str, bytes, os.PathLike)) and Path(path) == Path(watched):
        Path(watched + '.opened').write_text('unsafe downstream io.open attempted')
        if action == 'deny':
            raise OSError('modelled unsafe artifact reopen refused by test boundary')
    return original_io(path, *args, **kwargs)
io.open = io_opened
listed = os.scandir
injected = False
def scandir(path):
    entries = listed(path)
    actual = Path(os.readlink('/proc/self/fd/%d' % path)) if type(path) is int else Path(path)
    class Scan:
        def __enter__(self):
            entries.__enter__()
            return self
        def __exit__(self, *args):
            return entries.__exit__(*args)
        def __iter__(self):
            return self
        def __next__(self):
            global injected
            try:
                return next(entries)
            except StopIteration:
                if action == 'late-entry' and not injected and actual == Path(watched):
                    injected = True
                    os.mkfifo(actual / 'step-late')
                raise
    return Scan()
os.scandir = scandir
opened_fd = os.open
def fd_opened(path, flags, *args, **kwargs):
    global injected
    if action in {'replace-fifo', 'replace-symlink', 'change-content'} and not injected and str(path) == Path(watched).name:
        directory = kwargs.get('dir_fd')
        if directory is not None and Path(os.readlink('/proc/self/fd/%d' % directory)) == Path(watched).parent:
            injected = True
            target = Path(watched)
            if action == 'change-content':
                with original(target, 'ab') as stream: stream.write(b'changed')
            else:
                target.rename(target.with_name('retained-original-log'))
                if action == 'replace-fifo': os.mkfifo(target)
                else: target.symlink_to(target.with_name('retained-original-log'))
    return opened_fd(path, flags, *args, **kwargs)
os.open = fd_opened
sys.exit(router.main(sys.argv[5:]))
"""
    args = ["--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store), command,
            "--recipes", str(world.recipes_path), "--wait", "0.1"]
    if command == "dispatch":
        args.append("--evidence-only")
    process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROUTER),
        str(world.tmp / "home"), str(watch or ""), action, *args], capture_output=True, text=True,
        env=os.environ.copy(), timeout=30)
    assert process.returncode == expect and process.stderr == "", process.stdout + process.stderr
    return json.loads(process.stdout)


def formal_completed_job(world):
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    world.run_jobs()
    message = world.messages("job_request")[0]["message"]
    return world.workspace.store / "jobs/engine" / message["message_id"]


def test_formal_unlisted_fifo_refuses_before_downstream_open(tmp_path):
    (tmp_path / ".keep").write_text("formal retained-artifact refusal evidence\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    fifo = folder / "step-extra"
    os.mkfifo(fifo)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = formal_dispatch(world, watch=fifo, action="deny")["small_changes"][0]
    assert row["reason"] == "small_change_receipt_invalid"
    assert not Path(str(fifo) + ".opened").exists(), "retained FIFO reached an unchecked downstream reader"
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("role", [[], {}], ids=["list", "object"])
def test_formal_policy_role_type_holds_only_projection_boundary(tmp_path, role):
    world = compat_world(tmp_path)
    policy = world.ledger.path / "policy.json"
    value = json.loads(policy.read_text())
    value["actors"]["operator-1"]["role"] = role
    policy.write_text(json.dumps(value))
    world.send("pilot/root", "pilot/orchestrator", "retained-role-error")
    result, telemetry = compat_raw_pass(world, world.ledger.path, world.workspace.store)
    assert any(r["kind"] == "planning_exclusions_unavailable" and r["act"] == "owner" for r in result["holds"])
    assert {r["step"]: r["state"] for r in result["steps"]}["sweep"] == "skipped"
    assert {r["step"]: r["state"] for r in result["steps"]}["run_open"] == "ok"
    assert world.woken() == []
    assert [r["message"]["message_id"] for r in world.inbox("pilot/orchestrator")] == ["retained-role-error"]


def formal_foreign_assignment(world, lane="review0", complete=True):
    endpoint = "engine/lane/" + lane
    identifier = "legacy-" + lane
    brief = world.root.parent / (identifier + ".md")
    brief.write_text("prior owner assignment\n")
    invoke(world.root, "publish", {"message_id": identifier, "from": "engine/orchestrator", "to": endpoint,
        "host": "host-one", "session": "engine/orchestrator", "binding_generation": 1,
        "type": "dispatch", "body": "previous independent assignment",
        "brief": {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}})
    readiness = {"worktree": str(world.checkout), "branch": "candidate", "base_revision": world.revision,
        "lease_ref": "refs/aegis/lanes/modelled-legacy", "lease_oid": "a" * 40,
        "lease_expires_at": "2099-01-01T00:00:00Z", "owned_paths": ["app.txt"],
        "scan_workspace": str(world.checkout), "scan_evidence": "modelled scan",
        "enforcement_tier": "advisory", "hook_evidence": "modelled hooks"}
    extra = {} if lane == "review0" else {"readiness": readiness}
    invoke(world.root, "publish", {"message_id": identifier + "-accepted", "from": endpoint,
        "to": "engine/orchestrator", "host": "host-one", "session": endpoint, "binding_generation": 1,
        "type": "ack", "in_reply_to": identifier, "body": "accepted prior assignment",
        "acknowledgment": "accepted", **extra})
    if complete:
        invoke(world.root, "publish", {"message_id": identifier + "-completed", "from": endpoint,
            "to": "engine/orchestrator", "host": "host-one", "session": endpoint, "binding_generation": 1,
            "type": "review" if lane == "review0" else "result", "in_reply_to": identifier,
            "body": "prior assignment completed; grants no current lifecycle/check evidence",
            "result": {"source_revision": world.revision, "source_tree": world.tree,
                "lane_check": "modelled legacy completion", "checks": [
                    {"check": "legacy", "outcome": "fail", "reference": "prior failure retained"}]}})
    return identifier


def test_formal_completed_legacy_reviewer_does_not_block_later_small_change(tmp_path):
    (tmp_path / ".keep").write_text("formal closed-history evidence\n")
    world = DispatchWorld(tmp_path)
    parent = formal_foreign_assignment(world)
    row = world.dispatch()["small_changes"][0]
    assert row["state"] == "writer_sent", row
    assert [r["message"]["message_id"] for r in world.messages("dispatch")] == [
        parent, "scw-" + raw_request(world.change.plan)["sha256"]]
    assert world.change.row()["review"] is None and world.messages("job_request") == []


@pytest.mark.parametrize("damage", ["directory", "symlink", "late-entry", "replace-fifo", "replace-symlink", "change-content"])
def test_formal_artifact_types_and_races_hold_without_republication(tmp_path, damage):
    (tmp_path / ".keep").write_text("retained artifact race evidence\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    watch, action = folder / "step-1.log", damage
    if damage == "directory":
        watch = folder / "step-extra"
        watch.mkdir()
        action = "deny"
    elif damage == "symlink":
        private = tmp_path / "home/.codex/modelled-private"
        private.parent.mkdir()
        private.write_text("modelled private target: never an actual owner file")
        watch = folder / "step-extra"
        watch.symlink_to(private)
        action = "deny"
    elif damage == "late-entry":
        watch = folder
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = formal_dispatch(world, watch=watch, action=action)["small_changes"][0]
    assert row["reason"] == "small_change_receipt_invalid", row
    if damage in {"directory", "symlink"}:
        assert not Path(str(watch) + ".opened").exists()
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("name", ["step-1.log", "result.json", "claim.json", "process.json", "packet.md"])
def test_formal_captured_data_is_consumed_without_downstream_reopen(tmp_path, name):
    (tmp_path / ".keep").write_text("snapshot-consumption evidence\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    row = formal_dispatch(world, watch=folder / name, action="deny")["small_changes"][0]
    assert row["state"] == "reviewing", row
    assert not Path(str(folder / name) + ".opened").exists(), "captured artifact reopened by an unchecked reader"


def formal_jobs(world, mode, expect=3):
    script = r"""
import importlib.util, json, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_jobs', sys.argv[1])
jobs = importlib.util.module_from_spec(spec); spec.loader.exec_module(jobs)
original = os.link
mode = sys.argv[2]
def link(src, dst, *args, **kwargs):
    target = Path(dst)
    if mode == 'max-result' and target.name == 'result.json':
        value = json.loads(Path(src).read_text())
        value['padding'] = ''
        value['padding'] = 'p' * (jobs.MAX_RESULT_BYTES - len(jobs.encoded(value)) - 1)
        Path(src).write_bytes(jobs.encoded(value) + b'\n')
    if mode == 'receipt-loss' and target.suffix == '.md':
        text = Path(src).read_text()
        if text.startswith('---\n'):
            message = json.loads(text[4:].split('\n---\n', 1)[0])
            if message.get('type') == 'job_receipt' and message['receipt']['state'] in {'failed', 'refused'}:
                raise OSError('modelled original terminal receipt publication failure')
    value = original(src, dst, *args, **kwargs)
    if mode == 'numeric-logs' and target.name == 'result.json':
        for path in target.parent.glob('step-*.log'):
            path.rename(path.with_name('step-%d.log' % int(path.stem[5:])))
    return value
os.link = link
sys.exit(jobs.main(sys.argv[3:]))
"""
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(JOBS), mode,
        "--store", str(world.workspace.store), "--recipes", str(world.recipes_path), "run-open"],
        env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert p.returncode == expect and p.stderr == "", p.stdout + p.stderr
    return json.loads(p.stdout)


@pytest.mark.parametrize("outcome", ["failed", "refused"])
def test_formal_retained_failure_blocks_partial_batch_until_original_settlement(tmp_path, outcome):
    (tmp_path / ".keep").write_text("partial batch terminal receipt loss\n")
    changes = {"steps": [["$python", "-c", "raise SystemExit(7)"]]} if outcome == "failed" else None
    world = DispatchWorld(tmp_path, checks=2, recipe_changes=changes)
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    requests = world.messages("job_request")
    assert len(requests) == 1
    first = requests[0]["message"]["message_id"]
    app = world.checkout / "app.txt"
    original = app.read_bytes()
    if outcome == "refused":
        app.write_text("modelled dirty checkout during runner admission")
    formal_jobs(world, "receipt-loss")
    if outcome == "refused":
        app.write_bytes(original)
    folder = world.workspace.store / "jobs/engine" / first
    result = json.loads((folder / "result.json").read_text())
    assert result["state"] == outcome
    original_claim = (folder / "claim.json").read_bytes()
    original_result = (folder / "result.json").read_bytes()
    assert not any(r["message"]["receipt"]["state"] in {"failed", "refused"} for r in world.messages("job_receipt"))
    for command in ("status", "dispatch", "status", "dispatch"):
        row = world.dispatch(command=command)["small_changes"][0]
        assert row["reason"] == "small_change_check_failed", row
        assert world.messages("job_request") == requests
        assert len(world.messages("dispatch")) == 1
    settled = world.run_jobs()
    assert settled["rows"][0]["state"] == outcome
    assert any(r["message"]["receipt"]["state"] == outcome for r in world.messages("job_receipt"))
    assert (folder / "claim.json").read_bytes() == original_claim
    assert (folder / "result.json").read_bytes() == original_result
    assert world.messages("job_request") == requests


def test_formal_public_runner_receipt_parity_for_large_numeric_and_empty_logs(tmp_path):
    (tmp_path / ".keep").write_text("public runner byte parity\n")
    big = r"import sys; sys.stdout.buffer.write(b'x'*300000+b'\xff\x00\t\r\n')"
    steps = [["$python", "-c", big]] + [["$python", "-c", "print('step-%d')" % n] for n in range(2, 10)]
    steps += [["$python", "-c", r"import sys; sys.stdout.buffer.write(b'z'*3000+b'\xff\x00\t\r\n')"],
              ["$python", "-c", "pass"]]
    world = DispatchWorld(tmp_path, recipe_changes={"steps": steps})
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    formal_jobs(world, "numeric-logs", expect=0)
    receipts = world.messages("job_receipt")
    terminal = next(r for r in receipts if r["message"]["receipt"]["state"] == "completed")
    assert "z" * 100 in terminal["message"]["body"] and "\ufffd" in terminal["message"]["body"]
    assert "\x00" not in terminal["message"]["body"] and "\r" not in terminal["message"]["body"]
    job = world.messages("job_request")[0]["message"]["message_id"]
    folder = world.workspace.store / "jobs/engine" / job
    assert (folder / "step-1.log").stat().st_size > 262144 and (folder / "step-11.log").stat().st_size == 0
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}
    assert world.dispatch()["small_changes"][0]["state"] == "reviewing"
    assert world.messages("job_receipt") == receipts
    assert {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()} == before


@pytest.mark.parametrize("lane", ["fix", "review0"])
@pytest.mark.parametrize("succession", [False, True])
def test_formal_closed_assignment_history_is_not_current_success_evidence(tmp_path, lane, succession):
    (tmp_path / ".keep").write_text("closed historical binding evidence\n")
    world = DispatchWorld(tmp_path)
    parent = formal_foreign_assignment(world, lane=lane)
    old = request("legacy-canonical")
    world.ledger.ready(old)
    world.ledger.intent(old)
    world.ledger.event("start", actor=world.ledger.operator, intent_id="attempt-1", **world.ledger.target(old))
    world.ledger.terminal(old)
    world.ledger.accepted_delivery(old)
    world.ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": world.ledger.evidence},
                       **world.ledger.target(old))
    if succession:
        path = world.root.parent / "handoff-history.md"
        path.write_text("modelled owner stopped completed historical lane")
        binding = invoke(world.root, "bind", {"endpoint": "engine/lane/" + lane, "host": "next-host",
            "session": "next-session", "expected_generation": 1, "checkpoint": {
                "outgoing_stopped": True, "briefs": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}],
                "sources": [], "lease_refs": [], "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}})
        invoke(world.root, "ack-handoff", {"endpoint": "engine/lane/" + lane, "session": "next-session",
            "generation": 2, "checkpoint_sha256": binding["checkpoint_sha256"]})
    row = world.dispatch()["small_changes"][0]
    assert row["state"] == "writer_sent", row
    assert world.change.row()["terminal"] is None and world.change.row()["review"] is None
    assert world.messages("job_request") == []
    assert [r["message"]["message_id"] for r in world.messages("dispatch")] == [
        parent, "scw-" + raw_request(world.change.plan)["sha256"]]


@pytest.mark.parametrize("damage", ["missing-completion", "missing-acceptance", "duplicate-completion", "malformed-completion", "wrong-binding", "live-canonical"])
def test_formal_ambiguous_legacy_assignments_remain_held(tmp_path, damage):
    (tmp_path / ".keep").write_text("ambiguous historical assignment evidence\n")
    world = DispatchWorld(tmp_path)
    parent = formal_foreign_assignment(world, complete=damage != "missing-completion")
    if damage == "missing-acceptance":
        record = next(r for r in world.messages() if r["message"]["message_id"] == parent + "-accepted")
        Path(record["path"]).rename(tmp_path / "retained-missing-acceptance.md")
    elif damage == "duplicate-completion":
        record = next(r for r in world.messages() if r["message"]["message_id"] == parent + "-completed")
        path = Path(record["path"]).with_name("duplicate-legacy.md")
        path.write_bytes(Path(record["path"]).read_bytes())
        rewrite_message({"path": str(path)}, lambda m: m.update(message_id="duplicate-legacy-completion"))
    elif damage in {"malformed-completion", "wrong-binding"}:
        record = next(r for r in world.messages() if r["message"]["message_id"] == parent + "-completed")
        if damage == "malformed-completion":
            rewrite_message(record, lambda m: m["result"].pop("checks"))
        else:
            rewrite_message(record, lambda m: m.update(session="not-the-historical-session"))
    elif damage == "live-canonical":
        world.ledger.publish(request("still-open-canonical"))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()["small_changes"][0]
    assert row["state"] == "held"
    assert row["reason"] == ("small_change_result_invalid" if damage == "malformed-completion" else "small_change_mixed_queue")
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("prior", [False, True])
def test_formal_fresh_mixed_queue_fence_preserves_prior_delivery_recovery(tmp_path, prior):
    (tmp_path / ".keep").write_text("fresh mixed-queue fence and recovery\n")
    world = Loop(tmp_path)
    world.team("engine")
    canonical = request("canonical-before-selection")
    world.ledger.publish(canonical)
    world.ledger.approve(canonical)
    original_id = deliver_without_recording(world, canonical) if prior else None
    original = world.inbox("engine") if prior else None
    if prior:
        assert [r["message"]["message_id"] for r in original] == [original_id]
    change = SmallChange(world.ledger, request("small-registered-during-routing"))
    envelope = {"id": "register-during-mailbox-lock", "actor": "coordinator-1", "generation": 1,
        "custody": {"cid": "root-1", "generation": 1},
        "event": {"type": "small_change_plan", "proposal": raw_request(change.plan),
                  "participants": change.participants, **world.ledger.target(change.value)}}
    path = tmp_path / "late-registration.json"
    path.write_text(json.dumps(envelope))
    script = r"""
import importlib.util, os, subprocess, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_router', sys.argv[1])
router = importlib.util.module_from_spec(spec); spec.loader.exec_module(router)
root, journal, envelope, lifecycle_cli = sys.argv[2:6]
original = os.open
registered = False
def opened(path, flags, *args, **kwargs):
    global registered
    actual = Path(path)
    if not actual.is_absolute() and kwargs.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%d' % kwargs['dir_fd'])) / actual
    if not registered and actual == Path(root) / '.write.lock':
        registered = True
        p = subprocess.run([sys.executable, '-I', '-B', lifecycle_cli, '--root', journal, 'record',
                            '--event', envelope, '--evidence-only'], env=os.environ.copy(), capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
    return original(path, flags, *args, **kwargs)
os.open = opened
code = router.main(sys.argv[6:])
assert registered, 'the mixed-queue registration must reach the real mailbox lock boundary'
sys.exit(code)
"""
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROUTER), str(world.mailboxes["engine"]),
        str(world.ledger.path), str(path), str(ROOT / "tools/hierarchy_lifecycle.py"),
        "--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store),
        "route", "--actor", "router-1", "--evidence-only", "--wait", "0.1"],
        env=os.environ.copy(), capture_output=True, text=True, timeout=30)
    assert p.returncode == 0 and p.stderr == "", p.stdout + p.stderr
    result = json.loads(p.stdout)
    if prior:
        assert len(result["routed"]) == 1 and result["routed"][0]["delivered"] is False
        assert world.inbox("engine") == original
        before = world.ledger.files()
        assert world.route()["routed"] == [] and world.ledger.files() == before
    else:
        assert result["routed"] == [] and world.inbox("engine") == []
        assert next(r for r in result["requests"] if r["request_id"] == canonical["id"])["reason"] == "small_change_mixed_queue"


def test_formal_result_uses_runner_four_mib_limit_and_captured_bytes(tmp_path):
    (tmp_path / ".keep").write_text("exact public retained-result limit\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    formal_jobs(world, "max-result", expect=0)
    first = world.messages("job_request")[0]["message"]["message_id"]
    result = world.workspace.store / "jobs/engine" / first / "result.json"
    assert result.stat().st_size == 4194304
    receipts = world.messages("job_receipt")
    assert formal_dispatch(world, watch=result, action="deny")["small_changes"][0]["state"] == "reviewing"
    assert world.messages("job_receipt") == receipts
    assert not Path(str(result) + ".opened").exists()
    with result.open("ab") as stream:
        stream.write(b" ")
    row = formal_dispatch(world, watch=result, action="deny")["small_changes"][0]
    assert row["reason"] == "small_change_receipt_invalid"
    assert not Path(str(result) + ".opened").exists()


def test_formal_mixed_queue_allows_recovery_already_mixed_and_preserves_conflict(tmp_path):
    (tmp_path / ".keep").write_text("outer mixed selection recovery precedence\n")
    world = Loop(tmp_path)
    root = world.team("engine")
    value = request("prior-canonical-delivery")
    world.ledger.publish(value)
    world.ledger.approve(value)
    original_id = deliver_without_recording(world, value)
    original = world.inbox("engine")
    assert [r["message"]["message_id"] for r in original] == [original_id]
    change = SmallChange(world.ledger, request("later-small-change"))
    change.register()
    route = world.route()
    assert len(route["routed"]) == 1 and route["routed"][0]["delivered"] is False
    assert world.inbox("engine") == original
    conflict = request("conflicting-prior-delivery")
    world.ledger.publish(conflict)
    world.ledger.approve(conflict)
    sha = raw_request(conflict)["sha256"]
    invoke(root, "publish", {"message_id": "route-" + sha, "from": "engine/router", "to": "engine/orchestrator",
        "host": "host-one", "session": "engine-router", "binding_generation": 1, "type": "info", "body": "conflicting prior bytes"})
    result = world.route()
    assert result["routed"] == []
    row = next(r for r in result["requests"] if r["request_id"] == conflict["id"])
    assert row["reason"] == "route_message_conflict"


@pytest.mark.parametrize("name", ["result.json", "claim.json", "process.json"])
def test_formal_present_null_metadata_is_not_absence(tmp_path, name):
    (tmp_path / ".keep").write_text("unexpected retained metadata refuses\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    (folder / name).write_text("null")
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()["small_changes"][0]
    assert row["reason"] == "small_change_receipt_invalid", row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before



# Snapshot/v1 repair R2. All R1 tests above remain an exact byte prefix.
def snapshot_v1_probe(world, *, command="dispatch", reserved=None, log=None, grow=False):
    """Only OS I/O and the modelled password-database/home boundary are replaced."""
    script = r"""
import builtins, importlib.util, io, json, os, pwd, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_router', sys.argv[1])
router = importlib.util.module_from_spec(spec); spec.loader.exec_module(router)
home, telemetry_path, reserved, watched, grow = sys.argv[2:7]
user = pwd.getpwuid(os.getuid())
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], home, user.pw_shell))
telemetry = {'reserved_opens': [], 'reads': [], 'appends': 0}
raw_open, io_open, fd_open, read = builtins.open, io.open, os.open, os.read
def target(path, kwargs=None):
    if not isinstance(path, (str, bytes, os.PathLike)):
        return None
    value = Path(os.fsdecode(path))
    descriptor = (kwargs or {}).get('dir_fd')
    if not value.is_absolute() and descriptor is not None:
        value = Path(os.readlink('/proc/self/fd/%d' % descriptor)) / value
    return value
def refuse_reserved(path, kwargs=None):
    actual = target(path, kwargs)
    if reserved and actual == Path(reserved):
        telemetry['reserved_opens'].append(str(actual))
        raise OSError('modelled reserved metadata content open attempted')
def opened(path, *args, **kwargs):
    refuse_reserved(path)
    return raw_open(path, *args, **kwargs)
def io_opened(path, *args, **kwargs):
    refuse_reserved(path)
    return io_open(path, *args, **kwargs)
def fd_opened(path, flags, *args, **kwargs):
    refuse_reserved(path, kwargs)
    return fd_open(path, flags, *args, **kwargs)
builtins.open, io.open, os.open = opened, io_opened, fd_opened
def captured_read(descriptor, count):
    actual = Path(os.readlink('/proc/self/fd/%d' % descriptor))
    chunk = read(descriptor, count)
    if watched and actual == Path(watched):
        telemetry['reads'].append({'requested': count, 'returned': len(chunk)})
        if grow == 'yes' and chunk and telemetry['appends'] < 3:
            with raw_open(watched, 'ab') as stream:
                stream.write(b'a' * 65536)
            telemetry['appends'] += 1
    return chunk
os.read = captured_read
try:
    code = router.main(sys.argv[7:])
finally:
    Path(telemetry_path).write_text(json.dumps(telemetry))
sys.exit(code)
"""
    home = world.tmp / "snapshot-home"
    home.mkdir(exist_ok=True)
    telemetry = world.tmp / ("snapshot-" + command + "-telemetry.json")
    args = ["--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store), command,
            "--recipes", str(world.recipes_path), "--wait", "0.1"]
    if command == "dispatch":
        args.append("--evidence-only")
    env = {k: v for k, v in os.environ.items()
           if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    env["HOME"] = str(home)
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROUTER), str(home),
        str(telemetry), str(reserved or ""), str(log or ""), "yes" if grow else "no", *args],
        env=env, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0 and p.stderr == "", p.stdout + p.stderr
    return json.loads(p.stdout), json.loads(telemetry.read_text())


def snapshot_v1_unchanged(world):
    events = world.workspace.store / "events"
    return (world.ledger.files(), mailbox_snapshot(world.root),
            {p.name: p.read_bytes() for p in events.iterdir()})


def test_snapshot_v1_completed_runner_prerequisite_and_pristine_large_log_parity(tmp_path):
    (tmp_path / ".keep").write_text("R2 pristine public v1 prerequisite\n")
    world = DispatchWorld(tmp_path, recipe_changes={"steps": [
        ["$python", "-c", "import sys; sys.stdout.buffer.write(b'x' * 3000017)"]]})
    folder = formal_completed_job(world)
    packet = json.loads((folder / "packet.md").read_bytes())
    assert packet["schema"] == "aegis.hierarchy-job-packet/v1"
    assert not any((folder / name).exists() for name in ("execution.json", "derivation.json", "admitted.json"))
    receipts = world.messages("job_receipt")
    initial = (folder / "step-1.log").stat().st_size
    assert initial == 3000017 and initial > 262144
    result, telemetry = snapshot_v1_probe(world, log=folder / "step-1.log")
    assert result["small_changes"][0]["state"] == "reviewing", result
    assert sum(r["returned"] for r in telemetry["reads"]) == initial
    assert telemetry["appends"] == 0 and telemetry["reserved_opens"] == []
    assert world.messages("job_receipt") == receipts


SNAPSHOT_RESERVED_CASES = [
    ("execution.json", state, form)
    for state in ("live", "unknown", "dead") for form in ("regular", "fifo", "symlink", "directory")
] + [
    (name, "unsupported", form)
    for name in ("derivation.json", "admitted.json") for form in ("regular", "fifo", "symlink", "directory")
]


@pytest.mark.parametrize("name,state,form", SNAPSHOT_RESERVED_CASES,
                         ids=["%s-%s-%s" % case for case in SNAPSHOT_RESERVED_CASES])
def test_snapshot_v1_reserved_metadata_holds_before_content_reads(tmp_path, name, state, form):
    (tmp_path / ".keep").write_text("R2 modelled unsupported retained metadata\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    target = folder / name
    value = json.loads((folder / "claim.json").read_bytes())
    if state in {"live", "unknown"}:
        value["pid"] = os.getpid()
        value["start"] = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19]
        if state == "unknown":
            value["process_scope"] = {"modelled": "unobservable scope"}
    if form == "regular":
        target.write_text(json.dumps(value))
    elif form == "fifo":
        os.mkfifo(target)
    elif form == "directory":
        target.mkdir()
    else:
        private = tmp_path / "snapshot-home/.codex/modelled-reserved-target"
        private.parent.mkdir(parents=True, exist_ok=True)
        private.write_text("modelled private target; no read is permitted")
        target.symlink_to(private)
    retained_inbox = world.inbox("engine")
    assert retained_inbox, "public writer/job progression must leave its original replies"
    before = snapshot_v1_unchanged(world)
    for command in ("status", "dispatch", "status", "dispatch"):
        result, telemetry = snapshot_v1_probe(world, command=command, reserved=target)
        row = result["small_changes"][0]
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
        assert row["detail"] == "unsupported retained v1 metadata: " + name, row
        assert telemetry["reserved_opens"] == [], "reserved metadata reached a content reader"
        assert snapshot_v1_unchanged(world) == before
        assert world.inbox("engine") == retained_inbox


@pytest.mark.parametrize("size", [17, 3145747], ids=["small", "large"])
def test_snapshot_v1_growing_log_has_initial_size_io_budget_and_holds(tmp_path, size):
    (tmp_path / ".keep").write_text("R2 finite append stream and public I/O budget\n")
    world = DispatchWorld(tmp_path, recipe_changes={"steps": [
        ["$python", "-c", "import sys; sys.stdout.buffer.write(b'x' * %d)" % size]]})
    folder = formal_completed_job(world)
    log = folder / "step-1.log"
    initial = log.stat().st_size
    assert initial == size
    retained_inbox = world.inbox("engine")
    assert retained_inbox, "public writer/job progression must leave its original replies"
    before = snapshot_v1_unchanged(world)
    for command in ("status", "dispatch"):
        current = log.stat().st_size
        result, telemetry = snapshot_v1_probe(world, command=command, log=log, grow=True)
        row = result["small_changes"][0]
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
        assert row["detail"] == "retained artifact changed while reading: step-1.log", row
        assert telemetry["appends"] >= 1
        consumed = sum(r["returned"] for r in telemetry["reads"])
        assert consumed <= current, "snapshot read exceeded initially observed file size"
        remaining = current
        for read in telemetry["reads"]:
            assert 0 < read["requested"] <= min(1048576, remaining)
            remaining -= read["returned"]
        assert remaining == 0
        assert snapshot_v1_unchanged(world) == before
        assert world.inbox("engine") == retained_inbox


# R3 formal-review repairs: binding validity intervals, successor completion, receipt history and foreign packets.


def r3_rebind(world, lane, *, pending=None, readiness=None):
    """Acknowledged generation-2 handoff through the public mailbox CLI, which refuses a checkpoint omitting open work."""
    endpoint = "engine/lane/" + lane
    note = world.root.parent / ("r3-handoff-" + lane + ".md")
    note.write_text("modelled owner stopped the outgoing lane session\n")
    checkpoint = {"outgoing_stopped": True, "sources": [], "lease_refs": [], "completed_checks": [],
                  "pending_message_ids": [], "last_acknowledgment_ids": [],
                  "briefs": [{"path": str(note), "sha256": hashlib.sha256(note.read_bytes()).hexdigest()}]}
    if pending is not None:
        checkpoint["pending_message_ids"] = [pending["message_id"]]
        checkpoint["briefs"].append(pending["brief"])
    if readiness is not None:
        checkpoint["lease_refs"] = [readiness["lease_ref"]]
        checkpoint["sources"] = [{"worktree": readiness["worktree"], "source_revision": world.revision,
                                  "source_tree": world.tree, "dirty_state": "clean"}]
    binding = invoke(world.root, "bind", {"endpoint": endpoint, "host": "next-host", "session": "next-session",
                                          "expected_generation": 1, "checkpoint": checkpoint})
    invoke(world.root, "ack-handoff", {"endpoint": endpoint, "session": "next-session", "generation": 2,
                                       "checkpoint_sha256": binding["checkpoint_sha256"]})


def r3_identity(lane, generation):
    if generation == 1:
        return {"host": "host-one", "session": "engine/lane/" + lane, "binding_generation": 1}
    return {"host": "next-host", "session": "next-session", "binding_generation": 2}


def r3_dispatch(world, lane):
    identifier = "legacy-" + lane
    brief = world.root.parent / (identifier + ".md")
    brief.write_text("prior owner assignment\n")
    invoke(world.root, "publish", {"message_id": identifier, "from": "engine/orchestrator", "to": "engine/lane/" + lane,
        "host": "host-one", "session": "engine/orchestrator", "binding_generation": 1,
        "type": "dispatch", "body": "previous independent assignment",
        "brief": {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}})
    return next(r["message"] for r in world.messages("dispatch") if r["message"]["message_id"] == identifier)


def r3_reply(world, lane, parent, stage, generation):
    message = {"message_id": parent + "-" + stage, "from": "engine/lane/" + lane, "to": "engine/orchestrator",
               "in_reply_to": parent, **r3_identity(lane, generation)}
    if stage == "accepted":
        message.update(type="ack", acknowledgment="accepted", body="accepted prior assignment")
        if lane != "review0":
            message["readiness"] = {"worktree": str(world.checkout), "branch": "candidate",
                "base_revision": world.revision, "lease_ref": "refs/aegis/lanes/modelled-legacy", "lease_oid": "a" * 40,
                "lease_expires_at": "2099-01-01T00:00:00Z", "owned_paths": ["app.txt"],
                "scan_workspace": str(world.checkout), "scan_evidence": "modelled scan",
                "enforcement_tier": "advisory", "hook_evidence": "modelled hooks"}
    else:
        message.update(type="review" if lane == "review0" else "result",
            body="prior assignment completed; grants no current lifecycle/check evidence",
            result={"source_revision": world.revision, "source_tree": world.tree,
                    "lane_check": "modelled legacy completion", "checks": [
                        {"check": "legacy", "outcome": "fail", "reference": "prior failure retained"}]})
    invoke(world.root, "publish", message)
    return next(r for r in world.messages() if r["message"]["message_id"] == message["message_id"])


@pytest.mark.parametrize("lane", ["fix", "review0"])
@pytest.mark.parametrize("identity", ["superseded", "current"])
def test_r3_superseded_generation_cannot_close_a_later_legacy_assignment(tmp_path, lane, identity):
    (tmp_path / ".keep").write_text("R3 superseded binding generation evidence\n")
    world = DispatchWorld(tmp_path)
    r3_rebind(world, lane)
    parent = r3_dispatch(world, lane)["message_id"]
    replies = [r3_reply(world, lane, parent, stage, 2) for stage in ("accepted", "completed")]
    if identity == "superseded":
        # Generation 1 is a valid historical identity, but it was retired before this dispatch existed.
        for record in replies:
            rewrite_message(record, lambda m: m.update(r3_identity(lane, 1)))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()["small_changes"][0]
    dispatches = [r["message"]["message_id"] for r in world.messages("dispatch")]
    if identity == "superseded":
        assert (row["state"], row.get("reason")) == ("held", "small_change_mixed_queue"), row
        assert row["detail"] == "foreign lane dispatch: " + parent, row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
        assert dispatches == [parent]
    else:
        assert row["state"] == "writer_sent", row
        assert dispatches == [parent, "scw-" + raw_request(world.change.plan)["sha256"]]


@pytest.mark.parametrize("identity", ["superseded", "current"])
def test_r3_superseded_generation_cannot_close_a_sibling_small_change_writer_dispatch(tmp_path, identity):
    (tmp_path / ".keep").write_text("R3 sibling writer dispatch closure evidence\n")
    world = DispatchWorld(tmp_path)
    r3_rebind(world, "fix")
    second = SmallChange(world.ledger, request("engine-second"))
    second.plan["plan"]["checks"] = ["check-0"]
    second.register()
    second.decide()
    admission = second.admission()
    admission["checks"] = [{"check": "check-0", "recipe": "focused", "recipes_sha256": world.recipe_hash,
                            "evidence": world.ledger.evidence}]
    second.admit(admission)
    first, later = world.change.value["id"], second.value["id"]
    sibling = "scw-" + raw_request(world.change.plan)["sha256"]
    occupied = ("held", "small_change_configuration", "writer lane already has an open dispatch")
    rows = {r["request_id"]: r for r in world.dispatch()["small_changes"]}
    assert (rows[later]["state"], rows[later].get("reason"), rows[later].get("detail")) == occupied, rows
    assert [r["message"]["message_id"] for r in world.messages("dispatch")] == [sibling]
    replies = [r3_reply(world, "fix", sibling, stage, 2) for stage in ("accepted", "completed")]
    if identity == "superseded":
        # The sibling is the dispatcher's own scw, so only the open-dispatch guard sees this forged closure.
        for record in replies:
            rewrite_message(record, lambda m: m.update(r3_identity("fix", 1)))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    rows = {r["request_id"]: r for r in world.dispatch()["small_changes"]}
    dispatches = [r["message"]["message_id"] for r in world.messages("dispatch")]
    if identity == "superseded":
        assert (rows[first]["state"], rows[first].get("reason")) == ("held", "small_change_binding_changed"), rows
        assert (rows[later]["state"], rows[later].get("reason"), rows[later].get("detail")) == occupied, rows
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
        assert dispatches == [sibling]
    else:
        assert (rows[first]["state"], rows[first].get("reason")) == ("held", "small_change_check_failed"), rows
        assert rows[later]["state"] == "writer_sent", rows
        assert dispatches == [sibling, "scw-" + raw_request(second.plan)["sha256"]]


@pytest.mark.parametrize("lane", ["fix", "review0"])
def test_r3_successor_completion_after_acknowledged_handoff_permits_later_small_change(tmp_path, lane):
    (tmp_path / ".keep").write_text("R3 acknowledged successor completion evidence\n")
    world = DispatchWorld(tmp_path)
    dispatch = r3_dispatch(world, lane)
    parent = dispatch["message_id"]
    accepted = r3_reply(world, lane, parent, "accepted", 1)["message"]
    r3_rebind(world, lane, pending=dispatch, readiness=accepted.get("readiness"))
    r3_reply(world, lane, parent, "completed", 2)
    old = request("legacy-canonical")
    world.ledger.ready(old)
    world.ledger.intent(old)
    world.ledger.event("start", actor=world.ledger.operator, intent_id="attempt-1", **world.ledger.target(old))
    world.ledger.terminal(old)
    world.ledger.accepted_delivery(old)
    world.ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": world.ledger.evidence},
                       **world.ledger.target(old))
    row = world.dispatch()["small_changes"][0]
    assert row["state"] == "writer_sent", row
    assert world.change.row()["terminal"] is None and world.change.row()["review"] is None
    assert world.messages("job_request") == []
    assert [r["message"]["message_id"] for r in world.messages("dispatch")] == [
        parent, "scw-" + raw_request(world.change.plan)["sha256"]]


@pytest.mark.parametrize("outcome,reason", [("failed", "small_change_check_failed"),
                                            ("refused", "small_change_check_failed"),
                                            ("completed", "small_change_receipt_invalid")])
def test_r3_nonterminal_receipt_after_terminal_never_resumes_partial_batch(tmp_path, outcome, reason):
    (tmp_path / ".keep").write_text("R3 inconsistent receipt history evidence\n")
    changes = {"steps": [["$python", "-c", "raise SystemExit(7)"]]} if outcome == "failed" else None
    world = DispatchWorld(tmp_path, checks=2, recipe_changes=changes)
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    requests = world.messages("job_request")
    assert len(requests) == 1
    first = requests[0]["message"]["message_id"]
    app = world.checkout / "app.txt"
    original = app.read_bytes()
    if outcome == "refused":
        app.write_text("modelled dirty checkout during runner admission")
    assert world.run_jobs()["rows"][0]["state"] == outcome
    app.write_bytes(original)
    terminal = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == outcome)
    later = Path(terminal["path"]).with_name("r3-later-started.md")
    later.write_bytes(Path(terminal["path"]).read_bytes())
    stamp = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    rewrite_message({"path": str(later)}, lambda m: m.update(message_id="r3-later-started", created_at=stamp,
                                                             receipt={"state": "started"}))
    (world.workspace.store / "jobs/engine" / first / "result.json").unlink()
    for command in ("status", "dispatch", "status", "dispatch"):
        row = world.dispatch(command=command)["small_changes"][0]
        assert (row["state"], row.get("reason")) == ("held", reason), row
        assert world.messages("job_request") == requests
        assert len(world.messages("dispatch")) == 1


R3_LOOP_PASS = r"""
import argparse, importlib.util, os, pwd, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_loop', sys.argv[1])
loop = importlib.util.module_from_spec(spec); spec.loader.exec_module(loop)
loop.TOOLS['sweep'] = Path(sys.argv[2])
user = pwd.getpwuid(os.getuid())
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], sys.argv[3], user.pw_shell))
journal, store, recipes, state_dir = map(Path, sys.argv[4:8])
args = argparse.Namespace(lifecycle=journal, store=store, recipes=recipes, state_dir=state_dir, max_jobs=None,
                          dispatcher_host_plan=state_dir.parent/'dispatcher-host-plan.json')
sys.exit(loop.one_pass(args, None)[0])
"""


@pytest.mark.parametrize("attachment", ["[]", "null", "{"], ids=["list", "null", "invalid-json"])
def test_r3_malformed_foreign_job_packet_is_a_row_hold_and_run_open_continues(tmp_path, attachment):
    from tests.integration.test_hierarchy_loop import EMPTY_SWEEP
    (tmp_path / ".keep").write_text("R3 malformed foreign job packet evidence\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    packet = world.root.parent / "r3-foreign-packet.md"
    packet.write_text(attachment)
    invoke(world.root, "publish", {"message_id": "r3-foreign-job", "from": "engine/orchestrator", "to": "engine/root",
        "host": "host-one", "session": "engine/orchestrator", "binding_generation": 1, "type": "job_request",
        "body": "foreign job whose packet is not an object",
        "brief": {"path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}})
    docs = world.team("docs")
    world.workspace.run("update", {"initiative": "docs", "source": "owner", "checkouts": [str(world.checkout)]})
    canonical = tmp_path / "docs/canonical.md"
    canonical.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "focused",
        "checkout": str(world.checkout), "commit": world.revision, "tree": world.tree}))
    invoke(docs, "publish", {"message_id": "canonical-check", "from": "docs/orchestrator", "to": "docs/root",
        "host": "host-one", "session": "docs-orchestrator", "binding_generation": 1,
        "type": "job_request", "body": "owner canonical check", "brief": {
            "path": str(canonical), "sha256": hashlib.sha256(canonical.read_bytes()).hexdigest()}})
    # Only the wake step is modelled, so no host can start; router, dispatcher projection and runner are real.
    sweep = tmp_path / "r3-sweep.py"
    sweep.write_text("import json\nprint(json.dumps(%r))\n" % (EMPTY_SWEEP,))
    state = tmp_path / "r3-loop-state"
    state.mkdir()
    process = subprocess.run([sys.executable, "-I", "-B", "-c", R3_LOOP_PASS, str(ROOT / "tools/hierarchy_loop.py"),
        str(sweep), str(tmp_path / "home"), str(world.ledger.path), str(world.workspace.store),
        str(world.recipes_path), str(state)], env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert process.returncode == 3 and process.stderr == "", process.stdout + process.stderr
    report = json.loads(process.stdout.splitlines()[-1])
    detail = "malformed foreign job packet: r3-foreign-job"
    steps = {r["step"]: r for r in report["steps"]}
    assert (steps["sweep"]["state"], steps["run_open"]["state"]) == ("ok", "ok"), report
    assert {"job": "docs/canonical-check", "state": "completed"} in steps["run_open"]["rows"], report
    assert any((h["step"], h["kind"], h.get("request_id"), h["detail"]) ==
               ("dispatch", "small_change_mixed_queue", world.change.value["id"], detail) for h in report["holds"]), report
    row = world.projection()
    assert (row["state"], row["reason"], row["detail"]) == ("held", "small_change_mixed_queue", detail), row
    assert [r["message"]["message_id"] for r in world.messages("job_request")] == ["r3-foreign-job"]


# R4: owned-assignment fences, bounded snapshot descriptors and provision-object validation.
def r4_rotate_endpoint(world, endpoint):
    note = world.root.parent / "r4-outgoing-stopped.md"
    note.write_text("modelled owner stopped the outgoing endpoint\n")
    checkpoint = {"outgoing_stopped": True, "sources": [], "lease_refs": [], "completed_checks": [],
                  "pending_message_ids": [], "last_acknowledgment_ids": [], "briefs": [
                      {"path": str(note), "sha256": hashlib.sha256(note.read_bytes()).hexdigest()}]}
    binding = invoke(world.root, "bind", {"endpoint": endpoint, "host": "r4-successor",
        "session": "r4-successor-session", "expected_generation": 1, "checkpoint": checkpoint})
    invoke(world.root, "ack-handoff", {"endpoint": endpoint, "session": "r4-successor-session",
        "generation": 2, "checkpoint_sha256": binding["checkpoint_sha256"]})


@pytest.mark.parametrize("lane", ["fix", "review0"])
@pytest.mark.parametrize("case", ["completion-after-handoff", "acceptance-after-handoff",
    "dispatch-sender-after-handoff", "acceptance-before-dispatch", "completion-before-acceptance",
    "valid-before-handoff"])
def test_r4_owned_assignment_uses_binding_intervals_and_chronology(tmp_path, lane, case):
    (tmp_path / ".keep").write_text("R4 owned assignment interval and ordering evidence\n")
    world = DispatchWorld(tmp_path)
    if lane == "fix":
        world.dispatch()
        world.finish_writer()
    else:
        reviewer = ready_reviewer(world)
        review_result(world, reviewer)
    dispatch = next(r for r in world.messages("dispatch") if r["message"]["to"] == "engine/lane/" + lane)
    parent = dispatch["message"]["message_id"]
    replies = [r for r in world.messages() if r["message"].get("in_reply_to") == parent]
    acceptance = next(r for r in replies if r["message"].get("acknowledgment") == "accepted")
    completion = next(r for r in replies if r["message"]["type"] in {"result", "review"})
    if case in {"completion-after-handoff", "acceptance-after-handoff", "valid-before-handoff"}:
        r3_rebind(world, lane)
        after = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        if case != "valid-before-handoff":
            record = completion if case == "completion-after-handoff" else acceptance
            rewrite_message(record, lambda m: m.update(created_at=after))
    elif case == "dispatch-sender-after-handoff":
        r4_rotate_endpoint(world, "engine/orchestrator")
        after = datetime.now(timezone.utc)
        for index, record in enumerate([dispatch, acceptance, completion]):
            stamp = (after + timedelta(microseconds=index)).isoformat(timespec="microseconds").replace("+00:00", "Z")
            rewrite_message(record, lambda m, stamp=stamp: m.update(created_at=stamp))
    else:
        origin = datetime.fromisoformat(dispatch["message"]["created_at"].replace("Z", "+00:00"))
        stamp = (origin + timedelta(microseconds=-1 if case == "acceptance-before-dispatch" else 1))
        stamp = stamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
        rewrite_message(acceptance if case == "acceptance-before-dispatch" else completion,
                        lambda m: m.update(created_at=stamp))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    if case == "valid-before-handoff":
        row = world.dispatch()["small_changes"][0]
        assert row["state"] == ("checking" if lane == "fix" else "held"), row
        if lane == "fix":
            assert len(world.messages("job_request")) == 1
        else:
            assert row["reason"] == "small_change_close_due"
    else:
        reason = ("small_change_result_invalid" if case in {
            "acceptance-before-dispatch", "completion-before-acceptance"} else "small_change_binding_changed")
        for command in ("status", "dispatch"):
            row = world.dispatch(command=command)["small_changes"][0]
            assert (row["state"], row.get("reason")) == ("held", reason), row
            assert row["drafts"] == [] or all(
                d["event"].get("status") != "FINAL" for d in row["drafts"]), row
            assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def r4_limited_dispatch(world, *, checks, tamper=None):
    script = r"""
import importlib.util, json, os, pwd, resource, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_router', sys.argv[1])
router = importlib.util.module_from_spec(spec); spec.loader.exec_module(router)
home, limit, first, last, tamper = sys.argv[2:7]
user = pwd.getpwuid(os.getuid())
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], home, user.pw_shell))
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (int(limit), hard))
listed = os.scandir
changed = False
def scandir(directory):
    entries = listed(directory)
    actual = Path(os.readlink('/proc/self/fd/%d' % directory)) if type(directory) is int else Path(directory)
    class Scan:
        def __enter__(self):
            entries.__enter__()
            return self
        def __exit__(self, *args):
            return entries.__exit__(*args)
        def __iter__(self):
            return self
        def __next__(self):
            global changed
            try:
                return next(entries)
            except StopIteration:
                if tamper and not changed and actual == Path(last):
                    changed = True
                    target = Path(first)
                    if tamper == 'file':
                        with (target / 'step-1.log').open('ab') as stream: stream.write(b'changed after capture')
                    else:
                        target.rename(target.with_name(target.name + '.retained'))
                        target.mkdir()
                raise
    return Scan()
os.scandir = scandir
sys.exit(router.main(sys.argv[7:]))
"""
    requests = sorted(world.messages("job_request"), key=lambda r: json.loads(r["message"]["body"])["check"])
    assert len(requests) == checks
    folders = [world.workspace.store / "jobs/engine" / r["message"]["message_id"] for r in requests]
    limit = 128 if tamper else 64
    env = {k: v for k, v in os.environ.items()
           if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROUTER), str(world.tmp / "home"),
        str(limit), str(folders[0]), str(folders[-1]), tamper or "",
        "--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store),
        "dispatch", "--recipes", str(world.recipes_path), "--wait", "0.1", "--evidence-only"],
        env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and p.stderr == "", p.stdout + p.stderr
    (world.tmp / "r4-limited-result.json").write_text(p.stdout)
    return json.loads(p.stdout)["small_changes"][0]


def test_r4_valid_check_batch_progresses_under_low_descriptor_limit(tmp_path):
    (tmp_path / ".keep").write_text("R4 real retained jobs under RLIMIT_NOFILE64\n")
    world = DispatchWorld(tmp_path, checks=16)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    assert len(world.run_jobs()["rows"]) == 16
    receipts = world.messages("job_receipt")
    row = r4_limited_dispatch(world, checks=16)
    assert row["state"] == "reviewing", row
    assert len(world.messages("dispatch")) == 2
    assert world.messages("job_receipt") == receipts


@pytest.mark.parametrize("tamper", ["file", "directory"])
def test_r4_bounded_descriptors_keep_publication_time_snapshot_checks(tmp_path, tamper):
    (tmp_path / ".keep").write_text("R4 identity revalidation after earlier job capture\n")
    world = DispatchWorld(tmp_path, checks=2)
    world.dispatch()
    world.finish_writer()
    world.dispatch()
    assert len(world.run_jobs()["rows"]) == 2
    before = world.ledger.files(), mailbox_snapshot(world.root)
    messages = world.messages()
    row = r4_limited_dispatch(world, checks=2, tamper=tamper)
    assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
    after = mailbox_snapshot(world.root)
    assert world.ledger.files() == before[0] and world.messages() == messages
    assert all(after.get(name) == value for name, value in before[1].items())
    # Existing publication staging may leave an inert content-addressed brief before revalidation refuses.
    for name in after.keys() - before[1].keys():
        assert name.startswith("briefs/") and hashlib.sha256(after[name][0]).hexdigest() in name


@pytest.mark.parametrize("provision", [[], "not-an-object"], ids=["list", "string"])
def test_r4_nonobject_provision_is_a_row_hold_and_canonical_job_runs(tmp_path, provision):
    from tests.integration.test_hierarchy_loop import EMPTY_SWEEP
    (tmp_path / ".keep").write_text("R4 malformed provision and independent canonical job\n")
    world = DispatchWorld(tmp_path)
    (world.root.parent / "provision.json").write_text(json.dumps(provision))
    docs = world.team("docs")
    world.workspace.run("update", {"initiative": "docs", "source": "owner", "checkouts": [str(world.checkout)]})
    packet = tmp_path / "docs/r4-canonical.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "focused",
        "checkout": str(world.checkout), "commit": world.revision, "tree": world.tree}))
    invoke(docs, "publish", {"message_id": "r4-canonical-check", "from": "docs/orchestrator", "to": "docs/root",
        "host": "host-one", "session": "docs-orchestrator", "binding_generation": 1,
        "type": "job_request", "body": "independent canonical check", "brief": {
            "path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}})
    sweep = tmp_path / "r4-sweep.py"
    sweep.write_text("import json\nprint(json.dumps(%r))\n" % (EMPTY_SWEEP,))
    state = tmp_path / "r4-loop-state"
    state.mkdir()
    p = subprocess.run([sys.executable, "-I", "-B", "-c", R3_LOOP_PASS, str(ROOT / "tools/hierarchy_loop.py"),
        str(sweep), str(tmp_path / "home"), str(world.ledger.path), str(world.workspace.store),
        str(world.recipes_path), str(state)], env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert p.returncode == 3 and p.stderr == "", p.stdout + p.stderr
    report = json.loads(p.stdout.splitlines()[-1])
    steps = {r["step"]: r for r in report["steps"]}
    assert steps["run_open"]["state"] == "ok"
    assert {"job": "docs/r4-canonical-check", "state": "completed"} in steps["run_open"]["rows"], report
    assert any(h["kind"] == "small_change_configuration" and h.get("request_id") == world.change.value["id"]
               and h["detail"] == "provision record must be an object" for h in report["holds"]), report
    assert world.messages("dispatch") == []


# R5: validate recovery and receipt authority before effect, and bind review to completed checks.
def r5_rotate(world, endpoint, *, acknowledge=True):
    draft = invoke(world.root, "draft-handoff", {"endpoint": endpoint, "host": "r5-host",
        "session": "r5-session", "outgoing_stopped": True})
    binding = invoke(world.root, "bind", draft)
    if acknowledge:
        invoke(world.root, "ack-handoff", {"endpoint": endpoint, "generation": binding["generation"],
            "session": binding["session"], "checkpoint_sha256": binding["checkpoint_sha256"]})
    return binding


@pytest.mark.parametrize("stale", [False, True], ids=["valid-before-rotation", "retired-after-rotation"])
def test_r5_recovery_fences_original_dispatch_before_recording_route(tmp_path, stale):
    (tmp_path / ".keep").write_text("R5 recovered dispatch authority and durable writer exclusion\n")
    world = DispatchWorld(tmp_path)
    world.dispatch(fault="route")
    original = world.messages("dispatch")[0]
    r5_rotate(world, "engine/orchestrator")
    if stale:
        after = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        rewrite_message(original, lambda m: m.update(created_at=after))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    result = world.dispatch()
    row = result["small_changes"][0]
    if stale:
        assert world.ledger.files() == before[0], "invalid recovered dispatch must not acquire a lifecycle route"
        assert "route_receipt" not in row
        assert "engine/lane/fix" in result["planning_exclusions"]
        assert row["state"] == "held"
        assert mailbox_snapshot(world.root) == before[1]
        again = world.dispatch()
        assert "engine/lane/fix" in again["planning_exclusions"] and world.ledger.files() == before[0]
    else:
        assert row["state"] == "writer_sent" and row["route_receipt"]
        assert "engine/lane/fix" not in result["planning_exclusions"]
    assert len(world.messages("dispatch")) == 1


@pytest.mark.parametrize("case", ["retired", "unacknowledged", "before-request", "valid-before-rotation"])
def test_r5_check_receipts_require_in_force_sender_and_request_chronology(tmp_path, case):
    (tmp_path / ".keep").write_text("R5 check receipt binding and request chronology\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    assert (folder / "result.json").is_file()
    receipts = world.messages("job_receipt")
    completed = next(r for r in receipts if r["message"]["receipt"]["state"] == "completed")
    request_message = world.messages("job_request")[0]["message"]
    if case in {"retired", "unacknowledged", "valid-before-rotation"}:
        binding = r5_rotate(world, "engine/root", acknowledge=case != "unacknowledged")
        stamp = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        if case == "retired":
            rewrite_message(completed, lambda m: m.update(created_at=stamp))
        elif case == "unacknowledged":
            rewrite_message(completed, lambda m: m.update(created_at=stamp, host=binding["host"],
                session=binding["session"], binding_generation=binding["generation"]))
    else:
        origin = datetime.fromisoformat(request_message["created_at"].replace("Z", "+00:00"))
        for index, record in enumerate(sorted(receipts, key=lambda r: r["message"]["created_at"])):
            stamp = (origin - timedelta(microseconds=len(receipts) - index)).isoformat(
                timespec="microseconds").replace("+00:00", "Z")
            rewrite_message(record, lambda m, stamp=stamp: m.update(created_at=stamp))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()["small_changes"][0]
    if case == "valid-before-rotation":
        assert row["state"] == "reviewing", row
    else:
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
        assert world.ledger.files() == before[0]
        assert mailbox_snapshot(world.root) == before[1]
        assert len(world.messages("dispatch")) == 1


@pytest.mark.parametrize("damage", ["early", "missing-proofs", "wrong-source-proof"])
def test_r5_reviewer_assignment_is_bound_to_completed_check_proofs(tmp_path, damage):
    (tmp_path / ".keep").write_text("R5 immutable Reviewer assignment evidence and chronology\n")
    world = DispatchWorld(tmp_path)
    reviewer = ready_reviewer(world)
    review_result(world, reviewer)
    record = next(r for r in world.messages("dispatch") if r["message"]["message_id"] == reviewer["message_id"])
    if damage == "early":
        writer = next(r["message"] for r in world.messages("result"))
        start = datetime.fromisoformat(writer["created_at"].replace("Z", "+00:00"))
        replies = [r for r in world.messages() if r["message"].get("in_reply_to") == reviewer["message_id"]]
        acceptance = next(r for r in replies if r["message"].get("acknowledgment") == "accepted")
        completion = next(r for r in replies if r["message"]["type"] == "review")
        for index, current in enumerate([record, acceptance, completion]):
            stamp = (start + timedelta(microseconds=index + 1)).isoformat(timespec="microseconds").replace("+00:00", "Z")
            rewrite_message(current, lambda m, stamp=stamp: m.update(created_at=stamp))
    else:
        raw = Path(reviewer["brief"]["path"]).read_text()
        lines = raw.splitlines()
        matches = 0
        for index, line in enumerate(lines):
            if not line.startswith("- "):
                continue
            item = json.loads(line[2:])
            if item.get("kind") == "small_change_assignment":
                matches += 1
                if damage == "missing-proofs":
                    item["evidence"] = []
                else:
                    wrong = tmp_path / "wrong-writer-source.json"
                    wrong.write_text(json.dumps({"source_revision": "e" * 40, "source_tree": "f" * 40}))
                    item["evidence"][0] = {"path": str(wrong), "sha256": hashlib.sha256(wrong.read_bytes()).hexdigest()}
                lines[index] = "- " + json.dumps(item, sort_keys=True)
        assert matches == 1
        raw = ("\n".join(lines) + "\n").encode()
        sha = hashlib.sha256(raw).hexdigest()
        path = world.root.parent / "briefs" / ("fresh-" + sha + ".md")
        path.write_bytes(raw)
        rewrite_message(record, lambda m: m.update(brief={"path": str(path), "sha256": sha}))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ("status", "dispatch"):
        row = world.dispatch(command=command)["small_changes"][0]
        assert (row["state"], row.get("reason")) == ("held", "small_change_message_conflict"), row
        assert not any(d["event"].get("status") == "FINAL" for d in row["drafts"]), row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r5_terminal_evidence_open_race_never_blocks_independent_run_open(tmp_path):
    from tests.integration.test_hierarchy_loop import EMPTY_SWEEP
    (tmp_path / ".keep").write_text("R5 terminal evidence regular-to-FIFO race, modelled OS boundary\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    target = tmp_path / "terminal-evidence"
    target.write_bytes(b"valid terminal evidence")
    world.finish_writer(evidence=[{"path": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}])
    docs = world.team("docs")
    world.workspace.run("update", {"initiative": "docs", "source": "owner", "checkouts": [str(world.checkout)]})
    packet = tmp_path / "docs/r5-canonical.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "focused",
        "checkout": str(world.checkout), "commit": world.revision, "tree": world.tree}))
    invoke(docs, "publish", {"message_id": "r5-canonical-check", "from": "docs/orchestrator", "to": "docs/root",
        "host": "host-one", "session": "docs-orchestrator", "binding_generation": 1,
        "type": "job_request", "body": "independent canonical check", "brief": {
            "path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}})
    sweep = tmp_path / "r5-sweep.py"
    sweep.write_text("import json\nprint(json.dumps(%r))\n" % (EMPTY_SWEEP,))
    telemetry = tmp_path / "r5-evidence-io.json"
    injection = r"""
import io, stat
target, telemetry = Path(sys.argv[8]), Path(sys.argv[9])
observed = {'injected': False, 'unsafe_open': False}
old_stat, old_io_open, old_fd_open = os.stat, io.open, os.open
def actual(path, kwargs):
    if not isinstance(path, (str, bytes, os.PathLike)): return None
    value = Path(os.fsdecode(path))
    if not value.is_absolute() and kwargs.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%d' % kwargs['dir_fd'])) / value
    return value
def inspected(path, *args, **kwargs):
    info = old_stat(path, *args, **kwargs)
    if (not observed['injected'] and actual(path, kwargs) == target and stat.S_ISREG(info.st_mode)
            and (kwargs.get('follow_symlinks', True) or kwargs.get('dir_fd') is not None)):
        observed['injected'] = True
        target.rename(target.with_name(target.name + '.original'))
        os.mkfifo(target)
    return info
def opened(path, *args, **kwargs):
    if actual(path, kwargs) == target and observed['injected']:
        observed['unsafe_open'] = True
        raise OSError('modelled blocking evidence open intercepted before a real hang')
    return old_io_open(path, *args, **kwargs)
def descriptor(path, flags, *args, **kwargs):
    if actual(path, kwargs) == target and observed['injected'] and not flags & os.O_NONBLOCK:
        observed['unsafe_open'] = True
        raise OSError('modelled descriptor open lacks nonblocking flag')
    return old_fd_open(path, flags, *args, **kwargs)
os.stat, io.open, os.open = inspected, opened, descriptor
"""
    script = R3_LOOP_PASS.replace("journal, store, recipes, state_dir", injection + "\njournal, store, recipes, state_dir")
    script = script.replace("sys.exit(loop.one_pass(args, None)[0])", """
try:
    code = loop.one_pass(args, None)[0]
finally:
    telemetry.write_text(json.dumps(observed))
sys.exit(code)
""").replace("import argparse, importlib.util, os, pwd, sys", "import argparse, importlib.util, json, os, pwd, sys")
    state = tmp_path / "r5-loop-state"
    state.mkdir()
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools/hierarchy_loop.py"),
        str(sweep), str(tmp_path / "home"), str(world.ledger.path), str(world.workspace.store),
        str(world.recipes_path), str(state), str(target), str(telemetry)],
        env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert p.returncode == 3 and p.stderr == "", p.stdout + p.stderr
    observed = json.loads(telemetry.read_text())
    assert observed["injected"]
    assert not observed["unsafe_open"], "terminal evidence reached a blocking open after its regular-file check"
    report = json.loads(p.stdout.splitlines()[-1])
    steps = {r["step"]: r for r in report["steps"]}
    assert steps["run_open"]["state"] == "ok"
    assert {"job": "docs/r5-canonical-check", "state": "completed"} in steps["run_open"]["rows"], report


def r5b_reader_probe(world, target, *, entry="file_ref", action="steady"):
    script = r"""
import importlib.util, io, json, os, stat, sys
from pathlib import Path
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location('hierarchy_fresh_brief', sys.argv[1])
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
target, entry, action, root, lifecycle = Path(sys.argv[2]), *sys.argv[3:7]
seen = {'unsafe_open': False, 'injected': False, 'bytes': 0, 'appends': 0}
original_stat, original_open, original_fd, original_read = os.stat, io.open, os.open, os.read
def actual(path, kwargs):
    if not isinstance(path, (str, bytes, os.PathLike)): return None
    path = Path(os.fsdecode(path))
    if not path.is_absolute() and kwargs.get('dir_fd') is not None:
        path = Path(os.readlink('/proc/self/fd/%d' % kwargs['dir_fd'])) / path
    return path
def changed(path, *args, **kwargs):
    info = original_stat(path, *args, **kwargs)
    if (action in {'fifo', 'swap-regular'} and not seen['injected'] and actual(path, kwargs) == target
            and stat.S_ISREG(info.st_mode)
            and (kwargs.get('follow_symlinks', True) or kwargs.get('dir_fd') is not None)):
        seen['injected'] = True
        target.rename(target.with_name(target.name + '.original'))
        if action == 'fifo': os.mkfifo(target)
        else:
            with original_open(target, 'wb') as out: out.write(b'stable reference')
    return info
def observe(chunk):
    seen['bytes'] += len(chunk)
    if action == 'grow' and chunk and seen['appends'] < 3:
        with original_open(target, 'ab') as out: out.write(b'a' * 65536)
        seen['appends'] += 1
    return chunk
class Reader:
    def __init__(self, stream): self.stream = stream
    def __enter__(self): self.stream.__enter__(); return self
    def __exit__(self, *args): return self.stream.__exit__(*args)
    def read(self, *args): return observe(self.stream.read(*args))
    def __getattr__(self, name): return getattr(self.stream, name)
def opened(path, *args, **kwargs):
    if actual(path, kwargs) == target:
        if action == 'fifo' and seen['injected']:
            seen['unsafe_open'] = True
            raise OSError('modelled blocking reference open intercepted')
        return Reader(original_open(path, *args, **kwargs))
    return original_open(path, *args, **kwargs)
def descriptor(path, flags, *args, **kwargs):
    if actual(path, kwargs) == target and not flags & os.O_NONBLOCK:
        seen['unsafe_open'] = True
        raise OSError('reference descriptor is not nonblocking')
    return original_fd(path, flags, *args, **kwargs)
def read(fd, size):
    chunk = original_read(fd, size)
    return observe(chunk) if Path(os.readlink('/proc/self/fd/%d' % fd)) == target else chunk
os.stat, io.open, os.open, os.read = changed, opened, descriptor, read
try:
    if entry == 'file_ref':
        result = fresh.file_ref(target)
    else:
        raw, result = fresh.prepare(SimpleNamespace(root=root, initiative='engine', endpoint='engine/lane/review0',
            lifecycle=lifecycle, delivery_dir=None, as_of=None, target_generation=1))
    answer = {'state': 'ok', 'result': result}
except (ValueError, OSError) as exc:
    answer = {'state': 'refused', 'error': str(exc)}
print(json.dumps({**answer, 'observed': seen}))
"""
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script,
        str(ROOT / "tools/hierarchy_fresh_brief.py"), str(target), entry, action, str(world.root),
        str(world.ledger.path)], env=os.environ.copy(), capture_output=True, text=True, timeout=30)
    assert p.returncode == 0 and p.stderr == "", p.stdout + p.stderr
    return json.loads(p.stdout)


@pytest.mark.parametrize("entry", ["file_ref", "prepare"])
def test_r5b_shared_reader_race_is_nonblocking_for_direct_and_composition_paths(tmp_path, entry):
    (tmp_path / ".keep").write_text("R5b shared reader FIFO substitution without a real blocking open\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    target = tmp_path / "shared-terminal-evidence"
    target.write_bytes(b"stable reference")
    world.finish_writer(evidence=[{"path": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}])
    answer = r5b_reader_probe(world, target, entry=entry, action="fifo")
    assert answer["observed"]["injected"]
    assert not answer["observed"]["unsafe_open"], answer
    if entry == "file_ref":
        assert answer["state"] == "refused", answer


def test_r5b_shared_reader_stops_at_initial_size_and_refuses_growth(tmp_path):
    (tmp_path / ".keep").write_text("R5b finite initial-size reference budget\n")
    world = DispatchWorld(tmp_path)
    target = tmp_path / "growing-reference"
    target.write_bytes(b"x" * 65553)
    initial = target.stat().st_size
    answer = r5b_reader_probe(world, target, action="grow")
    assert answer["observed"]["appends"] > 0
    assert answer["observed"]["bytes"] <= initial, answer
    assert answer["state"] == "refused", answer


def test_r5b_shared_reader_rejects_replacement_inode_even_with_identical_bytes(tmp_path):
    (tmp_path / ".keep").write_text("R5b reference identity changes at open\n")
    world = DispatchWorld(tmp_path)
    target = tmp_path / "replaced-reference"
    target.write_bytes(b"stable reference")
    answer = r5b_reader_probe(world, target, action="swap-regular")
    assert answer["observed"]["injected"]
    assert answer["state"] == "refused", answer


def test_r5b_shared_reader_preserves_large_regular_evidence(tmp_path):
    (tmp_path / ".keep").write_text("R5b large evidence remains supported\n")
    world = DispatchWorld(tmp_path)
    target = tmp_path / "large-reference"
    data = b"x" * 3000017
    target.write_bytes(data)
    answer = r5b_reader_probe(world, target)
    assert answer["state"] == "ok", answer
    assert answer["result"] == {"path": str(target), "sha256": hashlib.sha256(data).hexdigest()}
    assert answer["observed"]["bytes"] == len(data)


# R6: retained attachments, contradictory completed steps, and portable bounded readers.
R6_ATTACHMENT_IO = r"""
import io, stat
target, telemetry = Path(sys.argv[8]), Path(sys.argv[9])
seen = {'injected': False, 'unsafe_open': False}
old_stat, old_io, old_fd = os.stat, io.open, os.open
def actual(path, kwargs):
    if not isinstance(path, (str, bytes, os.PathLike)): return None
    value = Path(os.fsdecode(path))
    if not value.is_absolute() and kwargs.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%d' % kwargs['dir_fd'])) / value
    return value
def inspected(path, *args, **kwargs):
    info = old_stat(path, *args, **kwargs)
    if (not seen['injected'] and actual(path, kwargs) == target and stat.S_ISREG(info.st_mode)
            and (kwargs.get('follow_symlinks', True) or kwargs.get('dir_fd') is not None)):
        seen['injected'] = True
        target.rename(target.with_name(target.name + '.original'))
        os.mkfifo(target)
    return info
def opened(path, *args, **kwargs):
    if actual(path, kwargs) == target and seen['injected']:
        seen['unsafe_open'] = True
        raise OSError('modelled blocking attachment open intercepted')
    return old_io(path, *args, **kwargs)
def descriptor(path, flags, *args, **kwargs):
    if actual(path, kwargs) == target and seen['injected'] and not flags & os.O_NONBLOCK:
        seen['unsafe_open'] = True
        raise OSError('modelled attachment open lacks nonblocking flag')
    return old_fd(path, flags, *args, **kwargs)
os.stat, io.open, os.open = inspected, opened, descriptor
"""


def r6_attachment_probe(world, target, *, loop=False):
    from tests.integration.test_hierarchy_loop import EMPTY_SWEEP
    sweep = world.tmp / "r6-sweep.py"
    sweep.write_text("import json\nprint(json.dumps(%r))\n" % (EMPTY_SWEEP,))
    state = world.tmp / "r6-loop-state"
    state.mkdir()
    telemetry = world.tmp / "r6-attachment-io.json"
    if loop:
        script = R3_LOOP_PASS.replace("journal, store, recipes, state_dir",
                                     R6_ATTACHMENT_IO + "\njournal, store, recipes, state_dir")
        script = script.replace("sys.exit(loop.one_pass(args, None)[0])", """
try:
    code = loop.one_pass(args, None)[0]
finally:
    telemetry.write_text(json.dumps(seen))
sys.exit(code)
""").replace("import argparse, importlib.util, os, pwd, sys",
              "import argparse, importlib.util, json, os, pwd, sys")
        tool = ROOT / "tools/hierarchy_loop.py"
    else:
        script = """import json, os, pwd, runpy, sys
from pathlib import Path
from types import SimpleNamespace
argv = sys.argv[:]
home = argv[3]
pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=home)
""" + R6_ATTACHMENT_IO + """
sys.argv = [argv[1], '--lifecycle', argv[4], '--store', argv[5], 'dispatch',
            '--recipes', argv[6], '--wait', '0.1', '--evidence-only']
try:
    runpy.run_path(argv[1], run_name='__main__')
finally:
    telemetry.write_text(json.dumps(seen))
"""
        tool = ROUTER
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(tool), str(sweep),
        str(world.tmp / "home"), str(world.ledger.path), str(world.workspace.store), str(world.recipes_path),
        str(state), str(target), str(telemetry)], env=os.environ.copy(), capture_output=True, text=True, timeout=60)
    assert p.returncode == (3 if loop else 0) and p.stderr == "", p.stdout + p.stderr
    return json.loads(p.stdout.splitlines()[-1]), json.loads(telemetry.read_text())


@pytest.mark.parametrize("stage", ["writer", "check", "reviewer", "foreign"])
def test_r6_retained_attachments_never_reach_blocking_open(tmp_path, stage):
    (tmp_path / ".keep").write_text("R6 attachment race, owned files and modelled OS boundary\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    if stage == "writer":
        message = world.messages("dispatch")[0]["message"]
    elif stage == "reviewer":
        world.finish_writer()
        world.dispatch()
        world.run_jobs()
        world.dispatch()
        message = next(r["message"] for r in world.messages("dispatch") if r["message"]["to"].endswith("review0"))
    elif stage == "check":
        world.finish_writer()
        world.dispatch()
        message = world.messages("job_request")[0]["message"]
    else:
        world.finish_writer()
        path = world.root.parent / "foreign-r6.md"
        path.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "focused",
            "checkout": str(world.checkout), "commit": "e" * 40, "tree": "f" * 40}))
        message = invoke(world.root, "publish", {"message_id": "foreign-r6", "from": "engine/orchestrator",
            "to": "engine/root", "host": "host-one", "session": "engine/orchestrator", "binding_generation": 1,
            "type": "job_request", "body": "foreign retained packet", "brief": {
                "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}})
        message = next(r["message"] for r in world.messages("job_request") if r["message"]["message_id"] == "foreign-r6")
    before = world.ledger.files(), mailbox_snapshot(world.root)
    target = Path(message["brief"]["path"])
    answer, seen = r6_attachment_probe(world, target)
    assert seen["injected"]
    assert not seen["unsafe_open"], "retained attachment reached a blocking open"
    assert answer["small_changes"][0]["state"] == "held", answer
    expected = dict(before[1])
    key = target.relative_to(world.root.parent).as_posix()
    expected[key + ".original"] = expected.pop(key)
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == (before[0], expected)


def test_r6_attachment_refusal_does_not_stall_canonical_run_open(tmp_path):
    (tmp_path / ".keep").write_text("R6 attachment race plus independent canonical runner\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    target = Path(world.messages("dispatch")[0]["message"]["brief"]["path"])
    docs = world.team("docs")
    world.workspace.run("update", {"initiative": "docs", "source": "owner", "checkouts": [str(world.checkout)]})
    packet = tmp_path / "docs/r6-canonical.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "focused",
        "checkout": str(world.checkout), "commit": world.revision, "tree": world.tree}))
    invoke(docs, "publish", {"message_id": "r6-canonical", "from": "docs/orchestrator", "to": "docs/root",
        "host": "host-one", "session": "docs-orchestrator", "binding_generation": 1,
        "type": "job_request", "body": "independent canonical check", "brief": {
            "path": str(packet), "sha256": hashlib.sha256(packet.read_bytes()).hexdigest()}})
    answer, seen = r6_attachment_probe(world, target, loop=True)
    assert seen["injected"]
    assert not seen["unsafe_open"], "retained attachment reached a blocking open"
    steps = {step["step"]: step for step in answer["steps"]}
    assert steps["run_open"]["state"] == "ok"
    assert {"job": "docs/r6-canonical", "state": "completed"} in steps["run_open"]["rows"], answer


@pytest.mark.parametrize("damage", ["exit-code", "timed-out", "empty-steps", "timeout-type",
                                  "timeout-zero", "timeout-none", "timeout-empty"])
def test_r6_completed_result_requires_successful_nonempty_steps(tmp_path, damage):
    (tmp_path / ".keep").write_text("R6 contradictory completed result with recomputed receipt evidence\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    path = folder / "result.json"
    result = json.loads(path.read_text())
    assert result["state"] == "completed" and result["exit_code"] == 0 and result["steps"]
    if damage == "exit-code":
        result["steps"][0]["exit_code"] = 7
    elif damage == "timed-out":
        result["steps"][0]["timed_out"] = True
    elif damage == "empty-steps":
        result["steps"] = []
    else:
        result["steps"][0]["timed_out"] = {"timeout-type": "not-a-bool", "timeout-zero": 0,
                                          "timeout-none": None, "timeout-empty": ""}[damage]
    path.write_text(json.dumps(result))
    receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    rewrite_message(receipt, lambda m: [ref.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                    for ref in m["receipt"]["evidence"] if ref["path"] == str(path)])
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ("status", "dispatch"):
        row = world.dispatch(command=command)["small_changes"][0]
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
        assert not any(d["event"].get("status") == "FINAL" for d in row["drafts"]), row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
    assert len(world.messages("dispatch")) == 1, "failed step evidence must not reach Reviewer"


def r6_reader_probe(target, *, portable=False, virtual=False, verify_path=None, race="", world=None):
    script = r"""
import importlib.util, json, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_fresh_brief', sys.argv[1])
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
target, portable, virtual, brief = Path(sys.argv[2]), sys.argv[3] == 'True', sys.argv[4] == 'True', sys.argv[5]
race, config = sys.argv[6:8]
seen = {'injected': False, 'bytes': 0}
if portable:
    os.supports_dir_fd = set()
    for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK'):
        if hasattr(os, name): delattr(os, name)
if virtual:
    original_stat, original_fstat, original_lstat = os.stat, os.fstat, os.lstat
    class AdvertisedZero:
        st_size = 0
        def __init__(self, real): self.real = real
        def __getattr__(self, key): return getattr(self.real, key)
    def actual(path, kwargs):
        path = Path(path)
        if not path.is_absolute() and kwargs.get('dir_fd') is not None:
            path = Path(os.readlink('/proc/self/fd/%d' % kwargs['dir_fd'])) / path
        return path
    def inspected(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        return AdvertisedZero(info) if actual(path, kwargs) == target else info
    def opened(fd):
        info = original_fstat(fd)
        return AdvertisedZero(info) if Path(os.readlink('/proc/self/fd/%d' % fd)) == target else info
    def linked(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        return AdvertisedZero(info) if actual(path, kwargs) == target else info
    os.stat, os.fstat, os.lstat = inspected, opened, linked
if race:
    original_open, original_read = os.open, os.read
    watched = set()
    def raced(path, flags, *args, **kwargs):
        if Path(path) == target and not seen['injected']:
            seen['injected'] = True
            target.rename(target.with_name(target.name + '.original'))
            replacement = target.with_name(target.name + '.replacement')
            replacement.write_bytes(b'replacement file')
            if race == 'symlink': target.symlink_to(replacement)
            else: target.write_bytes(b'replacement file')
            descriptor = original_open(path, flags, *args, **kwargs)
            watched.add(descriptor)
            return descriptor
        return original_open(path, flags, *args, **kwargs)
    def read(descriptor, size):
        chunk = original_read(descriptor, size)
        if descriptor in watched: seen['bytes'] += len(chunk)
        return chunk
    os.open, os.read = raced, read
if config:
    import pwd, runpy
    from types import SimpleNamespace
    args = json.loads(config)
    pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=args['home'])
    tool = str(Path(sys.argv[1]).with_name('hierarchy_router.py'))
    sys.argv = [tool, '--lifecycle', args['journal'], '--store', args['store'], 'dispatch',
                '--recipes', args['recipes'], '--wait', '0.1', '--evidence-only']
    runpy.run_path(tool, run_name='__main__')
if brief:
    sys.exit(fresh.main(['verify', '--path', brief, '--sha256', fresh.hashlib.sha256(Path(brief).read_bytes()).hexdigest()]))
try:
    result = fresh.file_ref(target)
    answer = {'state': 'ok', 'ref': result}
except (ValueError, OSError) as exc:
    answer = {'state': 'refused', 'error': str(exc)}
if race: answer['observed'] = seen
print(json.dumps(answer))
"""
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools/hierarchy_fresh_brief.py"),
        str(target), str(portable), str(virtual), str(verify_path or ""), race,
        json.dumps({"journal": str(world.ledger.path), "store": str(world.workspace.store),
                    "recipes": str(world.recipes_path), "home": str(world.tmp / "home")}) if world else ""], env=os.environ.copy(),
        capture_output=True, text=True, timeout=30)
    assert p.stderr == "", p.stdout + p.stderr
    return p.returncode, json.loads(p.stdout)


@pytest.mark.parametrize("entry", ["reference", "verify"])
def test_r6_portable_reader_preserves_existing_callers_without_descriptor_support(tmp_path, entry):
    (tmp_path / ".keep").write_text("R6 modelled portable host, no directory-descriptor/no-follow flags\n")
    target = tmp_path / "portable-evidence"
    data = b"portable reference\n" * 20000
    target.write_bytes(data)
    brief = tmp_path / "portable.md"
    lines = ["# Fresh thread brief", "<!-- aegis.hierarchy-fresh-brief/v1 -->", "Resume path: Verify first."]
    from tests.integration.test_hierarchy_fresh_brief import SECTIONS
    for section in SECTIONS:
        lines += ["## " + section, "- " + json.dumps({"kind": "evidence", "ref": {
            "path": str(target), "sha256": hashlib.sha256(data).hexdigest()}})]
    brief.write_text("\n".join(lines) + "\n")
    code, answer = r6_reader_probe(target, portable=True, verify_path=brief if entry == "verify" else None)
    assert code == 0 and (answer.get("ok") is True if entry == "verify" else answer["state"] == "ok"), answer
    if entry == "reference":
        assert answer["ref"] == {"path": str(target), "sha256": hashlib.sha256(data).hexdigest()}


@pytest.mark.parametrize("portable", [False, True], ids=["anchored", "portable"])
def test_r6_reader_refuses_nonempty_content_advertised_as_zero_bytes(tmp_path, portable):
    (tmp_path / ".keep").write_text("R6 owned virtual-file model, nonempty bytes with zero reported size\n")
    target = tmp_path / "virtual-file"
    target.write_bytes(b"readable virtual content\n")
    code, answer = r6_reader_probe(target, portable=portable, virtual=True)
    assert code == 0 and answer["state"] == "refused", answer
    assert answer["error"] == "reference content exceeds reported size: " + str(target), answer


@pytest.mark.parametrize("portable", [False, True], ids=["anchored", "portable"])
def test_r6_reader_preserves_genuinely_empty_regular_files(tmp_path, portable):
    target = tmp_path / "empty"
    target.write_bytes(b"")
    code, answer = r6_reader_probe(target, portable=portable)
    assert code == 0 and answer == {"state": "ok", "ref": {
        "path": str(target), "sha256": hashlib.sha256(b"").hexdigest()}}, answer



@pytest.mark.parametrize("race", ["replacement", "symlink"])
def test_r6_portable_open_identity_is_checked_before_reading_replacement(tmp_path, race):
    (tmp_path / ".keep").write_text("R6 portable leaf changes at OS open boundary\n")
    target = tmp_path / "portable-race"
    target.write_bytes(b"original file")
    code, answer = r6_reader_probe(target, portable=True, race=race)
    assert code == 0 and answer["observed"]["injected"], answer
    assert answer["observed"]["bytes"] == 0, answer
    assert answer["state"] == "refused", answer
    assert answer["error"] == "reference changed while opening: " + str(target), answer


def test_r6_retained_zero_size_log_cannot_authenticate_an_empty_hash(tmp_path):
    (tmp_path / ".keep").write_text("R6 modelled virtual retained log with forged empty receipt proof\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    target = folder / "step-1.log"
    assert target.read_bytes()
    receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    def corrupt(message):
        for ref in message["receipt"]["evidence"]:
            if ref["path"] == str(target):
                ref["sha256"] = hashlib.sha256(b"").hexdigest()
    rewrite_message(receipt, corrupt)
    receipt_path = Path(receipt["path"])
    header, body = receipt_path.read_text()[4:].split("\n---\n\n", 1)
    body = body.split("\n\nLast output, which is untrusted information:\n", 1)[0]
    receipt_path.write_text("---\n" + header + "\n---\n\n" + body)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    code, answer = r6_reader_probe(target, virtual=True, world=world)
    assert code == 0, answer
    row = answer["small_changes"][0]
    assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
    assert len(world.messages("dispatch")) == 1



@pytest.mark.parametrize("damage", ["hash", "limit"])
def test_r6_attachment_capture_preserves_hash_and_mailbox_byte_bound(tmp_path, damage):
    (tmp_path / ".keep").write_text("R6 original attachment hash and size guards remain enforced\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    record = world.messages("dispatch")[0]
    path = Path(record["message"]["brief"]["path"])
    if damage == "hash":
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        raw = path.read_bytes() + b"\n" + b"x" * 262144
        sha = hashlib.sha256(raw).hexdigest()
        path = path.with_name("fresh-" + sha + ".md")
        path.write_bytes(raw)
        rewrite_message(record, lambda m: m.update(brief={"path": str(path), "sha256": sha}))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()["small_changes"][0]
    assert (row["state"], row.get("reason")) == ("held", "small_change_message_conflict"), row
    assert ("brief sha256 mismatch" if damage == "hash" else "input exceeds 262144 bytes") in row["detail"], row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before



@pytest.mark.parametrize("entry", ["dispatch-with-recipes", "status-without-recipes"])
def test_r7_expects_tests_semantics_cannot_be_skipped_by_status_without_recipes(tmp_path, entry):
    (tmp_path / ".keep").write_text("R7 admitted recipe semantics and optional status configuration\n")
    program = ("from pathlib import Path; import sys; p=Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); "
               "p.write_text('<testsuite tests=\"1\" failures=\"0\" errors=\"0\" skipped=\"0\"/>')")
    world = DispatchWorld(tmp_path, recipe_changes={"expects_tests": True, "keep": ["run/junit.xml"],
        "steps": [["$python", "-c", program, "$scratch/junit.xml"]]})
    folder = formal_completed_job(world)
    result_path = folder / "result.json"
    result = json.loads(result_path.read_text())
    assert result["state"] == "completed" and result["reason"] is None
    assert result["tests"]["total"] == 1 and result["tests"]["passed"] == 1
    result["tests"] = None
    result_path.write_text(json.dumps(result))
    receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    rewrite_message(receipt, lambda m: [ref.update(sha256=hashlib.sha256(result_path.read_bytes()).hexdigest())
                    for ref in m["receipt"]["evidence"] if ref["path"] == str(result_path)])
    path = Path(receipt["path"])
    header, body = path.read_text()[4:].split("\n---\n\n", 1)
    assert any(part.startswith("Tests: ") for part in body.split("\n\n"))
    body = "\n\n".join(part for part in body.split("\n\n") if not part.startswith("Tests: "))
    path.write_text("---\n" + header + "\n---\n\n" + body)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    report = world.dispatch() if entry == "dispatch-with-recipes" else world.run("status")
    row = report["small_changes"][0]
    if entry == "dispatch-with-recipes":
        assert row["state"] == "held", row
        assert row["reason"] == "small_change_receipt_invalid", row
    assert len(world.messages("dispatch")) == 1, "contradictory expects_tests evidence reached Reviewer"
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def r7_router_probe(world, injection, *, command="dispatch", extra=(), evidence_only=True, expect=0, telemetry=None,
                    environ=None):
    script = """import importlib.util, json, os, pwd, sys
from pathlib import Path
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location('hierarchy_router', sys.argv[1])
router = importlib.util.module_from_spec(spec); spec.loader.exec_module(router)
pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=sys.argv[2])
telemetry = Path(sys.argv[3]); seen = {}
""" + injection + """
try:
    code = router.main(sys.argv[4:])
finally:
    telemetry.write_text(json.dumps(seen))
sys.exit(code)
"""
    telemetry = telemetry or world.tmp / "r7-io.json"
    args = ["--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store), command,
            "--recipes", str(world.recipes_path), "--wait", "0.1"]
    if command == "dispatch" and evidence_only:
        args.append("--evidence-only")
    env = {k: v for k, v in (os.environ if environ is None else environ).items()
           if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROUTER), str(world.tmp / "home"),
                        str(telemetry), *args, *extra], env=env, capture_output=True, text=True, timeout=30)
    assert p.returncode == expect and p.stderr == "", p.stdout + p.stderr
    return json.loads(p.stdout), json.loads(telemetry.read_text())


@pytest.mark.parametrize("stage", ["writer", "check", "reviewer", "check-batch"])
@pytest.mark.parametrize("damage", ["fifo", "symlink", "content", "steady", "after-capture"])
def test_r7_publication_uses_one_nonblocking_hash_bound_capture(tmp_path, stage, damage):
    (tmp_path / ".keep").write_text("R7 publication boundary; owned files, modelled OS substitutions\n")
    world = DispatchWorld(tmp_path, checks=2 if stage == "check-batch" else 1)
    if stage != "writer":
        world.dispatch()
        world.finish_writer()
    if stage == "reviewer":
        world.dispatch()
        world.run_jobs()
    original_dispatches, original_checks = world.messages("dispatch"), world.messages("job_request")
    injection = r"""
import io, stat
damage = %r
seen.update(injected=False, unsafe=False, bytes=0, raw_sha=None, target=None, checks=0, reopened=0)
link, inspected, opened, descriptor, read = os.replace, os.stat, io.open, os.open, os.read
def actual(path, kw):
    if not isinstance(path, (str, bytes, os.PathLike)): return None
    value = Path(os.fsdecode(path))
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / value
    return str(value)
def staged(src, dst, *args, **kw):
    answer = link(src, dst, *args, **kw)
    path = Path(actual(dst, {'dir_fd': kw.get('dst_dir_fd')}))
    if path.parent.name == 'briefs':
        seen['target'] = str(path)
        seen['raw_sha'] = __import__('hashlib').sha256(path.read_bytes()).hexdigest()
    return answer
def checked(path, *args, **kw):
    info = inspected(path, *args, **kw)
    if (damage == 'after-capture' and seen['bytes'] and not seen.get('changed')
            and '/bindings/engine/orchestrator/' in str(actual(path, kw))):
        seen['changed'] = True
        with opened(seen['target'], 'ab') as stream: stream.write(b'changed after capture')
    frame, reading = sys._getframe(1), False
    while frame is not None:
        reading = reading or frame.f_code.co_name in {'read_bytes', '_read_reference'}
        frame = frame.f_back
    if actual(path, kw) == seen['target'] and reading: seen['checks'] += 1
    # Substitute at the content reader's regular-file observation, not at publication's path-return check.
    if (actual(path, kw) == seen['target'] and reading and not seen['injected']
            and (kw.get('follow_symlinks', True) or kw.get('dir_fd') is not None)
            and stat.S_ISREG(info.st_mode)):
        seen['injected'] = True
        target = Path(seen['target'])
        if damage not in {'steady', 'after-capture'}:
            target.rename(target.with_name(target.name + '.original'))
            if damage == 'fifo': os.mkfifo(target)
            elif damage == 'symlink': target.symlink_to(target.with_name(target.name + '.original'))
            else: target.write_bytes(b'changed after the regular-file observation')
    return info
def unsafe(path, *args, **kw):
    mode = args[0] if args else kw.get('mode', 'r')
    if actual(path, kw) == seen['target'] and seen['injected'] and 'r' in mode:
        seen['unsafe'] = True
        raise OSError('modelled blocking publication open intercepted')
    return opened(path, *args, **kw)
watched = set()
def fdopen(path, flags, *args, **kw):
    if actual(path, kw) == seen['target'] and seen['injected'] and not flags & os.O_NONBLOCK:
        seen['unsafe'] = True
        raise OSError('modelled blocking descriptor publication open intercepted')
    result = descriptor(path, flags, *args, **kw)
    if actual(path, kw) == seen['target']: watched.add(result)
    else: watched.discard(result)
    return result
def consumed(fd, amount):
    data = read(fd, amount)
    if fd in watched: seen['bytes'] += len(data)
    return data
os.replace, os.stat, io.open, os.open, os.read = staged, checked, unsafe, fdopen, consumed
fdopen_stream = os.fdopen
def stream(fd, *args, **kw):
    mode = args[0] if args else kw.get('mode', 'r')
    if actual(os.readlink('/proc/self/fd/%%d' %% fd), {}) == seen['target'] and 'r' in mode:
        seen['reopened'] += 1
    return fdopen_stream(fd, *args, **kw)
os.fdopen = stream
""" % damage
    report, seen = r7_router_probe(world, injection)
    assert seen["injected"], seen
    assert not seen["unsafe"], "publication reached the pinned blocking attachment reader"
    row = report["small_changes"][0]
    if damage == "steady":
        assert row["state"] == {"writer": "writer_sent", "check": "checking", "check-batch": "checking", "reviewer": "reviewing"}[stage], row
        record = (world.messages("job_request") if stage in {"check", "check-batch"} else world.messages("dispatch"))[-1]
        ref = record["message"]["brief"]
        assert ref["sha256"] == seen["raw_sha"] == hashlib.sha256(Path(ref["path"]).read_bytes()).hexdigest()
        assert seen["bytes"] == Path(ref["path"]).stat().st_size, "publication recaptured an attachment"
        assert seen["reopened"] == 0, "publication staging reread an already captured attachment"
    else:
        if damage == "after-capture":
            assert seen.get("changed"), seen
        assert row["state"] == "held", row
        assert world.messages("dispatch") == original_dispatches and world.messages("job_request") == original_checks


@pytest.mark.parametrize("extension", [".cmd", ".bat", ".exe", ".com"])
@pytest.mark.parametrize("damage", ["steady", "type", "identity", "size", "mtime", "reparse"])
def test_r7_portable_verify_uses_platform_consistent_witnesses(tmp_path, extension, damage):
    (tmp_path / ".keep").write_text("R7 modelled Windows filename-derived execute bits\n")
    target = tmp_path / ("tool" + extension)
    target.write_bytes(b"ordinary executable reference\n")
    from tests.integration.test_hierarchy_fresh_brief import SECTIONS
    brief = tmp_path / "portable.md"
    lines = ["# Fresh thread brief", "<!-- aegis.hierarchy-fresh-brief/v1 -->", "Resume path: Verify first."]
    for section in SECTIONS:
        lines += ["## " + section, "- " + json.dumps({"kind": "evidence", "ref": {
            "path": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}})]
    brief.write_text("\n".join(lines) + "\n")
    script = r"""
import importlib.util, os, stat, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_fresh_brief', sys.argv[1])
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
target, brief, damage = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
os.supports_dir_fd = set()
original_lstat, original_fstat = os.lstat, os.fstat
class Witness:
    def __init__(self, original, **changes): self.original, self.changes = original, changes
    def __getattr__(self, key): return self.changes[key] if key in self.changes else getattr(self.original, key)
def linked(path, *args, **kw):
    info = original_lstat(path, *args, **kw)
    return Witness(info, st_mode=info.st_mode | 0o111) if Path(path) == target else info
def opened(fd):
    info = original_fstat(fd)
    if Path(os.readlink('/proc/self/fd/%%d' %% fd)) != target: return info
    changes = {}
    if damage == 'type': changes['st_mode'] = stat.S_IFDIR | 0o644
    if damage == 'identity': changes['st_ino'] = info.st_ino + 1
    if damage == 'size': changes['st_size'] = info.st_size + 1
    if damage == 'mtime': changes['st_mtime_ns'] = info.st_mtime_ns + 1
    if damage == 'reparse': changes['st_file_attributes'] = stat.FILE_ATTRIBUTE_REPARSE_POINT
    return Witness(info, **changes)
os.lstat, os.fstat = linked, opened
sys.exit(fresh.main(['verify', '--path', str(brief), '--sha256', __import__('hashlib').sha256(brief.read_bytes()).hexdigest()]))
""".replace("%%", "%")
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools/hierarchy_fresh_brief.py"),
        str(target), str(brief), damage], env=os.environ.copy(), capture_output=True, text=True, timeout=15)
    assert p.stderr == "", p.stdout + p.stderr
    answer = json.loads(p.stdout)
    if damage == "steady":
        assert p.returncode == 0 and answer["ok"], answer
    else:
        assert p.returncode != 0 and not answer.get("ok", False), answer
        assert "reference changed while opening" in answer["error"], answer


@pytest.mark.parametrize("damage", ["missing", "total-zero", "passed-zero", "reason", "reason-empty", "counts-disagree",
                                  "new-commit", "valid", "some-failed"])
def test_r7_completed_recipe_semantics_are_checked_before_publication(tmp_path, damage):
    (tmp_path / ".keep").write_text("R7 completed result semantics; original runner receipt body recomputed\n")
    program = ("from pathlib import Path; import sys; p=Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); "
               "p.write_text('<testsuite tests=\"1\"/>')")
    world = DispatchWorld(tmp_path, recipe_changes={"expects_tests": True, "keep": ["run/junit.xml"],
        "steps": [["$python", "-c", program, "$scratch/junit.xml"]]})
    folder = formal_completed_job(world)
    result_path = folder / "result.json"
    result = json.loads(result_path.read_text())
    if damage == "missing": result["tests"] = None
    elif damage == "total-zero": result["tests"].update(total=0, passed=0)
    elif damage == "passed-zero": result["tests"].update(passed=0, skipped=1)
    elif damage == "reason": result["reason"] = "the run passed no tests"
    elif damage == "reason-empty": result["reason"] = ""
    elif damage == "counts-disagree": result["tests"]["total"] = 2
    elif damage == "new-commit": result["commit"] = "f" * 40
    elif damage == "some-failed": result["tests"].update(total=2, failed=1)
    result_path.write_text(json.dumps(result))
    receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    rewrite_message(receipt, lambda m: [ref.update(sha256=hashlib.sha256(result_path.read_bytes()).hexdigest())
                    for ref in m["receipt"]["evidence"] if ref["path"] == str(result_path)])
    # Use the public runner's own unchanged rendering to remove unrelated body mismatches from the probe.
    from tools.hierarchy_jobs import Job, result_body
    job = Job(world.workspace.store, {"id": "engine"}, world.messages("job_request")[0]["message"])
    body = result_body(job, result)
    path = Path(receipt["path"])
    header, _body = path.read_text()[4:].split("\n---\n\n", 1)
    if damage == "reason":
        message = json.loads(header)
        message["receipt"]["reason"] = result["reason"]
        header = json.dumps(message)
    path.write_text("---\n" + header + "\n---\n\n" + body)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    if damage in {"reason", "reason-empty"}:
        status = world.run("status")["small_changes"][0]
        assert (status["state"], status.get("reason")) == ("held", "small_change_receipt_invalid"), status
    row = world.dispatch()["small_changes"][0]
    if damage in {"valid", "some-failed"}:
        assert row["state"] == "reviewing", row
    else:
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
        assert len(world.messages("dispatch")) == 1


@pytest.mark.parametrize("liveness", ["live", "dead", "unknown"])
def test_r7_started_check_observes_claim_before_growing_logs(tmp_path, liveness):
    (tmp_path / ".keep").write_text("R7 modelled process observation, real public runner's started receipt\n")
    world = DispatchWorld(tmp_path, checks=2)
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    world.run_jobs()
    record = world.messages("job_request")[0]
    folder = world.workspace.store / "jobs/engine" / record["message"]["message_id"]
    terminal = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    Path(terminal["path"]).unlink()
    (folder / "result.json").unlink()
    injection = r"""
import hierarchy_jobs as jobs
target = Path(%r)
claim_path = target / 'claim.json'
claim = json.loads(claim_path.read_text())
if %r == 'live':
    claim.update(pid=os.getpid(), start=jobs.process_start(os.getpid()), process_scope=jobs.process_scope())
elif %r == 'unknown': claim['process_scope'] = {'unknown': 'modelled inaccessible scope'}
claim_path.write_text(json.dumps(claim))
seen['log_reads'] = 0
read = os.read
def consumed(fd, amount):
    path = Path(os.readlink('/proc/self/fd/%%d' %% fd))
    if path.parent == target and path.name.startswith('step-'):
        seen['log_reads'] += 1
        with path.open('ab') as stream: stream.write(b'modelled concurrent log append')
    return read(fd, amount)
os.read = consumed
""" % (str(folder), liveness, liveness)
    before_messages = world.messages()
    for command in ("status", "dispatch"):
        report, seen = r7_router_probe(world, injection, command=command)
        row = report["small_changes"][0]
        if liveness == "live":
            assert row["state"] == "checking", row
            assert row["checks"][0]["state"] == "running", row
            assert seen["log_reads"] == 0, seen
            assert not row.get("drafts"), row
        else:
            assert (row["state"], row.get("reason")) == ("held", "small_change_unknown_effect"), row
        assert world.messages() == before_messages, "uncertain/running check allowed missing batch publication"


@pytest.mark.parametrize("damage", ["steady", "identity", "type", "reparse"])
def test_r7_retained_log_and_directory_marks_ignore_only_permissions(tmp_path, damage):
    (tmp_path / ".keep").write_text("R7 retained snapshot pathname/fstat permission disagreement\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    injection = r"""
import stat
target = Path(%r)
old_stat, old_fstat = os.stat, os.fstat
class Witness:
    def __init__(self, real, **changes): self.real, self.changes = real, changes
    def __getattr__(self, key): return self.changes[key] if key in self.changes else getattr(self.real, key)
def actual(path, kw):
    if type(path) is int: return Path(os.readlink('/proc/self/fd/%%d' %% path))
    value = Path(path)
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / value
    return value
def inspected(path, *args, **kw):
    info = old_stat(path, *args, **kw)
    value = actual(path, kw)
    if value == target or value.parent == target: return Witness(info, st_mode=info.st_mode ^ 0o111)
    return info
def opened(fd):
    info = old_fstat(fd)
    value = actual(fd, {})
    changes = {}
    if value.parent == target and value.name.startswith('step-'):
        if %r == 'identity': changes['st_ino'] = info.st_ino + 1
        if %r == 'type': changes['st_mode'] = stat.S_IFIFO | 0o600
        if %r == 'reparse': changes['st_file_attributes'] = stat.FILE_ATTRIBUTE_REPARSE_POINT
    return Witness(info, **changes)
os.stat, os.fstat = inspected, opened
""" % (str(folder), damage, damage, damage)
    row = r7_router_probe(world, injection)[0]["small_changes"][0]
    if damage == "steady":
        assert row["state"] == "reviewing", row
    else:
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
        assert len(world.messages("dispatch")) == 1


@pytest.mark.parametrize("publication_pause", ["steady", "receipt", "unlock"])
def test_r7_public_live_runner_is_running_without_log_capture_or_batch_continuation(tmp_path, publication_pause):
    import time
    (tmp_path / ".keep").write_text("R7 concurrent public command runner; temporary fixture process only\n")
    started, release = tmp_path / "started", tmp_path / "release"
    program = ("from pathlib import Path; import time; "
               "Path(%r).write_text('started'); "
               "exec(\"while not Path(%%r).exists():\\n print('growing log', flush=True)\\n time.sleep(0.01)\" %% %r)"
               % (str(started), str(release)))
    world = DispatchWorld(tmp_path, checks=2, recipe_changes={"timeout_seconds": 30,
        "steps": [["$python", "-c", program]]})
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    requests = world.messages("job_request")
    paused, resume = tmp_path / "publication-paused", tmp_path / "resume-publication"
    # Delay only this runner's mailbox OS boundary, leaving pytest's globals alone.
    script = r"""
import importlib.util, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_jobs', sys.argv[1])
jobs = importlib.util.module_from_spec(spec); sys.modules[spec.name] = jobs; spec.loader.exec_module(jobs)
import hierarchy_mailbox as mailbox
real_os = mailbox.os
class PublicationOS:
    published = False
    def __getattr__(self, name): return getattr(real_os, name)
    def pause(self):
        Path(sys.argv[3]).write_text('publication paused')
        deadline = time.monotonic() + 10
        while not Path(sys.argv[4]).exists():
            if time.monotonic() >= deadline: raise TimeoutError('fixture publication was not resumed')
            time.sleep(0.01)
    def link(self, src, dst, *args, **kwargs):
        if Path(dst).name.endswith('-started.md'):
            if sys.argv[2] == 'receipt': self.pause()
            result = real_os.link(src, dst, *args, **kwargs)
            self.published = True
            return result
        return real_os.link(src, dst, *args, **kwargs)
    def unlink(self, path, *args, **kwargs):
        if self.published and Path(path).name == '.write.lock':
            self.published = False
            if sys.argv[2] == 'unlock': self.pause()
        return real_os.unlink(path, *args, **kwargs)
mailbox.os = PublicationOS()
sys.exit(jobs.main(sys.argv[5:]))
"""
    env = {k: v for k, v in os.environ.items()
           if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    argv = [sys.executable, "-I", "-B", str(JOBS)]
    if publication_pause != "steady":
        argv = [sys.executable, "-I", "-B", "-c", script, str(JOBS), publication_pause, str(paused), str(resume)]
    process = subprocess.Popen(argv + ["--store", str(world.workspace.store),
        "--recipes", str(world.recipes_path), "run-open"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        ready = False
        while process.poll() is None and time.monotonic() < deadline:
            publication_is_paused = paused.exists() and not resume.exists()
            started_receipt = any(record["message"]["in_reply_to"] == requests[0]["message"]["message_id"]
                and record["message"]["receipt"]["state"] == "started"
                for record in world.messages("job_receipt"))
            locked = (world.root / ".write.lock").exists()
            if publication_is_paused:
                assert locked, "fixture did not retain the publication lock"
                assert started_receipt == (publication_pause == "unlock"), "fixture paused at the wrong boundary"
                resume.write_text("resume owned fixture publication\n")
            ready = started.exists() and started_receipt and not locked
            if ready:
                break
            time.sleep(0.01)
        assert ready, "public runner did not finish publishing its start receipt"
        assert publication_pause == "steady" or resume.exists(), "fixture did not pause publication"
        for command in ("status", "dispatch"):
            row = world.dispatch(command=command)["small_changes"][0]
            assert row["state"] == "checking" and row["checks"][0]["state"] == "running", row
            assert not row["drafts"]
            assert world.messages("job_request") == requests and len(world.messages("dispatch")) == 1
    finally:
        resume.write_text("resume owned fixture publication\n")
        release.write_text("finish original fixture check\n")
        stdout, stderr = process.communicate(timeout=20)
    assert process.returncode == 0 and not stderr, stdout + stderr
    assert json.loads(stdout)["rows"][0]["state"] == "completed"
    world.dispatch()
    assert len(world.messages("job_request")) == 2
    world.run_jobs()
    assert world.dispatch()["small_changes"][0]["state"] == "reviewing"


@pytest.mark.parametrize("command", ["status", "dispatch"])
def test_r7_lost_completed_receipt_holds_batch_until_original_settlement(tmp_path, command):
    (tmp_path / ".keep").write_text("R7 completed result is not an original terminal receipt\n")
    world = DispatchWorld(tmp_path, checks=2)
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    original = world.messages("job_request")
    world.run_jobs()
    folder = world.workspace.store / "jobs/engine" / original[0]["message"]["message_id"]
    claim, result = (folder / "claim.json").read_bytes(), (folder / "result.json").read_bytes()
    terminal = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    Path(terminal["path"]).unlink()
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch(command=command)["small_changes"][0]
    assert (row["state"], row.get("reason")) == ("held", "small_change_unknown_effect"), row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
    assert world.messages("job_request") == original
    world.run_jobs()
    assert (folder / "claim.json").read_bytes() == claim and (folder / "result.json").read_bytes() == result
    assert world.messages("job_receipt")[-1]["message"]["message_id"] == terminal["message"]["message_id"]
    world.dispatch()
    assert len(world.messages("job_request")) == 2
    world.run_jobs()
    assert world.dispatch()["small_changes"][0]["state"] == "reviewing"


def test_r7_claim_capture_refuses_missing_descriptor_capability_before_open(tmp_path):
    (tmp_path / ".keep").write_text("R7 modelled host missing a POSIX descriptor flag\n")
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    terminal = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    Path(terminal["path"]).unlink()
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = r7_router_probe(world, "del os.O_CLOEXEC\n", command="status")[0]["small_changes"][0]
    assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
    assert row["detail"] == "retained descriptor capture requires POSIX directory descriptors", row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
    assert (folder / "result.json").is_file()


def r8_refresh_receipt(world, folder):
    """Modelled retained-data tampering, correlated with the unchanged public runner renderer."""
    from tools.hierarchy_jobs import Job, result_body
    result_path = folder / "result.json"
    result = json.loads(result_path.read_text())
    receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    rewrite_message(receipt, lambda m: [ref.update(sha256=hashlib.sha256(Path(ref["path"]).read_bytes()).hexdigest())
                                      for ref in m["receipt"]["evidence"]])
    rewrite_message(receipt, lambda m: m["receipt"]["evidence"].sort(key=lambda ref: ref["path"]))
    job = Job(world.workspace.store, {"id": "engine"}, world.messages("job_request")[0]["message"])
    path = Path(receipt["path"])
    header, _body = path.read_text()[4:].split("\n---\n\n", 1)
    path.write_text("---\n" + header + "\n---\n\n" + result_body(job, result))


@pytest.mark.parametrize("damage", ["steady", "truncate", "drop-last", "gap", "extra", "process", "reorder"])
def test_r8_completed_recipe_has_exact_order_and_numbered_logs(tmp_path, damage):
    world = DispatchWorld(tmp_path, recipe_changes={"steps": [["$python", "-c", "print(%d)" % n] for n in range(3)]})
    folder = formal_completed_job(world)
    path = folder / "result.json"
    result = json.loads(path.read_text())
    if damage == "truncate": result["steps"] = result["steps"][:1]
    if damage == "drop-last": result["steps"].pop()
    if damage == "extra": result["steps"].append(result["steps"][-1])
    if damage == "reorder": result["steps"].reverse()
    if damage == "gap":
        (folder / "step-2.log").rename(folder / "step-4.log")
        receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
        rewrite_message(receipt, lambda m: [ref.update(path=str(folder / "step-4.log"))
                        for ref in m["receipt"]["evidence"] if ref["path"] == str(folder / "step-2.log")])
    if damage == "process":
        process_path = folder / "process.json"
        process = json.loads(process_path.read_text())
        process["step"] = 4
        process_path.write_text(json.dumps(process))
    path.write_text(json.dumps(result))
    r8_refresh_receipt(world, folder)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()["small_changes"][0]
    if damage == "steady":
        assert row["state"] == "reviewing", json.dumps(row, indent=2)
    else:
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), json.dumps(row, indent=2)
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
        assert len(world.messages("dispatch")) == 1


@pytest.mark.parametrize("command", ["status", "dispatch"])
def test_r8_live_runner_with_terminal_receipt_holds_until_runner_exits(tmp_path, command):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    injection = """
import hierarchy_jobs as jobs
path = Path(%r) / 'claim.json'
claim = json.loads(path.read_text())
claim.update(pid=os.getpid(), start=jobs.process_start(os.getpid()), process_scope=jobs.process_scope())
path.write_text(json.dumps(claim))
""" % str(folder)
    before = world.ledger.files(), world.messages()
    row = r7_router_probe(world, injection, command=command)[0]["small_changes"][0]
    assert (row["state"], row.get("reason")) == ("held", "small_change_unknown_effect"), json.dumps(row, indent=2)
    assert (world.ledger.files(), world.messages()) == before
    # The fixture observation process has now exited. Original work settles without replay or a replacement ID.
    assert world.dispatch()["small_changes"][0]["state"] == "reviewing"
    assert world.messages("job_request") == [record for record in before[1] if record["message"]["type"] == "job_request"]


def test_r8_terminal_capture_checks_descriptor_capabilities_before_constants(tmp_path):
    world = DispatchWorld(tmp_path)
    formal_completed_job(world)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = r7_router_probe(world, "del os.O_CLOEXEC\n", command="status")[0]["small_changes"][0]
    assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), json.dumps(row, indent=2)
    assert row["detail"] == "retained descriptor capture requires POSIX directory descriptors", json.dumps(row, indent=2)
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r8_recipe_less_close_has_an_unverified_reason_and_next_action(tmp_path):
    world = DispatchWorld(tmp_path)
    review_result(world, ready_reviewer(world))
    row = world.run("status")["small_changes"][0]
    assert row["state"] == "held" and row["reason"] == "small_change_close_unverified", json.dumps(row, indent=2)
    assert row["drafts"] == [] and "rerun with --recipes <file>" in row["detail"], json.dumps(row, indent=2)


def r8_compose_probe(world, injection=""):
    script = """import importlib.util, json, os, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_fresh_brief', sys.argv[1])
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
seen = {}
""" + injection + """
try:
    code = fresh.main(sys.argv[3:])
finally:
    Path(sys.argv[2]).write_text(json.dumps(seen))
sys.exit(code)
"""
    telemetry = world.tmp / "r8-compose-io.json"
    process = subprocess.run([sys.executable, "-I", "-B", "-c", script,
        str(ROOT / "tools/hierarchy_fresh_brief.py"), str(telemetry), "compose", "--root", str(world.root),
        "--initiative", "engine", "--endpoint", "engine/orchestrator", "--lifecycle", str(world.ledger.path)],
        env=os.environ.copy(), capture_output=True, text=True, timeout=20)
    assert process.stderr == "", process.stdout + process.stderr
    return process.returncode, json.loads(process.stdout), json.loads(telemetry.read_text())


@pytest.mark.parametrize("kind", ["brief", "ack", "result", "review", "job_receipt"])
@pytest.mark.parametrize("damage", ["steady", "oversize", "fifo", "symlink"])
def test_r8_unread_typed_attachments_are_bounded_and_fail_closed(tmp_path, kind, damage):
    world = DispatchWorld(tmp_path)
    formal_completed_job(world)
    world.dispatch()
    if kind == "review": review_result(world, next(r["message"] for r in world.messages("dispatch") if r["message"]["to"].endswith("review0")))
    if kind == "brief":
        original = world.root.parent / "notice.md"
        original.write_text("original brief\n")
        ref = {"path": str(original), "sha256": hashlib.sha256(original.read_bytes()).hexdigest()}
        invoke(world.root, "publish", {"message_id": "unread-notice", "from": "engine/root",
            "to": "engine/orchestrator", "host": "host-one", "session": "engine/root",
            "binding_generation": 1, "type": "brief", "brief": ref, "body": "retained notice"})
    record = world.messages(kind)[-1]
    path = world.root.parent / "typed.md"
    raw = b"unread typed attachment\n"
    if damage == "oversize": raw = b"x" * (262144 + 1)
    target = world.root.parent / "target.md"
    target.write_bytes(raw)
    if damage == "fifo": os.mkfifo(path)
    elif damage == "symlink": path.symlink_to(target)
    else: path.write_bytes(raw)
    rewrite_message(record, lambda m: m.update(brief={"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}))
    injection = """
import io
target = Path(%r)
seen['reads'] = 0
old_read = os.read
old_open = io.open
def opened(path, mode='r', *args, **kw):
    if not isinstance(path, int) and Path(path) == target and 'r' in mode: seen['reads'] += 1
    return old_open(path, mode, *args, **kw)
def observed(fd, count):
    if Path(os.readlink('/proc/self/fd/%%d' %% fd)) == target and count != 1: seen['reads'] += 1
    return old_read(fd, count)
os.read, io.open = observed, opened
""" % str(path)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    code, answer, seen = r8_compose_probe(world, injection)
    if damage == "steady":
        assert code == 0 and answer["ok"], answer
        assert seen["reads"] == 1, seen
    else:
        # R16: unread typed notes are declarations, never open work packets.
        assert code == 0 and answer["ok"], answer
        assert seen["reads"] == 0, seen
        assert "unverified_evidence" in Path(answer["brief"]["path"]).read_text()
    assert world.ledger.files() == before[0]
    after = mailbox_snapshot(world.root)
    assert all(after.get(key) == value for key, value in before[1].items())
    assert set(after) - set(before[1]) == {str(Path(answer["brief"]["path"]).relative_to(world.root.parent))}


def test_r8_recipe_and_event_bytes_are_consumed_once_per_operation(tmp_path):
    observations = []
    for checks in (1, 3):
        run = tmp_path / ("checks-%d" % checks)
        run.mkdir()
        world = DispatchWorld(run, checks=checks)
        world.dispatch()
        world.finish_writer()
        injection = r"""
import io
recipe = Path(%r)
events = Path(%r) / 'events'
seen['reads'] = {}
seen['journal_phases'] = {}
seen['recipe_parses'] = 0
operations = []
def profiled(frame, event, arg):
    if event == 'call' and frame.f_code.co_name == 'strict_json' and frame.f_back.f_code.co_name == 'recipe_file':
        seen['recipe_parses'] += 1
sys.setprofile(profiled)
old_open, old_fd = io.open, os.open
def track(path):
    path = Path(path)
    if path == recipe or path.parent == events:
        key = str(path)
        seen['reads'][key] = seen['reads'].get(key, 0) + 1
        if path.parent == events:
            frame, phase = sys._getframe(1), 'uncaptured'
            while frame is not None:
                if frame.f_code.co_name == 'read' and frame.f_code.co_filename.endswith('hierarchy_fresh_brief.py'):
                    operation = frame.f_locals['self']
                    if operation not in operations: operations.append(operation)
                    phase = 'capture-%%d' %% operations.index(operation)
                    break
                frame = frame.f_back
            counts = seen['journal_phases'].setdefault(phase, {})
            counts[path.name] = counts.get(path.name, 0) + 1
def opened(path, mode='r', *args, **kw):
    if not isinstance(path, int) and 'r' in mode: track(path)
    return old_open(path, mode, *args, **kw)
def descriptor(path, flags, *args, **kw):
    target = Path(path)
    if not target.is_absolute() and kw.get('dir_fd') is not None:
        target = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / target
    if flags & os.O_ACCMODE in (os.O_RDONLY, os.O_RDWR) and not flags & os.O_DIRECTORY: track(target)
    return old_fd(path, flags, *args, **kw)
io.open, os.open = opened, descriptor
""" % (str(world.recipes_path), str(world.ledger.path))
        answer, seen = r7_router_probe(world, injection)
        assert answer["small_changes"][0]["state"] == "checking", answer
        assert len(world.messages("job_request")) == checks
        assert seen["reads"][str(world.recipes_path)] == 1 and seen["recipe_parses"] == 1, seen
        phases = seen["journal_phases"]
        assert set(phases) == {"capture-0", "capture-1", "capture-2"}, seen
        assert all(counts and set(counts.values()) == {1} for counts in phases.values()), seen
        journal = {Path(path).name: count for path, count in seen["reads"].items()
                   if Path(path).parent == world.ledger.path / "events"}
        assert journal and set(journal.values()) == {len(phases)}, seen
        observations.append((phases, journal))
    assert observations[0] == observations[1], "journal reads must not grow with checks or publications"


@pytest.mark.parametrize("stage", ["writer", "check", "reviewer"])
@pytest.mark.parametrize("window", ["after-fence", "after-commit"])
def test_r8_witness_survives_last_mailbox_hook_and_commit(tmp_path, stage, window):
    world = DispatchWorld(tmp_path, checks=2 if stage == "check" else 1)
    if stage != "writer":
        world.dispatch()
        world.finish_writer()
    if stage == "reviewer":
        world.dispatch()
        world.run_jobs()
    before = world.messages(), world.ledger.files()
    injection = r"""
import io
window = %r
seen['changed'] = False
old_stat, old_link = os.stat, os.link
def alter(request):
    if seen['changed']: return
    seen['changed'] = True
    with open(request['brief']['path'], 'ab') as stream: stream.write(b'changed after fence')
def inspected(path, *args, **kw):
    value = old_stat(path, *args, **kw)
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_name == 'publish' and frame.f_code.co_filename.endswith('hierarchy_mailbox.py'):
            request = frame.f_locals['request']
            if window == 'after-fence' and 'recipient' in frame.f_locals: alter(request)
            break
        frame = frame.f_back
    return value
def linked(src, dst, *args, **kw):
    value = old_link(src, dst, *args, **kw)
    if window == 'after-commit' and Path(dst).suffix == '.md':
        raw = Path(src).read_text()
        header = json.loads(raw[4:].split('\n---\n\n', 1)[0])
        if header['type'] in {'dispatch', 'job_request'}: alter(header)
    return value
os.stat, os.link = inspected, linked
""" % window
    answer, seen = r7_router_probe(world, injection)
    assert seen["changed"], seen
    row = answer["small_changes"][0]
    assert row["state"] == "held", json.dumps(row, indent=2)
    assert world.ledger.files() == before[1], "stale assignment acquired a route receipt"
    delta = len(world.messages()) - len(before[0])
    assert delta == (1 if window == "after-commit" else 0)
    if window == "after-commit":
        assert row["reason"] == "small_change_partial_publication" and row["partial_publication"]["message_id"], row
    if stage == "writer":
        assert "engine/lane/fix" in answer["planning_exclusions"] if delta else True


@pytest.mark.parametrize("entry", ["message", "event"])
def test_r8_message_and_event_fifo_swap_never_reaches_blocking_open(tmp_path, entry):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    target = Path(world.messages()[0]["path"]) if entry == "message" else world.ledger.path / "events/000001.json"
    injection = r"""
import io, stat
target = Path(%r)
seen.update(changed=False, unsafe=False)
old_stat, old_open, old_fd = os.stat, io.open, os.open
def actual(path, kw):
    if isinstance(path, int): return None
    value = Path(path)
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / value
    return value
def inspected(path, *args, **kw):
    info = old_stat(path, *args, **kw)
    frame, reading = sys._getframe(1), False
    while frame is not None:
        reading |= frame.f_code.co_name in {'_read_reference', 'read_bytes', 'load_json'}
        frame = frame.f_back
    if (reading and actual(path, kw) == target and not seen['changed'] and stat.S_ISREG(info.st_mode)
            and (kw.get('follow_symlinks', True) or kw.get('dir_fd') is not None)):
        seen['changed'] = True
        target.rename(target.with_suffix('.original'))
        os.mkfifo(target)
    return info
def opened(path, *args, **kw):
    if actual(path, kw) == target and seen['changed']:
        seen['unsafe'] = True
        raise OSError('blocking FIFO open intercepted by the test OS boundary')
    return old_open(path, *args, **kw)
def descriptor(path, flags, *args, **kw):
    if actual(path, kw) == target and seen['changed'] and not flags & os.O_NONBLOCK:
        seen['unsafe'] = True
        raise OSError('blocking FIFO descriptor open intercepted by the test OS boundary')
    return old_fd(path, flags, *args, **kw)
os.stat, io.open, os.open = inspected, opened, descriptor
""" % str(target)
    script = """import json, os, pwd, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1]); import hierarchy_router as router
pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=sys.argv[2])
seen = {}
""" + injection + """
try: code = router.main(sys.argv[4:])
finally: Path(sys.argv[3]).write_text(json.dumps(seen))
sys.exit(code)
"""
    telemetry = tmp_path / "entry-io.json"
    process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools"), str(tmp_path / "home"),
        str(telemetry), "--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store), "dispatch",
        "--recipes", str(world.recipes_path), "--evidence-only", "--wait", "0.1"],
        env=os.environ.copy(), capture_output=True, text=True, timeout=15)
    assert not process.stderr, process.stdout + process.stderr
    answer, seen = json.loads(process.stdout), json.loads(telemetry.read_text())
    assert seen["changed"] and not seen["unsafe"], seen
    assert process.returncode == 2 or answer["small_changes"][0]["state"] == "held", answer


def test_r8_standalone_composer_keeps_captures_until_output_commit(tmp_path):
    world = DispatchWorld(tmp_path)
    path = world.root.parent / "unread.md"
    path.write_text("unread notice")
    invoke(world.root, "publish", {"message_id": "standalone-notice", "from": "engine/root",
        "to": "engine/orchestrator", "host": "host-one", "session": "engine/root", "binding_generation": 1,
        "type": "brief", "brief": {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, "body": "notice"})
    injection = """
target = Path(%r)
old_mkdir = os.mkdir
def created(path, *args, **kw):
    if Path(path).name == 'briefs':
        target.write_bytes(b'changed after inspect before output publication')
        seen['changed'] = True
    return old_mkdir(path, *args, **kw)
os.mkdir = created
""" % str(path)
    code, answer, seen = r8_compose_probe(world, injection)
    assert seen["changed"], seen
    assert code != 0 and "changed" in answer["error"], answer
    assert not list((world.root.parent / "briefs").glob("fresh-*.md"))


@pytest.mark.parametrize("command", ["status", "dispatch"])
def test_r8_claim_appearing_after_absence_is_running_not_a_lost_receipt(tmp_path, command):
    world = DispatchWorld(tmp_path, checks=2)
    world.dispatch()
    world.finish_writer()
    world.dispatch(fault="batch")
    original = world.messages("job_request")
    world.run_jobs()
    folder = world.workspace.store / "jobs/engine" / original[0]["message"]["message_id"]
    claim = json.loads((folder / "claim.json").read_text())
    (folder / "claim.json").unlink()
    terminal = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    Path(terminal["path"]).unlink()
    injection = """
import hierarchy_jobs as jobs
folder = Path(%r)
claim = %r
claim.update(pid=os.getpid(), start=jobs.process_start(os.getpid()), process_scope=jobs.process_scope())
old_stat = os.stat
seen['appeared'] = False
def observed(path, *args, **kw):
    value = old_stat(path, *args, **kw)
    if str(path) == 'result.json' and kw.get('dir_fd') is not None and not seen['appeared']:
        if Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) == folder:
            seen['appeared'] = True
            (folder / 'claim.json').write_text(json.dumps(claim))
    return value
os.stat = observed
""" % (str(folder), claim)
    answer, seen = r7_router_probe(world, injection, command=command)
    row = answer["small_changes"][0]
    assert seen["appeared"], seen
    assert row["state"] == "checking" and row["checks"][0]["state"] == "running", json.dumps(row, indent=2)
    assert not row.get("reason") and not row["drafts"]
    assert world.messages("job_request") == original


@pytest.mark.parametrize("window", ["before-route", "after-route"])
def test_r8b_route_append_rechecks_the_same_captured_assignment(tmp_path, window):
    (tmp_path / ".keep").write_text("R8b modelled route-append boundary; no new writer effect\n")
    world = DispatchWorld(tmp_path)
    before = world.ledger.files()
    injection = r"""
window = %r
seen.update(changed=False, target=None, committed_event=None, event_synced=False)
old_link, old_stat, old_sync = os.link, os.stat, os.fsync
def alter():
    if seen['changed'] or seen['target'] is None: return
    seen['changed'] = True
    with open(seen['target'], 'ab') as stream: stream.write(b'changed at route boundary')
def linked(src, dst, *args, **kw):
    answer = old_link(src, dst, *args, **kw)
    if Path(dst).suffix == '.md':
        message = json.loads(Path(src).read_text()[4:].split('\n---\n\n', 1)[0])
        if message.get('type') == 'dispatch': seen['target'] = message['brief']['path']
    if window == 'after-route' and Path(dst).parent.name == 'events':
        raw = Path(src).read_bytes()
        event = json.loads(raw)
        if event['envelope']['event']['type'] == 'route':
            import hashlib
            seen['committed_event'] = {'message_id':event['envelope']['id'],
                'evidence':{'path':str(dst),'sha256':hashlib.sha256(raw).hexdigest()}}
            alter()
    return answer
def inspected(path, *args, **kw):
    answer = old_stat(path, *args, **kw)
    if window == 'before-route':
        frame = sys._getframe(1)
        while frame is not None:
            if (frame.f_code.co_name == '_record_under_lock' and 'record' in frame.f_locals
                    and frame.f_code.co_filename.endswith('hierarchy_fresh_brief.py')):
                alter()
                break
            frame = frame.f_back
    return answer
def synced(fd):
    answer = old_sync(fd)
    committed = seen['committed_event']
    if committed and Path(os.readlink('/proc/self/fd/%%d' %% fd)) == Path(committed['evidence']['path']).parent:
        seen['event_synced'] = True
    return answer
os.link, os.stat, os.fsync = linked, inspected, synced
""" % window
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["changed"], seen
    if window == "before-route":
        assert (row["state"], row.get("reason")) == ("held", "delivered_unrecorded"), row
    else:
        assert seen["committed_event"] and seen["event_synced"], seen
        assert (row["state"], row.get("reason")) == ("held", "small_change_committed_event"), row
        assert row["partial_publication"] == seen["committed_event"], row
        assert hashlib.sha256(Path(seen["committed_event"]["evidence"]["path"]).read_bytes()).hexdigest() == seen["committed_event"]["evidence"]["sha256"]
    assert len(world.messages("dispatch")) == 1 and world.messages("job_request") == []
    assert len(world.ledger.files()) - len(before) == (1 if window == "after-route" else 0)
    assert "engine/lane/fix" in answer["planning_exclusions"]


@pytest.mark.parametrize("stage,which", [("writer", "event"), ("check", "event"), ("reviewer", "event"),
                                         ("check", "recipe"), ("reviewer", "recipe")])
def test_r8b_recipe_and_event_witnesses_refuse_stale_publication(tmp_path, stage, which):
    (tmp_path / ".keep").write_text("R8b modelled mutation after the mailbox fence\n")
    world = DispatchWorld(tmp_path)
    if stage != "writer":
        world.dispatch()
        world.finish_writer()
    if stage == "reviewer":
        world.dispatch()
        world.run_jobs()
    target = world.recipes_path if which == "recipe" else world.ledger.path / "events/000001.json"
    before = world.messages(), set(world.ledger.files())
    injection = """
target = Path(%r)
old_stat = os.stat
seen['changed'] = False
def inspected(path, *args, **kw):
    info = old_stat(path, *args, **kw)
    frame = sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_name == 'publish' and frame.f_code.co_filename.endswith('hierarchy_mailbox.py'):
            if 'recipient' in frame.f_locals and not seen['changed']:
                seen['changed'] = True
                with open(target, 'ab') as stream: stream.write(b'\\n')
            break
        frame = frame.f_back
    return info
os.stat = inspected
""" % str(target)
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["changed"] and row["state"] == "held", (seen, row)
    if which == "recipe":
        assert row["reason"] == "small_change_recipe_mismatch", row
    assert world.messages() == before[0]
    assert set(world.ledger.files()) == before[1]


def r9_source(world):
    import shutil
    source = world.tmp / "fixture-source"
    shutil.copytree(ROOT / "tools/hierarchy_templates", source / "tools/hierarchy_templates")
    # These are mutable, modelled input fixtures, even when the tested source copy is mode-read-only.
    for path in source.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    source.chmod(0o700)
    (world.root.parent / "provision.json").write_text(json.dumps({"initiative": "engine",
        "mailbox_root": str(world.root), "source": str(source), "delivery_dir": str(world.root.parent / "delivery")}))
    return source


@pytest.mark.parametrize("kind", ["contract", "plan"])
@pytest.mark.parametrize("damage", ["steady", "fifo", "oversize", "symlink"])
def test_r9_all_composition_inputs_use_bounded_captures(tmp_path, kind, damage):
    (tmp_path / ".keep").write_text("R9 modelled input boundary, no real owner-home access\n")
    world = DispatchWorld(tmp_path)
    source = r9_source(world)
    if kind == "contract":
        target = source / "tools/hierarchy_templates/roles/orchestrator.md"
    else:
        target = world.root.parent / "host-plan.json"
        target.write_text(json.dumps({"schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "engine",
            "root": "codex-cli", "team": "codex-cli", "stand_ins": {}, "config_sha256": "a" * 64}))
    if damage == "oversize": target.write_bytes(target.read_bytes() + b" " * 262145)
    if damage == "symlink":
        original = target.with_suffix(".original")
        target.rename(original)
        target.symlink_to(original)
    injection = r"""
import io, stat
target = Path(%r); damage = %r
seen.update(changed=False, unsafe=False, opens=0)
old_stat, old_open, old_fd = os.stat, io.open, os.open
def actual(path, kw):
    if isinstance(path, int): return None
    value = Path(path)
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / value
    return value
def inspected(path, *args, **kw):
    return old_stat(path, *args, **kw)
def replace_at_open(path, kw):
    if damage == 'fifo' and actual(path, kw) == target and not seen['changed']:
        seen['changed'] = True
        target.rename(target.with_suffix('.original'))
        os.mkfifo(target)
def opened(path, mode='r', *args, **kw):
    if actual(path, kw) == target and 'r' in mode:
        replace_at_open(path, kw)
        seen['opens'] += 1
        seen['unsafe'] = True
        if damage == 'fifo': raise OSError('modelled blocking input open intercepted')
    return old_open(path, mode, *args, **kw)
def descriptor(path, flags, *args, **kw):
    if actual(path, kw) == target:
        replace_at_open(path, kw)
        seen['opens'] += 1
        if not flags & os.O_NONBLOCK:
            seen['unsafe'] = True
            if damage == 'fifo': raise OSError('modelled blocking input descriptor intercepted')
    return old_fd(path, flags, *args, **kw)
os.stat, io.open, os.open = inspected, opened, descriptor
""" % (str(target), damage)
    code, answer, seen = r8_compose_probe(world, injection)
    if damage == "steady":
        assert code == 0 and seen["opens"] == 1 and not seen["unsafe"], (answer, seen)
    else:
        assert code == 2 and not seen["unsafe"], (answer, seen)
        if damage == "oversize":
            expected = ("fresh brief exceeds mailbox brief byte limit (262144)" if kind == "contract"
                        else "input exceeds 262144 bytes")
            assert answer["error"] == expected and seen["opens"] == 0, (answer, seen)
        if damage == "fifo": assert seen["changed"], seen


def test_r9_compose_does_not_take_or_remove_a_journal_writer_lock(tmp_path):
    world = DispatchWorld(tmp_path)
    lock = world.ledger.path / ".write.lock"
    lock.write_text("fixture unrelated writer owns this marker")
    before = lock.read_bytes()
    code, answer, _seen = r8_compose_probe(world)
    assert code == 0 and answer["ok"], answer
    assert lock.read_bytes() == before


def test_r9_deny_adopted_during_composition_prevents_writer_publication(tmp_path):
    world = DispatchWorld(tmp_path)
    actor = world.ledger.root_actor
    envelope = {"id": "deny-during-compose", "actor": actor, "generation": 1,
        "custody": {"cid": actor, "generation": 1}, "event": {"type": "decision", "decision": "deny",
        "reason": "owner denies before publication", **world.ledger.target(world.change.value)}}
    event_path = tmp_path / "deny.json"
    event_path.write_text(json.dumps(envelope))
    injection = r"""
import io
seen['denied'] = False
old_open, old_fd = io.open, os.open
def deny(path):
    if Path(path).name != 'lane.md' or seen['denied']: return
    seen['denied'] = True
    import subprocess
    proc = subprocess.run([sys.executable, '-I', '-B', %r, '--root', %r, 'record', '--event', %r, '--evidence-only'],
        env=os.environ.copy(), capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0, proc.stdout + proc.stderr
def opened(path, *args, **kw):
    if not isinstance(path, int): deny(path)
    return old_open(path, *args, **kw)
def descriptor(path, *args, **kw):
    if not isinstance(path, int): deny(path)
    return old_fd(path, *args, **kw)
io.open, os.open = opened, descriptor
""" % (str(ROOT / "tools/hierarchy_lifecycle.py"), str(world.ledger.path), str(event_path))
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["denied"], seen
    assert (row["state"], row.get("reason")) == ("held", "small_change_revoked"), row
    assert world.messages() == []


@pytest.mark.parametrize("origin", ["lifecycle", "receipt", "attachment-first", "staging"])
def test_r9_shared_reference_and_attachment_consumer_order(tmp_path, origin):
    world = DispatchWorld(tmp_path)
    shared = world.root.parent / "shared.md"
    shared.write_text("One unchanged file shared by evidence and typed attachment\n")
    ref = {"path": str(shared), "sha256": hashlib.sha256(shared.read_bytes()).hexdigest()}
    if origin == "lifecycle":
        other = tmp_path / "other-journal"
        other.mkdir()
        ledger = Ledger(other, policy_changes={"authority": [ref]})
        # The public composer is allowed to inspect an external journal, independent of dispatcher authority.
        world.ledger = ledger
    if origin == "receipt":
        world.dispatch()
        world.finish_writer()
        world.dispatch()
        parent = world.messages("job_request")[0]["message"]["message_id"]
        invoke(world.root, "publish", {"message_id": "queued-with-attachment", "from": "engine/root",
            "to": "engine/orchestrator", "host": "host-one", "session": "engine/root", "binding_generation": 1,
            "type": "job_receipt", "in_reply_to": parent, "body": "queued", "brief": ref,
            "receipt": {"state": "started", "evidence": [ref]}})
    elif origin == "staging":
        from tools.hierarchy_mailbox import encoded
        world.dispatch()
        raw = encoded({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "focused", "checkout": str(world.checkout),
                       "commit": world.revision, "tree": world.tree})
        packet = world.root.parent / "briefs" / ("check-" + hashlib.sha256(raw).hexdigest() + ".md")
        packet.write_bytes(raw)
        world.finish_writer(evidence=[{"path": str(packet), "sha256": hashlib.sha256(raw).hexdigest()}])
        row = world.dispatch()["small_changes"][0]
        assert row["state"] == "checking" and len(world.messages("job_request")) == 1, row
        return
    else:
        invoke(world.root, "publish", {"message_id": "shared-input", "from": "engine/root", "to": "engine/orchestrator",
            "host": "host-one", "session": "engine/root", "binding_generation": 1, "type": "brief", "brief": ref, "body": "notice"})
    code, answer, _seen = r8_compose_probe(world)
    assert code == 0 and answer["ok"], answer


@pytest.mark.parametrize("closed_kind", ["complete", "blocked"])
def test_r9_recipe_less_closed_audit_is_explicitly_unverified(tmp_path, closed_kind):
    world = DispatchWorld(tmp_path)
    reviewer = ready_reviewer(world)
    if closed_kind == "blocked":
        world.ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "owner",
            "next_decision": "review", "condition": "owner waiting", "evidence": world.ledger.evidence},
            **world.ledger.target(world.change.value))
    review_result(world, reviewer)
    if closed_kind == "complete": record_drafts(world, world.dispatch()["small_changes"][0])
    row = world.run("status")["small_changes"][0]
    assert row.get("reason") == "small_change_close_unverified" and not row["drafts"], row
    assert "rerun with --recipes <file>" in row["detail"], row


def test_r9_composer_precommit_change_is_a_refusal_not_an_internal_error(tmp_path):
    world = DispatchWorld(tmp_path)
    path = world.root.parent / "notice.md"
    path.write_text("notice")
    invoke(world.root, "publish", {"message_id": "notice", "from": "engine/root", "to": "engine/orchestrator",
        "host": "host-one", "session": "engine/root", "binding_generation": 1, "type": "brief", "body": "notice",
        "brief": {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}})
    injection = """
old_mkdir = os.mkdir
def created(path, *args, **kw):
    if Path(path).name == 'briefs':
        Path(%r).write_text('changed before commit')
        seen['changed'] = True
    return old_mkdir(path, *args, **kw)
os.mkdir = created
""" % str(path)
    code, answer, seen = r8_compose_probe(world, injection)
    assert seen["changed"] and code == 2 and "changed" in answer["error"], (code, answer, seen)


@pytest.mark.parametrize("damage", ["content", "fifo"])
def test_r9_partial_message_identity_does_not_reread_the_committed_path(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    before = world.ledger.files()
    injection = r"""
import hashlib
old_link = os.link
seen['changed'] = False
def linked(src, dst, *args, **kw):
    result = old_link(src, dst, *args, **kw)
    if Path(dst).suffix == '.md' and not seen['changed']:
        raw = Path(src).read_bytes()
        header = json.loads(raw[4:].split(b'\n---\n\n', 1)[0])
        seen.update(changed=True, message_id=header['message_id'], ref={'path':str(dst),'sha256':hashlib.sha256(raw).hexdigest()})
        if %r == 'fifo':
            Path(dst).rename(Path(dst).with_suffix('.original'))
            os.mkfifo(dst)
        else: Path(dst).write_bytes(b'changed committed message')
    return result
os.link = linked
""" % damage
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["changed"] and row["state"] == "held", (seen, row)
    assert row["reason"] == "small_change_partial_publication", row
    assert row["partial_publication"] == {"message_id": seen["message_id"], "evidence": seen["ref"]}, row
    assert world.ledger.files() == before


def r9_read_orchestrator(world):
    """Read the actual public page, then record exactly the returned IDs through the existing public method."""
    from tools.hierarchy_mailbox import Mailbox
    mailbox = Mailbox(world.root)
    page = mailbox.inbox("engine/orchestrator", limit=100)
    mailbox.record_read(world.root.parent / "delivery", {"from": "engine/orchestrator", "host": "host-one",
        "session": "engine/orchestrator", "binding_generation": 1}, [r["message"]["message_id"] for r in page["messages"]])
    return page


@pytest.mark.parametrize("window", ["before", "after"])
@pytest.mark.parametrize("artifact", ["step-1.log", "result.json", "claim.json", "process.json"])
def test_r9_retained_job_witnesses_cover_the_actual_publication_boundary(tmp_path, window, artifact):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    page = r9_read_orchestrator(world)
    assert any(r["message"]["type"] == "job_receipt" for r in page["messages"])
    injection = r"""
target = Path(%r); window = %r
old_stat, old_link = os.stat, os.link
seen['changed'] = False
def change():
    if seen['changed']: return
    seen['changed'] = True
    with open(target, 'ab') as stream: stream.write(b'\n')
def inspected(path, *args, **kw):
    info = old_stat(path, *args, **kw)
    if window == 'before':
        frame = sys._getframe(1)
        while frame is not None:
            if frame.f_code.co_name == 'publish' and frame.f_code.co_filename.endswith('hierarchy_mailbox.py'):
                if 'recipient' in frame.f_locals: change()
                break
            frame = frame.f_back
    return info
def linked(src, dst, *args, **kw):
    result = old_link(src, dst, *args, **kw)
    if window == 'after' and Path(dst).suffix == '.md': change()
    return result
os.stat, os.link = inspected, linked
""" % (str(folder / artifact), window)
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["changed"] and row["state"] == "held", (seen, row)
    assert len(world.messages("dispatch")) == (2 if window == "after" else 1)
    if window == "after":
        assert row["partial_publication"]["message_id"].startswith("scr-"), row
        assert row["reason"] == "small_change_receipt_invalid", row


def test_r9_read_only_status_rechecks_recipe_before_delivery_drafts(tmp_path):
    world = DispatchWorld(tmp_path)
    review_result(world, ready_reviewer(world))
    injection = r"""
target = Path(%r)
old_stat = os.stat
seen['changed'] = False
def inspected(path, *args, **kw):
    info = old_stat(path, *args, **kw)
    frame, final = sys._getframe(1), False
    while frame is not None:
        final |= frame.f_code.co_name == 'recheck_jobs'
        frame = frame.f_back
    if str(path) == 'result.json' and final and not seen['changed']:
        seen['changed'] = True
        with open(target, 'ab') as stream: stream.write(b'\n')
    return info
os.stat = inspected
""" % str(world.recipes_path)
    answer, seen = r7_router_probe(world, injection, command="status")
    row = answer["small_changes"][0]
    assert seen["changed"], seen
    assert row["reason"] != "small_change_close_due", row
    assert not any(d["event"].get("status") == "FINAL" or d["event"]["type"] == "delivery" for d in row["drafts"]), row


@pytest.mark.parametrize("optional", ["delivery", "provision"])
def test_r9_absent_inputs_are_witnessed_until_composer_publication(tmp_path, optional):
    world = DispatchWorld(tmp_path)
    injection = """
old_mkdir = os.mkdir
seen['created'] = False
def created(path, *args, **kw):
    if Path(path).name == 'briefs' and not seen['created']:
        seen['created'] = True
        if %r == 'delivery': Path(%r).mkdir(parents=True)
        else: Path(%r).write_text(json.dumps({'initiative':'engine','mailbox_root':%r,'source':%r}))
    return old_mkdir(path, *args, **kw)
os.mkdir = created
""" % (optional, str(world.root.parent / "delivery/reads/engine/orchestrator"),
           str(world.root.parent / "provision.json"), str(world.root), str(ROOT))
    code, answer, seen = r8_compose_probe(world, injection)
    assert seen["created"] and code == 2, (code, answer, seen)
    assert "changed" in answer["error"], answer


def test_r9_each_row_captures_under_its_own_lock_without_other_team_witnesses(tmp_path):
    world = DispatchWorld(tmp_path)
    root = tmp_path / "docs/mailbox"
    root.parent.mkdir()
    endpoints = {"docs/" + name: {} for name in ("front-door", "orchestrator", "root", "router")}
    endpoints.update({"docs/lane/fix": {"kind": "implementer"}, "docs/lane/review0": {"kind": "reviewer"}})
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints, "counterparts": [], "writer_limit": 3})
    for endpoint in endpoints:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    world.workspace.register("docs", mailbox_root=str(root), checkouts=[str(world.checkout)])
    second = SmallChange(world.ledger, request("zz-docs-change", team="docs"))
    second.register()
    second.decide()
    admission = second.admission()
    admission["checks"][0]["recipes_sha256"] = world.recipe_hash
    second.admit(admission)
    injection = r"""
target = Path(%r); first = Path(%r)
old_open = os.open
seen['changed'] = False
def opened(path, *args, **kw):
    value = Path(path)
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / value
    if value == target and not seen['changed']:
        messages = list((first / 'engine/lane').glob('*scw-*.md'))
        assert len(messages) == 1, messages
        messages[0].touch()
        seen['changed'] = True
    return old_open(path, *args, **kw)
os.open = opened
""" % (str(root / "manifest.json"), str(world.root))
    answer, seen = r7_router_probe(world, injection)
    rows = {row["request_id"]: row for row in answer["small_changes"]}
    assert seen["changed"], seen
    assert rows[second.value["id"]]["state"] == "writer_sent", rows
    assert len(list((root / "docs/lane").glob("*scw-*.md"))) == 1


@pytest.mark.parametrize("variant", ["steady", "schema", "python", "path", "env-name", "env-value", "extra", "recipe-kind",
                                     "steps", "boolean", "identity", "prefix", "valid-env", "valid-prefix", "valid-identity"])
def test_r9_recipe_validation_matches_the_public_runner(tmp_path, variant):
    world = DispatchWorld(tmp_path)
    table = world.recipes
    if variant == "schema": table["schema"] = "unexpected/v99"
    if variant == "python": table["python"] = "relative"
    if variant == "path": table["path"] = []
    if variant == "env-name": table["env"] = {"bad-name": "x"}
    if variant == "env-value": table["env"] = {"VALUE": "$unknown"}
    if variant == "extra": table["unexpected"] = True
    if variant == "recipe-kind": table["recipes"]["focused"]["kind"] = "unknown"
    if variant == "steps": table["recipes"]["focused"]["steps"] = []
    if variant == "boolean": table["recipes"]["focused"]["heavy"] = 1
    if variant == "identity":
        table["recipes"]["other"] = {"kind": "commit", "timeout_seconds": 5, "sandbox": "none"}
    if variant == "prefix": table["prefix"] = ["relative"]
    if variant == "valid-env": table["env"] = {"FIXTURE_VALUE": "plain"}
    if variant == "valid-prefix": table["prefix"] = ["/usr/bin/env"]
    if variant == "valid-identity":
        table["recipes"]["other"] = {"kind": "commit", "timeout_seconds": 5, "sandbox": "none"}
        table["identity"] = {"name": "Fixture", "email": "fixture@example.invalid"}
    # Malformed configuration refuses before provenance comparison. A valid changed table reaches that comparison.
    raw = json.dumps(table).encode()
    world.recipes_path.write_bytes(raw)
    script = """import json,sys
sys.path.insert(0,sys.argv[1]); import hierarchy_jobs as jobs
try:
    value=jobs.load_recipes(sys.argv[2]); result={'ok':True}
except (ValueError,OSError,TypeError,KeyError) as error: result={'ok':False,'error':str(error)}
print(json.dumps(result))
"""
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools"), str(world.recipes_path)],
                          env=os.environ.copy(), capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    expected = json.loads(proc.stdout)
    world.dispatch()
    world.finish_writer()
    row = world.dispatch()["small_changes"][0]
    if expected["ok"] and variant == "steady":
        assert row["state"] == "checking", row
    elif expected["ok"]:
        assert (row["state"], row.get("reason")) == ("held", "small_change_recipe_mismatch"), row
    else:
        assert (row["state"], row.get("reason")) == ("held", "small_change_configuration"), row
        assert row["detail"] == expected["error"], (row, expected)


def test_r9_wake_absence_is_rechecked_at_the_final_publication_hook(tmp_path):
    world = DispatchWorld(tmp_path)
    before = world.ledger.files()
    marker = world.root / ".wake-engine%2Forchestrator.lock"
    injection = r"""
old_stat = os.stat
seen['changed'] = False
def inspected(path, *args, **kw):
    info = old_stat(path, *args, **kw)
    frame = sys._getframe(1)
    while frame is not None:
        if (frame.f_code.co_name == 'publish' and frame.f_code.co_filename.endswith('hierarchy_mailbox.py')
                and 'recipient' in frame.f_locals and not seen['changed']):
            Path(%r).write_text('modelled planning turn appeared before commit')
            seen['changed'] = True
            break
        frame = frame.f_back
    return info
os.stat = inspected
""" % str(marker)
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["changed"] and row["state"] == "held" and "changed" in row["detail"], (seen, row)
    assert world.messages() == [] and world.ledger.files() == before
    assert marker.read_text() == "modelled planning turn appeared before commit"


def test_r9_delivery_names_and_values_use_one_captured_listing(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    r9_read_orchestrator(world)
    injection = r"""
old_list = os.listdir
seen['extra'] = 0
def listed(path):
    if not isinstance(path, int):
        frame = sys._getframe(1)
        while frame is not None:
            if frame.f_code.co_name == 'unread_records':
                seen['extra'] += 1
                break
            frame = frame.f_back
    return old_list(path)
os.listdir = listed
"""
    code, answer, seen = r8_compose_probe(world, injection)
    assert code == 0 and answer["ok"] and seen["extra"] == 0, (answer, seen)


def test_r9_witness_rechecks_share_one_parent_walk_per_verification(tmp_path):
    world = DispatchWorld(tmp_path)
    for number in range(12):
        path = world.root.parent / ("notice-%d.md" % number)
        path.write_text("retained notice %d" % number)
        invoke(world.root, "publish", {"message_id": "notice-%d" % number, "from": "engine/root",
            "to": "engine/orchestrator", "host": "host-one", "session": "engine/root", "binding_generation": 1,
            "type": "brief", "body": "notice", "brief": {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}})
    injection = r"""
old_open = os.open
seen['walks'] = {}
def opened(path, flags, *args, **kw):
    frame = sys._getframe(1)
    if path == '/' and frame.f_code.co_name == '_reference_parent' and frame.f_locals['path'] == Path(%r):
        caller = frame.f_back
        while caller is not None:
            if caller.f_code.co_name == 'verify' and caller.f_code.co_filename.endswith('hierarchy_fresh_brief.py'):
                # Keep frames alive so ids cannot be reused across distinct verification calls.
                frames.append(caller)
                key = str(id(caller))
                seen['walks'][key] = seen['walks'].get(key, 0) + 1
                break
            caller = caller.f_back
    return old_open(path, flags, *args, **kw)
frames = []
os.open = opened
""" % str(world.root.parent)
    code, answer, seen = r8_compose_probe(world, injection)
    assert code == 0 and answer["ok"], answer
    assert seen["walks"] and max(seen["walks"].values()) == 1, seen


def test_r9_late_status_change_discards_already_computed_success_drafts(tmp_path):
    world = DispatchWorld(tmp_path)
    review_result(world, ready_reviewer(world))
    injection = r"""
old_stat = os.stat
seen['changed'] = False
def inspected(path, *args, **kw):
    info = old_stat(path, *args, **kw)
    if not seen['changed']:
        frame = sys._getframe(1)
        while frame is not None:
            if (frame.f_code.co_name == 'run' and frame.f_code.co_filename.endswith('hierarchy_small_change_dispatch.py')
                    and frame.f_locals['self'].view.get('drafts')):
                seen['changed'] = True
                with open(%r, 'ab') as stream: stream.write(b'\n')
                break
            frame = frame.f_back
    return info
os.stat = inspected
""" % str(world.recipes_path)
    answer, seen = r7_router_probe(world, injection, command="status")
    row = answer["small_changes"][0]
    assert seen["changed"] and (row["state"], row["reason"]) == ("held", "small_change_recipe_mismatch"), (seen, row)
    assert row["drafts"] == [], row


@pytest.mark.parametrize("name", [".codex", ".claude"])
@pytest.mark.parametrize("field", ["hide", "ro_binds"])
def test_r9_recipe_folder_checks_refuse_private_inputs_before_metadata(tmp_path, name, field):
    """Refuse before private content discovery; only bounded root identity metadata is allowed."""
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    private = world.tmp / "home" / name
    private.mkdir(parents=True)
    config = json.loads(world.recipes_path.read_text())
    config[field] = [str(private)]
    world.recipes_path.write_text(json.dumps(config))
    injection = PRIVATE_ROOT_PROBE + "\nseen.update(roots=_probe_roots, accesses=_probe_accesses)\n"
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert (row["state"], row["reason"], row["detail"]) == ("held", "small_change_configuration", "owner-private host directory is not an input"), row
    assert_private_root_probes(seen["roots"], seen["accesses"])
    assert world.messages("job_request") == [], seen


@pytest.mark.parametrize("name", [".codex", ".claude"])
def test_r9_standalone_verify_refuses_private_paths_before_discovery(tmp_path, name):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    private = tmp_path / "modelled-home" / name
    private.mkdir(parents=True)
    path = private / "retained.md"
    path.write_bytes(Path(world.messages("dispatch")[0]["message"]["brief"]["path"]).read_bytes())
    script = r"""import importlib.util, json, os, pwd, sys
from pathlib import Path
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location('hierarchy_fresh_brief', sys.argv[1])
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=sys.argv[2])
old_stat = os.stat
probes = []
def inspected(path, *args, **kw):
    if not isinstance(path, int) and (Path(sys.argv[4]) == Path(path) or Path(sys.argv[4]) in Path(path).parents):
        probes.append(str(path))
    return old_stat(path, *args, **kw)
os.stat = inspected
try: code = fresh.main(['verify','--path',sys.argv[5],'--sha256',sys.argv[6]])
finally: Path(sys.argv[3]).write_text(json.dumps(probes))
sys.exit(code)
"""
    telemetry = tmp_path / "verify-io.json"
    env = {k:v for k,v in os.environ.items() if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools/hierarchy_fresh_brief.py"),
        str(private.parent), str(telemetry), str(private), str(path), hashlib.sha256(path.read_bytes()).hexdigest()],
        capture_output=True, text=True, env=env, timeout=20)
    assert process.stderr == "", process.stdout + process.stderr
    assert (process.returncode, json.loads(process.stdout)) == (2, {"error":"owner-private host directory is not an input"})
    assert json.loads(telemetry.read_text()) == []


@pytest.mark.parametrize("command", ["dispatch", "verify"])
def test_r9_grouped_directory_open_failure_remains_a_public_refusal(tmp_path, command):
    world = DispatchWorld(tmp_path)
    entry, arguments = ROUTER, ["--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store), "dispatch",
        "--recipes", str(world.recipes_path), "--wait", "0.1", "--evidence-only"]
    if command == "verify":
        world.dispatch()
        brief = world.messages("dispatch")[0]["message"]["brief"]
        entry, arguments = ROOT / "tools/hierarchy_fresh_brief.py", ["verify", "--path", brief["path"], "--sha256", brief["sha256"]]
    before = world.ledger.files(), mailbox_snapshot(world.root)
    script = r"""import importlib.util, json, os, pwd, sys
from pathlib import Path
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location(Path(sys.argv[1]).stem, sys.argv[1])
router = importlib.util.module_from_spec(spec); spec.loader.exec_module(router)
pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=sys.argv[2])
old_open = os.open
seen = False
def opened(path, *args, **kw):
    global seen
    frame = sys._getframe(1)
    if path == '/' and frame.f_code.co_name == '_reference_parent' and not seen:
        caller = frame.f_back
        if caller.f_code.co_name == 'verify' and caller.f_code.co_filename.endswith('hierarchy_fresh_brief.py'):
            seen = True
            raise FileNotFoundError('modelled directory unavailable at recheck')
    return old_open(path, *args, **kw)
os.open = opened
try: code = router.main(sys.argv[4:])
finally: Path(sys.argv[3]).write_text(json.dumps(seen))
sys.exit(code)
"""
    telemetry = tmp_path / "directory-recheck.json"
    env = {k:v for k,v in os.environ.items() if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    process = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(entry), str(tmp_path / "home"),
        str(telemetry), *arguments], env=env,
        capture_output=True, text=True, timeout=20)
    assert process.stderr == "", process.stdout + process.stderr
    assert json.loads(telemetry.read_text()) is True
    assert process.returncode == 2 and json.loads(process.stdout)["error"] == "modelled directory unavailable at recheck", process.stdout
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r9b_committed_route_sync_failure_retains_evidence_without_busy_retry(tmp_path):
    world = DispatchWorld(tmp_path)
    before = world.ledger.files()
    injection = r"""
import errno, hashlib, time
seen.update(committed_event=None, event_syncs=0, publications=0)
old_link, old_sync = os.link, os.fsync
def linked(src, dst, *args, **kw):
    answer = old_link(src, dst, *args, **kw)
    if Path(dst).parent.name == 'events':
        raw = Path(src).read_bytes()
        event = json.loads(raw)
        if event['envelope']['event']['type'] == 'route':
            seen['publications'] += 1
            seen['committed_event'] = {'message_id':event['envelope']['id'],
                'evidence':{'path':str(dst),'sha256':hashlib.sha256(raw).hexdigest()}}
    return answer
def synced(fd):
    committed = seen['committed_event']
    if committed and Path(os.readlink('/proc/self/fd/%d' % fd)) == Path(committed['evidence']['path']).parent:
        seen['event_syncs'] += 1
        raise OSError(errno.EBUSY, 'modelled route directory is busy')
    return old_sync(fd)
# A known publication must escape patient() even when its post-commit error says busy.
# Make the retry budget deterministic; the mutant's next call finds the recorded original receipt.
time.monotonic = lambda: 0.0
os.link, os.fsync = linked, synced
"""
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["event_syncs"] == 1 and seen["publications"] == 1, seen
    assert (row["state"], row.get("reason")) == ("held", "small_change_committed_event"), row
    assert row["partial_publication"] == seen["committed_event"], row
    assert len(world.ledger.files()) == len(before) + 1
    assert len(world.messages("dispatch")) == 1 and world.messages("job_request") == []


# R10: cold registry/source readers and known mailbox publications remain bounded/truthful.
def r10_registry_substitution(world, damage):
    fifo = world.tmp / "r10-registry-fifo"
    os.mkfifo(fifo)
    return r"""
import io
target = Path(router.__file__).parent / 'hierarchy_templates/role-registry.json' if 'router' in globals() else Path(fresh.__file__).parent / 'hierarchy_templates/role-registry.json'
fifo, damage = Path(%r), %r
seen.update(unsafe=False, registry_opens=0, target_reads=0)
old_io, old_fd, old_read = io.open, os.open, os.read
substituted = set()
def actual(path, kw):
    if isinstance(path, int): return None
    value = Path(os.fsdecode(path))
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / value
    return value
def opened(path, mode='r', *args, **kw):
    if actual(path, kw) == target and 'r' in mode:
        seen['registry_opens'] += 1
        seen['unsafe'] = True
        if damage == 'fifo': raise OSError('modelled unsafe registry open intercepted')
    return old_io(path, mode, *args, **kw)
def descriptor(path, flags, *args, **kw):
    if actual(path, kw) == target:
        seen['registry_opens'] += 1
        seen['unsafe'] |= not bool(flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW)
        if damage == 'fifo':
            fd = old_fd(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            substituted.add(fd)
            return fd
    return old_fd(path, flags, *args, **kw)
def consumed(fd, amount):
    if fd in substituted and Path(os.readlink('/proc/self/fd/%%d' %% fd)) == fifo: seen['target_reads'] += 1
    return old_read(fd, amount)
io.open, os.open, os.read = opened, descriptor, consumed
""" % (str(fifo), damage)


@pytest.mark.parametrize("stage", ["writer", "reviewer", "standalone"])
@pytest.mark.parametrize("damage", ["steady", "fifo"])
def test_r10_cold_registry_is_captured_before_any_content_read(tmp_path, stage, damage):
    (tmp_path / ".keep").write_text("R10 modelled registry descriptor substitution; no pinned target mutation\n")
    world = DispatchWorld(tmp_path)
    if stage == "reviewer":
        formal_completed_job(world)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    injection = r10_registry_substitution(world, damage)
    if stage == "standalone":
        code, answer, seen = r8_compose_probe(world, injection)
        assert code == (2 if damage == "fifo" else 0), (answer, seen)
    else:
        answer, seen = r7_router_probe(world, injection)
        row = answer["small_changes"][0]
        assert row["state"] == ("held" if damage == "fifo" else "reviewing" if stage == "reviewer" else "writer_sent"), row
    assert not seen["unsafe"], (answer, seen)
    assert seen["registry_opens"] == 1 and seen["target_reads"] == 0, (answer, seen)
    if damage == "fifo":
        detail = answer["error"] if stage == "standalone" else row["detail"]
        assert "regular file" in detail or "changed" in detail, detail
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def r10_source_io(world):
    return r"""
import builtins, io
target = Path(%r)
seen.update(content_opens=0)
old_io, old_builtin, old_fd = io.open, builtins.open, os.open
def actual(path, kw):
    if isinstance(path, int): return None
    value = Path(os.fsdecode(path))
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd'])) / value
    return value
def opened(original, path, mode='r', *args, **kw):
    if actual(path, kw) == target and 'r' in mode:
        seen['content_opens'] += 1
        raise OSError('modelled unsafe dirty-content reader intercepted')
    return original(path, mode, *args, **kw)
def descriptor(path, flags, *args, **kw):
    if actual(path, kw) == target and not flags & os.O_DIRECTORY:
        seen['content_opens'] += 1
        raise OSError('modelled unsafe dirty-content descriptor intercepted')
    return old_fd(path, flags, *args, **kw)
io.open = lambda path, *args, **kw: opened(old_io, path, *args, **kw)
builtins.open = lambda path, *args, **kw: opened(old_builtin, path, *args, **kw)
os.open = descriptor
""" % str(world.checkout / "app.txt")


def r10_planning_probe(world, injection):
    from tests.integration.test_hierarchy_loop import EMPTY_SWEEP
    child = world.tmp / "r10-modelled-child.py"
    child.write_text("import json, sys\nfrom pathlib import Path\n"
                     "if '--rounds' in sys.argv: Path(%r).write_text(json.dumps(sys.argv))\n" % str(world.tmp / "r10-sweep-args.json") +
                     "if 'status' in sys.argv or 'dispatch' in sys.argv:\n"
                     "    print(json.dumps({'error':'modelled child failure'})); sys.exit(2)\n"
                     "print(json.dumps({'rows':[]} if 'run-open' in sys.argv else %r))\n" % EMPTY_SWEEP)
    state = world.tmp / "r10-loop-state"
    state.mkdir()
    telemetry = world.tmp / "r10-planning-io.json"
    script = """import argparse, importlib.util, json, os, pwd, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location('hierarchy_loop', sys.argv[1])
loop = importlib.util.module_from_spec(spec); spec.loader.exec_module(loop)
user = pwd.getpwuid(os.getuid())
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], sys.argv[3], user.pw_shell))
for key in ('router','jobs','sweep'): loop.TOOLS[key] = Path(sys.argv[2])
seen = {}
""" + injection + """
args = argparse.Namespace(lifecycle=Path(sys.argv[4]), store=Path(sys.argv[5]), recipes=Path(sys.argv[6]),
                          state_dir=Path(sys.argv[7]), max_jobs=None,
                          dispatcher_host_plan=Path(sys.argv[7]).parent/'dispatcher-host-plan.json')
code = loop.one_pass(args, None)[0]
Path(sys.argv[8]).write_text(json.dumps(seen))
sys.exit(code)
"""
    env = {k: v for k, v in os.environ.items()
           if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "tools/hierarchy_loop.py"),
        str(child), str(world.tmp / "home"), str(world.ledger.path), str(world.workspace.store),
        str(world.recipes_path), str(state), str(telemetry)], env=env, capture_output=True, text=True, timeout=40)
    assert p.returncode == 3 and p.stderr == "", p.stdout + p.stderr
    return json.loads(p.stdout.splitlines()[-1]), json.loads(telemetry.read_text())


@pytest.mark.parametrize("command", ["dispatch", "status", "planning"])
@pytest.mark.parametrize("dirty", [False, True])
def test_r10_clean_source_observation_never_opens_dirty_content(tmp_path, command, dirty):
    (tmp_path / ".keep").write_text("R10 clean-source public command boundary; no native work\n")
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    if dirty:
        (world.checkout / "app.txt").write_text("dirty retained checkout\n")
    before = world.ledger.files(), mailbox_snapshot(world.root)
    if command == "planning":
        answer, seen = r10_planning_probe(world, r10_source_io(world))
        steps = {r["step"]: r["state"] for r in answer["steps"]}
        assert steps["sweep"] == "ok" and steps["run_open"] == "ok", answer
    else:
        answer, seen = r7_router_probe(world, r10_source_io(world), command=command)
    row = answer["small_changes"][0]
    assert seen["content_opens"] == 0, (row, seen)
    if dirty:
        assert (row["state"], row.get("reason")) == ("held", "small_change_configuration"), row
        assert row["detail"] == "source does not match packet", row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
    else:
        assert row["state"] == "checking", row
    assert len(world.messages("job_request")) == (1 if command == "dispatch" and not dirty else 0)


@pytest.mark.parametrize("stage", ["writer", "check", "reviewer"])
def test_r10_mailbox_sync_failure_keeps_original_publication_evidence(tmp_path, stage):
    world = DispatchWorld(tmp_path)
    if stage != "writer":
        world.dispatch()
        world.finish_writer()
    if stage == "reviewer":
        world.dispatch()
        world.run_jobs()
    before = world.ledger.files()
    injection = r"""
import hashlib
seen.update(failed=False, original=None)
old_sync = os.fsync
def synced(fd):
    frame = sys._getframe(1)
    if (not seen['failed'] and frame.f_code.co_name == 'sync_directory'
            and frame.f_back.f_code.co_name == 'publish'
            and frame.f_back.f_code.co_filename.endswith('hierarchy_small_change_dispatch.py')):
        record = frame.f_back.f_locals['record']
        seen['original'] = {'message_id':record['message']['message_id'],
            'evidence':{'path':record['path'],'sha256':record['sha256']}}
        seen['failed'] = True
        raise OSError('modelled committed mailbox directory sync failure')
    return old_sync(fd)
os.fsync = synced
"""
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["failed"] and seen["original"], (row, seen)
    assert row["state"] == "held" and row["reason"] == "small_change_partial_publication", row
    assert row["partial_publication"] == seen["original"], row
    assert row["writer_message_present"] is True, row
    assert hashlib.sha256(Path(seen["original"]["evidence"]["path"]).read_bytes()).hexdigest() == seen["original"]["evidence"]["sha256"]
    assert "engine/lane/fix" in answer["planning_exclusions"] if stage == "writer" else True
    assert world.ledger.files() == before
    committed = mailbox_snapshot(world.root)
    # A fresh public recovery uses the original bytes; it cannot send the known assignment again.
    world.dispatch()
    assert mailbox_snapshot(world.root) == committed


def test_r10_cold_planning_does_not_open_the_composition_registry(tmp_path):
    world = DispatchWorld(tmp_path)
    injection = "import hierarchy_fresh_brief as fresh\n" + r10_registry_substitution(world, "fifo")
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer, seen = r10_planning_probe(world, injection)
    assert answer["small_changes"][0]["state"] == "writer_ready", answer
    assert seen == {"unsafe": False, "registry_opens": 0, "target_reads": 0}, seen
    swept = json.loads((world.tmp / "r10-sweep-args.json").read_text())
    assert [swept[n+1] for n, arg in enumerate(swept) if arg == "--skip"] == ["engine/decider", "engine/orchestrator"], swept
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("command", ["dispatch", "status", "planning"])
@pytest.mark.parametrize("kind", ["fifo", "symlink", "directory"])
def test_r10_dirty_special_source_is_refused_without_open(tmp_path, command, kind):
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    app = world.checkout / "app.txt"
    app.rename(world.checkout / "retained-app.original")
    if kind == "fifo": os.mkfifo(app)
    elif kind == "directory": app.mkdir()
    else: app.symlink_to(world.checkout / "retained-app.original")
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer, seen = (r10_planning_probe(world, r10_source_io(world)) if command == "planning"
                    else r7_router_probe(world, r10_source_io(world), command=command))
    row = answer["small_changes"][0]
    assert seen["content_opens"] == 0, (row, seen)
    assert (row["state"], row.get("reason"), row["detail"]) == (
        "held", "small_change_configuration", "source does not match packet"), row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r10_registry_witness_survives_until_writer_publication(tmp_path):
    world = DispatchWorld(tmp_path)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    injection = r"""
target = Path(router.__file__).parent / 'hierarchy_templates/role-registry.json'
seen['changed'] = False
old_stat, old_replace = os.stat, os.replace
class Changed:
    def __init__(self, value): self.value = value
    def __getattr__(self, name):
        value = getattr(self.value, name)
        return value + 1 if name == 'st_mtime_ns' else value
def actual(path, kw):
    if isinstance(path, int): return None
    value = Path(os.fsdecode(path))
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(os.readlink('/proc/self/fd/%d' % kw['dir_fd'])) / value
    return value
def replaced(src, dst, *args, **kw):
    answer = old_replace(src, dst, *args, **kw)
    if actual(dst, {'dir_fd':kw.get('dst_dir_fd')}).parent.name == 'briefs': seen['changed'] = True
    return answer
def inspected(path, *args, **kw):
    answer = old_stat(path, *args, **kw)
    return Changed(answer) if seen['changed'] and actual(path, kw) == target else answer
os.stat, os.replace = inspected, replaced
"""
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert seen["changed"] and row["state"] == "held", (row, seen)
    assert "changed" in row["detail"] and "role-registry.json" in row["detail"], row
    assert world.ledger.files() == before[0]
    after = mailbox_snapshot(world.root)
    # The content-addressed brief was staged before this late input change; no assignment was published.
    assert {k: v for k, v in after.items() if not k.startswith("briefs/")} == before[1]
    assert world.messages("dispatch") == [] and world.messages("job_request") == []


@pytest.mark.parametrize("damage", ["dirty-after", "both-dirty", "missing", "extra", "bool-count", "unequal"])
def test_r12_completed_source_witness_requires_full_clean_equal_observations(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    path = folder / "result.json"
    result = json.loads(path.read_text())
    if damage in {"dirty-after", "both-dirty"}:
        for key in (("before", "after") if damage == "both-dirty" else ("after",)):
            result[key].update(dirty_entries=1, dirty_state_sha256=hashlib.sha256(b"dirty status").hexdigest())
    elif damage == "missing": result["after"].pop("dirty_entries")
    elif damage == "extra": result["after"]["unexpected"] = True
    elif damage == "bool-count": result["after"]["dirty_entries"] = False
    else: result["after"]["dirty_state_sha256"] = hashlib.sha256(b"contradictory clean status").hexdigest()
    path.write_text(json.dumps(result))
    receipt = next(r for r in world.messages("job_receipt") if r["message"]["receipt"]["state"] == "completed")
    rewrite_message(receipt, lambda m: [ref.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        for ref in m["receipt"]["evidence"] if ref["path"] == str(path)])
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ("status", "dispatch"):
        row = world.dispatch(command=command)["small_changes"][0]
        assert (row["state"], row.get("reason")) == ("held", "small_change_receipt_invalid"), row
        assert "source witness" in row["detail"] or "fields" in row["detail"], row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize("planned", [False, True, None])
def test_hostenv_clean_source_actual_git_environment(tmp_path, monkeypatch, planned):
    from types import SimpleNamespace
    import hierarchy_hosts
    import hierarchy_small_change_dispatch as dispatch
    import shutil

    checkout = tmp_path / "checkout"
    checkout.mkdir()
    git(checkout, "init", "-q")
    tracked = checkout / "tracked.txt"
    tracked.write_text("clean\n", encoding="utf-8")
    git(checkout, "add", "tracked.txt")
    git(checkout, "commit", "-qm", "test-owned initial commit")
    revision, tree = git(checkout, "rev-parse", "HEAD"), git(checkout, "rev-parse", "HEAD^{tree}")
    names = set()
    for host in hierarchy_hosts.describe()["hosts"].values():
        names.update(host["billing_variables"])
        names.add(host["session_variable"]["name"])
        names.update(host["session_markers"]["names"])
        names.update(prefix + "FUTURE_MARKER" for prefix in host["session_markers"]["prefixes"])
    # This executable observes its actual inherited environment, then becomes the real Git process.
    real_git = shutil.which("git")
    assert real_git
    binaries = tmp_path / "bin"
    binaries.mkdir()
    evidence = tmp_path / "git-environments.jsonl"
    wrapper = binaries / "git"
    wrapper.write_text("#!" + sys.executable + "\n" + """
import json, os, sys
with open(sys.argv[0] + '.evidence', encoding='utf-8') as stream:
    config = json.load(stream)
with open(config['evidence'], 'a', encoding='utf-8') as stream:
    stream.write(json.dumps({'names': sorted(os.environ), 'unrelated': os.environ.get('TEST_UNRELATED_SETTING'),
                             'optional_locks': os.environ.get('GIT_OPTIONAL_LOCKS')}) + '\\n')
os.execv(config['git'], [config['git'], *sys.argv[1:]])
""", encoding="utf-8")
    wrapper.chmod(0o755)
    wrapper.with_name("git.evidence").write_text(json.dumps({"git": real_git, "evidence": str(evidence)}), encoding="utf-8")
    parent_before = dict(os.environ)
    inherited = {**os.environ, **dict.fromkeys(names, "modelled-value"), "TEST_UNRELATED_SETTING": "retained",
                 "PATH": str(binaries) + os.pathsep + os.environ["PATH"]}
    inherited_before = dict(inherited)
    original_read_env = dispatch.jobs.object_read_env
    def read_env(*, inherit_config=False):
        return original_read_env(inherited, inherit_config=inherit_config)
    monkeypatch.setattr("hierarchy_small_change_dispatch.jobs", SimpleNamespace(**{**vars(dispatch.jobs), "object_read_env": read_env}))
    # Baseline 2103cf22 stripped only these exact billing/session names, not session-marker prefixes.
    legacy_removed = {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                      "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
                      "OPENAI_API_KEY", "CODEX_API_KEY", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID"}
    git_controls = {"GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT", "GIT_NO_REPLACE_OBJECTS", "GIT_NO_LAZY_FETCH",
                    "GIT_PROTOCOL_FROM_USER", "GIT_ALLOW_PROTOCOL"}
    for _ in range(2):
        assert dispatch._clean_source(checkout, planned=planned) == (revision, tree)
    tracked.write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ValueError, match="^source does not match packet$"):
        dispatch._clean_source(checkout, planned=planned)
    tracked.write_text("clean\n", encoding="utf-8")
    assert dispatch._clean_source(checkout, planned=planned) == (revision, tree)
    rows = [json.loads(line) for line in evidence.read_text(encoding="utf-8").splitlines()]
    assert rows
    for row in rows:
        if planned is not False:
            assert not names.intersection(row["names"])
        else:
            assert set(row["names"]) == (set(inherited) | git_controls) - legacy_removed
            assert {"CODEX_CI", "CODEX_SESSION_ID", "CLAUDE_EFFORT", "CLAUDE_CODE_FUTURE_MARKER"} <= set(row["names"])
        assert row["unrelated"] == "retained" and row["optional_locks"] == "0"
        assert "PATH" in row["names"]
    assert inherited == inherited_before and dict(os.environ) == parent_before


@pytest.mark.parametrize("plan_state", ["absent", "present", "unreadable"])
def test_r12_git_environment_uses_every_registry_hosts_declared_policy(tmp_path, plan_state):
    world = DispatchWorld(tmp_path)
    world.dispatch(); world.finish_writer()
    environment = {**os.environ, "HOSTENV_TEST_PLAN_STATE": plan_state}
    injection = r"""
import hierarchy_hosts, hierarchy_fresh_brief, hierarchy_small_change_dispatch as dispatch, subprocess
data=hierarchy_hosts.describe()
data['hosts']['fixture-extra']={**next(iter(data['hosts'].values())),
    'billing_variables':['TEST_EXTRA_BILLING'],'session_variable':{'name':'TEST_EXTRA_SESSION','verified_for_mcp':False},
    'session_markers':{'names':['TEST_EXTRA_MARKER'],'prefixes':['TEST_EXTRA_PREFIX_']}}
hierarchy_hosts.describe=lambda: data
names=set()
for entry in data['hosts'].values():
    names.update(entry['billing_variables']);names.add(entry['session_variable']['name'])
    names.update(entry['session_markers']['names'])
    names.update(prefix+'FUTURE_MARKER' for prefix in entry['session_markers']['prefixes'])
for name in names: os.environ[name]='modelled-test-value'
os.environ['TEST_UNRELATED_SETTING']='retained'
seen.update(git=0,leaked=[],unrelated=True,plan_probes=0)
old_exists=hierarchy_fresh_brief._Operation.exists
# This predicate stub tests selection only. The real decorated failure latch is covered by
# test_hostenv_real_plan_probe_failure_preserves_precommit_state below.
def exists(operation,path):
    if Path(path).name == hierarchy_hosts.PLAN_FILE:
        seen['plan_probes']+=1
        state=os.environ['HOSTENV_TEST_PLAN_STATE']
        if state == 'unreadable': raise PermissionError('modelled unreadable host plan')
        if state == 'present': return True
    return old_exists(operation,path)
hierarchy_fresh_brief._Operation.exists=exists
old_popen=subprocess.Popen
def started(argv,*a,**kw):
    if argv[0]=='git':
        seen['git']+=1
        seen['leaked'].extend(sorted(names & set(kw.get('env',{}))))
        seen['unrelated'] &= kw.get('env',{}).get('TEST_UNRELATED_SETTING')=='retained'
    return old_popen(argv,*a,**kw)
dispatch.subprocess=SimpleNamespace(**{**vars(subprocess),'Popen':started})
"""
    answer, seen = r7_router_probe(world, injection, environ=environment)
    assert seen["plan_probes"] and seen["unrelated"], seen
    if plan_state == "unreadable":
        row = answer["small_changes"][0]
        assert (row["state"], row["reason"]) == ("held", "small_change_configuration"), row
        assert seen["git"] == 0 and seen["leaked"] == []
        return
    assert answer["small_changes"][0]["state"] == "checking", answer
    assert seen["git"], seen
    if plan_state == "absent":
        assert {"CODEX_CI", "CODEX_SESSION_ID", "CLAUDE_EFFORT", "CLAUDE_CODE_FUTURE_MARKER"} <= set(seen["leaked"])
        assert "CODEX_THREAD_ID" not in seen["leaked"]
    else:
        assert seen["leaked"] == []


@pytest.mark.parametrize("fault", ["symlink", "permission-first", "permission-second"])
def test_hostenv_real_plan_probe_failure_preserves_precommit_state(tmp_path, fault):
    from concurrent.futures import ThreadPoolExecutor
    from tests.conftest import symlink_or_skip

    world = DispatchWorld(tmp_path, checks=2)
    world.dispatch()
    world.finish_writer()
    plan = world.root.parent / "host-plan.json"
    if fault == "symlink":
        symlink_or_skip(world.dispatcher_plan, plan)
    environment = {**os.environ, "HOSTENV_PROBE_PATH": str(plan),
                   "HOSTENV_PROBE_FAIL_AT": "2" if fault == "permission-second" else "1", "HOSTENV_PROBE_FAULT": fault}
    injection = r"""
import stat, hierarchy_fresh_brief as fresh, hierarchy_lifecycle as life
probe=fresh._Operation.exists
seen.update(decorated_probe=hasattr(probe,'__wrapped__'),probe_calls=0,directory_syncs=0)
original_os=fresh.os
def lstat(path,*args,**kwargs):
    return plan_metadata(original_os.lstat,path,*args,**kwargs)
def stated(path,*args,**kwargs):
    return plan_metadata(original_os.stat,path,*args,**kwargs)
def plan_metadata(original,path,*args,**kwargs):
    actual = None if isinstance(path,int) else Path(path)
    if actual is not None and not actual.is_absolute() and kwargs.get('dir_fd') is not None:
        actual = Path(original_os.readlink('/proc/self/fd/%d' % kwargs['dir_fd']))/actual
    if actual == Path(os.environ['HOSTENV_PROBE_PATH']):
        seen['probe_calls']+=1
        if (os.environ['HOSTENV_PROBE_FAULT'].startswith('permission-')
                and seen['probe_calls'] == int(os.environ['HOSTENV_PROBE_FAIL_AT'])):
            raise PermissionError('modelled unreadable host plan')
    return original(path,*args,**kwargs)
fresh.os=SimpleNamespace(**{**vars(original_os),'lstat':lstat,'stat':stated})
sync_os=life.os
def fsync(descriptor):
    if stat.S_ISDIR(sync_os.fstat(descriptor).st_mode):
        seen['directory_syncs']+=1
    return sync_os.fsync(descriptor)
life.os=SimpleNamespace(**{**vars(sync_os),'fsync':fsync})
assert fresh._Operation.exists is probe and seen['decorated_probe']
"""
    briefs = world.root.parent / "briefs"
    assert not list(briefs.glob("check-*.md"))
    def snapshot():
        directories = {str(p.relative_to(world.root.parent))
                       for top in (briefs, world.root) for p in top.rglob("*") if p.is_dir()}
        return mailbox_snapshot(world.root), world.ledger.files(), directories
    before = snapshot()
    # Without --evidence-only, the CLI refuses before reaching the probe.
    refused, seen = r7_router_probe(world, injection, evidence_only=False, expect=2, environ=environment)
    assert refused["state"] == "hold" and refused["error"] == (
        "routing requires --evidence-only; the router is configuration-bound and unauthenticated")
    assert seen["decorated_probe"] and seen["probe_calls"] == seen["directory_syncs"] == 0
    assert snapshot() == before
    def dispatch(index):
        return r7_router_probe(world, injection, extra=("--wait", "5"),
                               telemetry=world.tmp / ("hostenv-probe-%d.json" % index), environ=environment)
    # Sequential retries must reach the latch. Concurrent retries may receive the documented busy refusal.
    outcomes = [dispatch(0), dispatch(1)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        concurrent = list(pool.map(dispatch, range(2, 4)))
    outcomes += concurrent
    assert any(answer["small_changes"][0].get("release_validation_error") for answer, _ in concurrent)
    for index, (answer, seen) in enumerate(outcomes):
        row = answer["small_changes"][0]
        assert (row["state"], row["reason"]) == ("held", "small_change_configuration"), row
        assert "route_receipt" not in row and "writer_publication_verified" not in row
        if row.get("detail") == "mailbox writer is busy; inspect an abandoned lock before retrying":
            assert index >= 2
        else:
            assert row.get("release_validation_error"), "the real decorated capture must retain its failed latch"
        assert seen["decorated_probe"]
        assert seen["directory_syncs"] == 0, seen
    assert not list(briefs.glob("check-*.md")), "a precommit refusal must not leave an orphaned check packet"
    assert snapshot() == before


@pytest.mark.parametrize("home_variable", ["CODEX_HOME", "CLAUDE_CONFIG_DIR"])
@pytest.mark.parametrize("kind", ["evidence", "attachment", "recipe", "checkout"])
def test_r12_all_dispatcher_private_inputs_refuse_before_metadata(tmp_path, home_variable, kind):
    """Private content is never discovered; trusted root identity probes share one policy."""
    import shutil
    world = DispatchWorld(tmp_path)
    world.dispatch()
    private = tmp_path / "relocated-host-private"
    private.mkdir()
    extra = ()
    private_record = None
    if kind == "evidence":
        target=private / "evidence.txt";target.write_text("modelled evidence, never credentials")
        world.finish_writer(evidence=[{"path":str(target),"sha256":hashlib.sha256(target.read_bytes()).hexdigest()}])
    elif kind == "attachment":
        record=world.messages("dispatch")[0]; ref=record["message"]["brief"];private_record=record["path"]
        target=private / Path(ref["path"]).name;target.write_bytes(Path(ref["path"]).read_bytes())
        rewrite_message(record,lambda m:m.update(brief={**ref,"path":str(target)}))
    elif kind == "recipe":
        world.finish_writer();target=private / "recipes.json";target.write_bytes(world.recipes_path.read_bytes())
        extra=("--recipes",str(target))
    else:
        world.finish_writer();target=private / "checkout";shutil.copytree(world.checkout,target)
        accepted=next(r for r in world.messages("ack") if r["message"].get("acknowledgment")=="accepted");private_record=accepted["path"]
        rewrite_message(accepted,lambda m:m["readiness"].update(worktree=str(target),scan_workspace=str(target)))
        world.workspace.run("update",{"initiative":"engine","source":"owner","checkouts":[str(target)]})
    injection = ("private=Path(%r);os.environ[%r]=str(private)\n" % (str(private), home_variable)
                 + PRIVATE_ROOT_PROBE + "\nseen.update(roots=_probe_roots, accesses=_probe_accesses)\n")
    # Keep the public router invocation, but expose an argument-stage refusal as well as a row hold.
    script = """import importlib.util,json,os,pwd,sys
from pathlib import Path
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('hierarchy_router',sys.argv[1]);router=importlib.util.module_from_spec(spec);spec.loader.exec_module(router)
pwd.getpwuid=lambda uid:SimpleNamespace(pw_dir=sys.argv[2]);seen={}
""" + injection + """
try: code=router.main(sys.argv[4:])
finally: Path(sys.argv[3]).write_text(json.dumps(seen))
sys.exit(code)
"""
    telemetry=tmp_path / "r12-private-io.json"
    before=world.ledger.files(),mailbox_snapshot(world.root)
    p=subprocess.run([sys.executable,"-I","-B","-c",script,str(ROUTER),str(tmp_path / "home"),str(telemetry),
        "--lifecycle",str(world.ledger.path),"--store",str(world.workspace.store),"dispatch","--recipes",str(world.recipes_path),
        "--evidence-only","--wait","0.1",*extra],env=os.environ.copy(),capture_output=True,text=True,timeout=30)
    assert p.stderr=="" and p.returncode in (0,2),p.stdout+p.stderr
    answer=json.loads(p.stdout);seen=json.loads(telemetry.read_text())
    assert_private_root_probes(seen['roots'], seen['accesses'])
    detail=answer.get('error') if p.returncode==2 else answer['small_changes'][0]['detail']
    expected='owner-private host directory is not an input'
    if private_record is not None:expected='malformed mailbox message: '+private_record+': '+expected
    assert detail==expected,answer
    assert (world.ledger.files(),mailbox_snapshot(world.root))==before


@pytest.mark.parametrize("stage", ["mailbox", "verify", "retained"])
@pytest.mark.parametrize("budget", ["entries", "bytes"])
def test_r12_directory_collection_stops_at_the_budget(tmp_path, stage, budget):
    world=DispatchWorld(tmp_path)
    target=formal_completed_job(world) if stage=='retained' else world.root / 'engine/orchestrator'
    injection=r"""
from types import SimpleNamespace
target=Path(%r);stage=%r;budget=%r
seen.update(collected=0,collections=[]);old_list,old_scan=os.listdir,os.scandir
maximum=10001 if budget=='entries' else 66
def actual(path):return Path(os.readlink('/proc/self/fd/%%d' %% path)) if isinstance(path,int) else Path(path)
def chosen(path):
    if actual(path)!=target:return False
    if stage!='verify':return True
    frame=sys._getframe(1)
    while frame is not None:
        if frame.f_code.co_name=='verify' and frame.f_code.co_filename.endswith('hierarchy_fresh_brief.py'):return True
        frame=frame.f_back
    return False
def names(path):
    count=0
    try:
        yield from old_list(path)
        for n in range(maximum+1):
            count+=1;seen['collected']+=1
            yield '.pending-'+str(n)+('x'*170000 if budget=='bytes' else '')
    finally:seen['collections'].append(count)
class Entries:
    def __init__(self,path):self.values=iter(names(path))
    def __enter__(self):return self
    def __exit__(self,*a):self.values.close();return False
    def __iter__(self):return self
    def __next__(self):return SimpleNamespace(name=next(self.values))
def listed(path):return list(names(path)) if chosen(path) else old_list(path)
def scanned(path):return Entries(path) if chosen(path) else old_scan(path)
os.listdir,os.scandir=listed,scanned
""" % (str(target),stage,budget)
    before=world.ledger.files(),mailbox_snapshot(world.root)
    answer,seen=r7_router_probe(world,injection)
    row=answer['small_changes'][0]
    assert row['state']=='held' and 'directory listing exceeds' in row['detail'],(row,seen)
    assert seen['collections'] and max(seen['collections']) <= (10001 if budget=='entries' else 62),(row,seen)
    assert world.ledger.files()==before[0]
    after=mailbox_snapshot(world.root)
    assert all(after.get(k)==v for k,v in before[1].items())
    assert all(name.startswith('briefs/') for name in after.keys()-before[1].keys())


@pytest.mark.parametrize("stream,command", [('stdout','ls-files'),('stderr','status'),('stdout','status')])
def test_r12_git_output_is_bounded_and_dirty_status_stops_immediately(tmp_path,stream,command):
    world=DispatchWorld(tmp_path);world.dispatch();world.finish_writer()
    injection=r"""
import subprocess
seen.update(read=0,started=False)
old_popen,old_read=subprocess.Popen,os.read;watched={}
def started(argv,*a,**kw):
    if argv[0]=='git' and %r in argv and not seen['started']:
        seen['started']=True
        program="import os; data=b'x'*65536; " + "os.write(%%d,data);"*66
        program=program %% tuple([%d]*66)
        process=old_popen([sys.executable,'-I','-B','-c',program],*a,**kw)
        fd=getattr(process,%r).fileno();info=os.fstat(fd);watched[fd]=(info.st_dev,info.st_ino);return process
    return old_popen(argv,*a,**kw)
def consumed(fd,amount):
    info=os.fstat(fd);selected=watched.get(fd)==(info.st_dev,info.st_ino)
    value=old_read(fd,amount)
    if selected:seen['read']+=len(value)
    return value
subprocess.Popen,os.read=started,consumed
""" % (command,1 if stream=='stdout' else 2,stream)
    before=world.ledger.files(),mailbox_snapshot(world.root)
    answer,seen=r7_router_probe(world,injection)
    row=answer['small_changes'][0]
    assert seen['started'] and row['state']=='held',(row,seen)
    if stream=='stdout' and command=='status':
        assert row['detail']=='source does not match packet' and seen['read']<=1,(row,seen)
    else:
        assert row['detail']=='Git output exceeds byte limit' and seen['read']<=4194305,(row,seen)
    assert (world.ledger.files(),mailbox_snapshot(world.root))==before


def test_r12_git_index_record_count_is_bounded_before_splitting(tmp_path):
    world=DispatchWorld(tmp_path);world.dispatch();world.finish_writer()
    injection=r"""
import subprocess
old_popen=subprocess.Popen
seen['replaced']=False
def started(argv,*a,**kw):
    if argv[0]=='git' and 'ls-files' in argv:
        seen['replaced']=True
        return old_popen([sys.executable,'-I','-B','-c',"import os; os.write(1,bytes([0])*10001)"],*a,**kw)
    return old_popen(argv,*a,**kw)
subprocess.Popen=started
"""
    before=world.ledger.files(),mailbox_snapshot(world.root)
    answer,seen=r7_router_probe(world,injection)
    row=answer['small_changes'][0]
    assert seen['replaced'] and (row['state'],row.get('detail'))==('held','Git output exceeds entry limit'),(row,seen)
    assert (world.ledger.files(),mailbox_snapshot(world.root))==before


R13_PRIVATE_ROW_PROBE = r"""
import json, os, pwd, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
user = pwd.getpwuid(os.getuid())
home = Path(sys.argv[2])
pwd.getpwuid = lambda uid: pwd.struct_passwd((*user[:5], str(home), user.pw_shell))
import hierarchy_router as router
import hierarchy_lifecycle as life
functions = {name: value for name, value in vars(life).items() if callable(value)}
""" + PRIVATE_ROOT_PROBE + r"""
code = router.main(sys.argv[3:])
print(json.dumps({'roots': _probe_roots, 'accesses': _probe_accesses,
    'lifecycle_functions_unchanged': all(getattr(life, name) is value for name, value in functions.items())}))
sys.exit(code)
"""


def r13_private_row(world, command, expect=0):
    """R13 preserves private content refusal while applying the shared identity-probe policy."""
    args = ['--lifecycle', str(world.ledger.path), '--store', str(world.workspace.store),
            command, '--recipes', str(world.recipes_path), '--wait', '0.1']
    if command == 'dispatch':
        args.append('--evidence-only')
    proc = subprocess.run([sys.executable, '-I', '-B', '-c', R13_PRIVATE_ROW_PROBE,
                           str(ROOT/'tools'), str(world.tmp/'home'), *args],
                          capture_output=True, text=True, env=dict(os.environ), timeout=30)
    lines = proc.stdout.splitlines()
    assert len(lines) == 2, (proc.returncode, proc.stdout, proc.stderr)
    answer, observation = map(json.loads, lines)
    assert_private_root_probes(observation['roots'], observation['accesses'])
    assert observation['lifecycle_functions_unchanged'] is True, observation
    assert proc.returncode == expect, answer
    return answer


@pytest.mark.parametrize('command', ['status', 'dispatch'])
def test_r13_private_row_refusal_preserves_state_before_any_metadata(tmp_path, command):
    world = DispatchWorld(tmp_path, private_evidence=True)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer = r13_private_row(world, command)
    assert [(r['request_id'], r['state'], r['reason']) for r in answer['small_changes']] == [
        (world.change.value['id'], 'held', 'small_change_configuration')]
    assert 'owner-private' in answer['small_changes'][0]['detail']
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def r13_second_team(world, identifier):
    root = world.tmp/'docs/mailbox'
    root.parent.mkdir(parents=True)
    endpoints = {'docs/'+name: {} for name in ('front-door', 'orchestrator', 'root', 'router', 'decider')}
    endpoints.update({'docs/lane/fix': {'kind': 'implementer'}, 'docs/lane/review0': {'kind': 'reviewer'}})
    invoke(root, 'init', {'schema': 'aegis.hierarchy-pilot/v1', 'endpoints': endpoints,
                         'counterparts': [], 'writer_limit': 3})
    for endpoint in endpoints:
        invoke(root, 'bind', {'endpoint': endpoint, 'host': 'host-one', 'session': endpoint,
                             'expected_generation': 0})
    world.workspace.register('docs', mailbox_root=str(root), checkouts=[str(world.checkout)])
    change = SmallChange(world.ledger, request(identifier, team='docs'))
    change.plan['plan']['checks'] = ['focused-tests']
    change.register()
    change.decide()
    body = change.admission()
    body['checks'][0]['recipes_sha256'] = world.recipe_hash
    change.admit(body)
    return root, change


@pytest.mark.parametrize('writer_finished', [False, True], ids=['unstarted', 'retained-terminal'])
def test_r13_private_row_does_not_block_other_team_or_erase_accounting(tmp_path, writer_finished):
    world = DispatchWorld(tmp_path, private_evidence=True)
    if writer_finished:
        world.dispatch()
        world.finish_writer()
    other_root, other = r13_second_team(world, 'docs-independent')
    original = world.ledger.status()
    before = world.ledger.files(), mailbox_snapshot(world.root), mailbox_snapshot(other_root)
    answer = r13_private_row(world, 'status')
    rows = {r['request_id']: r for r in answer['small_changes']}
    assert rows[world.change.value['id']]['reason'] == 'small_change_configuration'
    assert rows[other.value['id']]['state'] == 'writer_ready', rows
    assert (world.ledger.files(), mailbox_snapshot(world.root), mailbox_snapshot(other_root)) == before
    answer = r13_private_row(world, 'dispatch')
    rows = {r['request_id']: r for r in answer['small_changes']}
    assert rows[world.change.value['id']]['reason'] == 'small_change_configuration', rows
    assert rows[other.value['id']]['state'] == 'writer_sent', rows
    after = world.ledger.status()
    for key in ('consumed', 'meters', 'current'):
        assert after[key] == original[key]
    assert after['requests'][world.change.value['id']] == original['requests'][world.change.value['id']]
    assert mailbox_snapshot(world.root) == before[1]
    stable = world.ledger.files(), mailbox_snapshot(world.root), mailbox_snapshot(other_root)
    for _ in range(2):
        r13_private_row(world, 'status')
        r13_private_row(world, 'dispatch')
    assert (world.ledger.files(), mailbox_snapshot(world.root), mailbox_snapshot(other_root)) == stable


@pytest.mark.parametrize('damage,error', [
    ('sha256', 'invalid evidence sha256'),
    ('actor', 'role root cannot record small_change_admit'),
])
def test_r13_private_row_quarantine_does_not_bypass_pinned_semantics(tmp_path, damage, error):
    world = DispatchWorld(tmp_path, private_evidence=True)
    path = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    record = json.loads(path.read_text())
    envelope = record['envelope']
    assert envelope['event']['type'] == 'small_change_admit'
    if damage == 'sha256':
        envelope['event']['gates']['capability'][0]['sha256'] = 'malformed'
    else:
        envelope['actor'] = world.ledger.root_actor
    record['event_sha256'] = hashlib.sha256(json.dumps(envelope, sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    path.write_text(json.dumps(record))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ('status', 'dispatch'):
        answer = r13_private_row(world, command, expect=2)
        assert answer['state'] == 'hold' and error in answer['error'], answer
        assert 'small_changes' not in answer
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('damage', ['missing', 'malformed', 'contradictory'])
def test_r14_execution_source_export_is_required_and_bound_to_packet(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    path = folder/'result.json'
    result = json.loads(path.read_text())
    assert result['source_export']['commit'] == world.revision
    assert result['source_export']['tree'] == world.tree
    if damage == 'missing':
        del result['source_export']
    elif damage == 'malformed':
        result['source_export'] = []
    else:
        result['source_export'].update(commit='e'*40, tree='f'*40)
    path.write_text(json.dumps(result))
    r8_refresh_receipt(world, folder)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()['small_changes'][0]
    assert (row['state'], row.get('reason')) == ('held', 'small_change_receipt_invalid'), row
    assert 'source export' in row['detail'], row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.xfail(strict=True, reason="R15: deferred until JOBS-1 public validate_recipes(data) lands")
def test_r14_census_recipe_uses_the_same_public_validation(tmp_path):
    class CensusWorld(DispatchWorld):
        def save_recipes(self):
            self.recipes['census_outside_policy'] = 'ignore'
            super().save_recipes()
    world = CensusWorld(tmp_path)
    assert world.run_jobs()['rows'] == []
    row = world.dispatch()['small_changes'][0]
    assert row['state'] == 'writer_sent', row
    world.finish_writer()
    row = world.dispatch()['small_changes'][0]
    assert row['state'] == 'checking' and len(world.messages('job_request')) == 1, row


@pytest.mark.parametrize('host_kind', ['codex-cli', 'claude-code'])
def test_r14_no_plan_loop_keeps_independent_sweep_on_busy_journal(tmp_path, host_kind):
    from tests.integration.test_hierarchy_loop import World
    class CodexWorld(World):
        def add_role(self, endpoint, host=None, **changes):
            host = host or host_kind
            if host == 'codex-cli':
                changes.setdefault('session', endpoint.replace('/', '-')+'-session')
            return super().add_role(endpoint, host, **changes)
    worlds = []
    for name in ('legacy-sweep', 'loop'):
        directory = tmp_path/name
        directory.mkdir()
        git(directory, 'init', '-q', '-b', 'candidate')
        world = CodexWorld(directory)
        assert not (world.base/'host-plan.json').exists()
        assert invoke(world.root, 'status')['bindings']['pilot/orchestrator']['host'] == host_kind
        world.send('pilot/root', 'pilot/orchestrator', 'independent-root-message')
        (world.ledger.path/'.write.lock').write_text('modelled writer lock')
        worlds.append(world)
    legacy, loop = worlds
    legacy.sweep()
    assert legacy.woken() == ['pilot/orchestrator']
    result = loop.once(expect=3)
    assert next(r['state'] for r in result['steps'] if r['step'] == 'run_open') == 'ok'
    assert next(r['state'] for r in result['steps'] if r['step'] == 'sweep') == 'ok', result
    assert loop.woken() == legacy.woken()


def test_r14_malformed_unscoped_event_between_valid_records_does_not_abort_loop(tmp_path):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    world.ledger.publish(request('before-malformed', team='pilot'))
    world.ledger.event('meter', actor=world.ledger.operator, subject=world.ledger.operator,
                       active_seconds=5, open_since=None)
    world.ledger.publish(request('after-malformed', team='pilot'))
    paths = sorted((world.ledger.path/'events').glob('*.json'))
    records = [json.loads(path.read_text()) for path in paths]
    record = next(r for r in records if r['envelope']['event']['type'] == 'meter')
    record['envelope']['event'] = []
    record['event_sha256'] = hashlib.sha256(json.dumps(record['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    for index, record in enumerate(records):
        if index:
            record['previous'] = hashlib.sha256(json.dumps(records[index-1], sort_keys=True,
                separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        paths[index].write_text(json.dumps(record))
    # No request_id survives in the corrupted event. Do not invent a row or erase
    # possible accounting effects: keep planning unknown while run-open proceeds.
    result = world.once(expect=3)
    assert next(r['state'] for r in result['steps'] if r['step'] == 'run_open') == 'ok'
    assert any(r['kind'] == 'planning_exclusions_unavailable' and r['act'] == 'owner'
               for r in result['holds'])


def modelled_loop_plan(folder):
    """A real validated configuration record in the modelled test home, never a grant."""
    plan = folder/'dispatcher-host-plan.json'
    plan.write_text(json.dumps({'schema': 'aegis.hierarchy-host-plan/v1', 'hierarchy': 'pilot',
        'root': 'codex-cli', 'team': 'claude-code', 'stand_ins': {}, 'config_sha256': 'd'*64}))
    return plan


def activate_loop(world):
    """Modelled opt-in; the external record is configuration, never a role grant."""
    plan = modelled_loop_plan(world.tmp)
    flags = world.flags
    world.flags = lambda: flags()+['--dispatcher-host-plan', str(plan)]
    world.dispatcher_plan = plan
    return world


R15_CONTROLLER_PROBE = R13_PRIVATE_ROW_PROBE.replace(
    'code = router.main(sys.argv[3:])',
    "if sys.argv[3] == 'router':\n    code = router.main(sys.argv[4:])\nelse:\n"
    "    import hierarchy_fresh_brief as fresh\n    code = fresh.main(sys.argv[4:])")


def r15_controller(world, tool, args, expect=0, probe=None):
    """R15/R16/R16b keep private content undiscovered under the shared identity-probe policy."""
    process = subprocess.run([sys.executable, '-I', '-B', '-c', R15_CONTROLLER_PROBE if probe is None else probe,
        str(ROOT/'tools'), str(world.tmp/'home'), tool, *map(str, args)],
        env=dict(os.environ), capture_output=True, text=True, timeout=40)
    assert not process.stderr, process.stderr
    lines = process.stdout.splitlines()
    assert len(lines) == 2, process.stdout
    answer, observation = map(json.loads, lines)
    assert_private_root_probes(observation['roots'], observation['accesses'])
    assert process.returncode == expect, answer
    assert observation['lifecycle_functions_unchanged'], observation
    return answer


@pytest.mark.parametrize('kind', ['evidence', 'paths', 'changed-evidence'])
def test_r15_canonical_row_reference_refusal_is_scoped_for_status_route_and_compose(tmp_path, kind):
    world = Loop(tmp_path)
    world.team('engine'); world.team('docs')
    private = tmp_path/'home/.codex/declared-evidence'
    private.parent.mkdir(parents=True)
    private.write_text('modelled private claim')
    value = request('canonical-refused', paths=[str(private)] if kind == 'paths' else ['/fixture/engine/tests'])
    world.ledger.ready(value)
    world.ledger.intent(value)
    evidence = world.ledger.evidence if kind != 'evidence' else [
        {'path': str(private), 'sha256': hashlib.sha256(private.read_bytes()).hexdigest()}]
    result = {'request_sha256': raw_request(value)['sha256'], 'intent_id': 'attempt-1', 'outcome': 'passed',
              'exit_code': 0, 'source': value['source'], 'evidence': evidence}
    world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request(result), **world.ledger.target(value))
    healthy = world.approved(request('canonical-healthy', team='docs'))
    if kind == 'changed-evidence':
        world.ledger.evidence_path.write_text('changed retained evidence')
    common = ['--lifecycle', world.ledger.path, '--store', world.workspace.store]
    answer = r15_controller(world, 'router', [*common, 'status', '--wait', '0.1'])
    rows = {r['request_id']: r for r in answer['requests']}
    # R16 restores inert canonical evidence: only lexical private declarations hold.
    assert rows[value['id']]['state'] == ('ready' if kind == 'changed-evidence' else 'held'), rows
    assert rows[healthy['id']]['state'] == 'ready', rows
    routed = r15_controller(world, 'router', [*common, 'route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'])
    assert {r['request_id'] for r in routed['routed']} == ({healthy['id'], value['id']}
        if kind == 'changed-evidence' else {healthy['id']}), json.dumps(routed, sort_keys=True)
    composed = r15_controller(world, 'fresh', ['compose', '--root', world.mailboxes['docs'],
        '--initiative', 'docs', '--endpoint', 'docs/orchestrator', '--lifecycle', world.ledger.path])
    text = Path(composed['brief']['path']).read_text()
    assert ('lifecycle_hold' in text) == (kind != 'changed-evidence'), text
    if kind == 'changed-evidence':
        assert 'unverified_evidence' in text, text


@pytest.mark.parametrize('damage', ['endpoint-prefix', 'generation-prefix', 'duplicate-header'])
def test_r15_recovery_checks_exact_brief_identity(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.dispatch(fault='route')
    writer = world.messages('dispatch')[0]
    path = Path(writer['message']['brief']['path'])
    raw = path.read_bytes()
    if damage == 'endpoint-prefix':
        raw = raw.replace(b'Endpoint: engine/lane/fix\n', b'Endpoint: engine/lane/fix-rev\n')
    elif damage == 'generation-prefix':
        raw = raw.replace(b'Target generation: 1\n', b'Target generation: 10\n')
    else:
        raw = raw.replace(b'Endpoint: engine/lane/fix\n', b'Endpoint: engine/lane/fix\nEndpoint: engine/lane/fix-rev\n')
    digest = hashlib.sha256(raw).hexdigest()
    changed = path.with_name('fresh-'+digest+'.md'); changed.write_bytes(raw)
    rewrite_message(writer, lambda m: m['brief'].update(path=str(changed), sha256=digest))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()['small_changes'][0]
    assert (row['state'], row.get('reason')) == ('held', 'small_change_message_conflict'), row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r15_revoked_owned_hold_never_drafts_success(tmp_path):
    world = DispatchWorld(tmp_path)
    formal_completed_job(world)
    world.dispatch()
    reviewer = next(r['message'] for r in world.messages('dispatch') if r['message']['to'].endswith('review0'))
    review_result(world, reviewer)
    world.ledger.event('decision', actor=world.ledger.root_actor, decision='deny', reason='revoked',
                       **world.ledger.target(world.change.value))
    world.ledger.event('disposition', status='HOLD', resolution={'kind': 'blocked', 'owner': 'owner',
        'next_decision': 'reconcile', 'condition': 'revoked', 'evidence': world.ledger.evidence},
        **world.ledger.target(world.change.value))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()['small_changes'][0]
    assert row['state'] == 'owned_hold' and row.get('reason') == 'small_change_revoked', row
    assert not row['drafts'], row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r15_oversized_mailbox_keeps_unrecorded_writer_excluded(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch(fault='route')
    folder = Path(world.messages('dispatch')[0]['path']).parent
    for n in range(10001):
        (folder/('.pending-%05d' % n)).write_bytes(b'')
    before = world.ledger.files()
    result = world.dispatch(command='status')
    assert result['small_changes'][0]['state'] == 'held'
    assert 'engine/lane/fix' in result['planning_exclusions'], result
    assert world.ledger.files() == before


@pytest.mark.parametrize('damage', ['missing', 'changed'])
def test_r15_unread_typed_brief_remains_unverified_without_blocking_compose(tmp_path, damage):
    world = Loop(tmp_path)
    root = world.team('engine')
    path = root.parent/'note.md'; path.write_text('original typed note')
    reference = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    binding = invoke(root, 'status')['bindings']['engine/front-door']
    invoke(root, 'publish', {'message_id': 'typed-note', 'from': binding['endpoint'], 'to': 'engine/orchestrator',
        'host': binding['host'], 'session': binding['session'], 'binding_generation': binding['generation'],
        'type': 'brief', 'body': 'a note', 'brief': reference})
    if damage == 'missing':
        path.unlink()
    else:
        path.write_text('changed typed note')
    answer = r15_controller(world, 'fresh', ['compose', '--root', root, '--initiative', 'engine',
        '--endpoint', 'engine/orchestrator', '--lifecycle', world.ledger.path])
    assert 'unverified_evidence' in Path(answer['brief']['path']).read_text()


def test_r15_readonly_projection_replays_journal_a_constant_number_of_times(tmp_path):
    (tmp_path/'.keep').write_text('R15 journal-read count telemetry\n')
    world = DispatchWorld(tmp_path)
    for n in range(1, 5):
        change = SmallChange(world.ledger, request('independent-'+str(n)))
        change.register(); change.decide()
        body = change.admission(); body['checks'][0]['recipes_sha256'] = world.recipe_hash
        change.admit(body)
    events = len(list((world.ledger.path/'events').glob('*.json')))
    injection = r"""
old_open = os.open
seen['event_opens'] = 0
def opened(path, flags, *args, **kwargs):
    if not flags & os.O_DIRECTORY and str(path).endswith('.json'):
        parent = kwargs.get('dir_fd')
        if parent is not None and Path(os.readlink('/proc/self/fd/%%d' %% parent)) == Path(%r):
            seen['event_opens'] += 1
    return old_open(path, flags, *args, **kwargs)
os.open = opened
""" % str(world.ledger.path/'events')
    result, seen = r7_router_probe(world, injection, command='status')
    assert len(result['small_changes']) == 5
    assert all(r['state'] == 'writer_ready' for r in result['small_changes'])
    assert 0 < seen['event_opens'] <= events*4, (events, seen)


def test_r15_activated_busy_journal_retains_mail_and_owner_planning_hold(tmp_path):
    from tests.integration.test_hierarchy_loop import World, step_states
    world = activate_loop(World(tmp_path))
    world.send('pilot/root', 'pilot/orchestrator', 'retained-root-info')
    lock = world.ledger.path/'.write.lock'; lock.write_text('fixture writer')
    first = world.once(expect=3)
    assert step_states(first) == {'router_status': 'hold', 'route': 'skipped', 'dispatch': 'hold',
                                  'sweep': 'skipped', 'run_open': 'ok'}
    assert any(r['kind'] == 'planning_exclusions_unavailable' and r['act'] == 'owner' for r in first['holds'])
    assert world.woken() == [] and len(world.inbox('pilot/orchestrator')) == 1
    world.status_path.unlink()
    world.once(expect=3)
    assert world.woken() == [] and lock.read_text() == 'fixture writer'
    lock.unlink()
    recovered = world.once()
    assert recovered['holds'] == [] and world.woken() == ['pilot/orchestrator']


def test_r15_private_canonical_row_does_not_stop_activated_sweep(tmp_path):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    value = world.ledger.ready(request('private-canonical', team='pilot'))
    world.ledger.intent(value)
    private = tmp_path/'codex-home/declared-evidence'; private.write_text('modelled private artifact')
    result = {'request_sha256': raw_request(value)['sha256'], 'intent_id': 'attempt-1', 'outcome': 'passed',
              'exit_code': 0, 'source': value['source'], 'evidence': [
                  {'path': str(private), 'sha256': hashlib.sha256(private.read_bytes()).hexdigest()}]}
    world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request(result), **world.ledger.target(value))
    world.send('pilot/root', 'pilot/orchestrator', 'healthy-independent-info')
    result = world.once(expect=3)
    assert next(r['state'] for r in result['steps'] if r['step'] == 'sweep') == 'ok', result
    assert next(r['state'] for r in result['steps'] if r['step'] == 'run_open') == 'ok', result
    assert not any(r['kind'] == 'planning_exclusions_unavailable' for r in result['holds'])
    assert world.woken() == ['pilot/orchestrator']


def test_r15_private_message_does_not_block_other_endpoint_composition(tmp_path, monkeypatch):
    world = Loop(tmp_path); root = world.team('engine')
    folder = root.parent/'private-notes'; folder.mkdir()
    note = folder/'note.md'; note.write_text('modelled private artifact')
    reference = {'path': str(note), 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}
    binding = invoke(root, 'status')['bindings']['engine/orchestrator']
    invoke(root, 'publish', {'message_id': 'private-note', 'from': binding['endpoint'], 'to': 'engine/root',
        'host': binding['host'], 'session': binding['session'], 'binding_generation': binding['generation'],
        'type': 'brief', 'body': 'private claim', 'brief': reference})
    monkeypatch.setenv('CODEX_HOME', str(folder))
    for endpoint in ('engine/router', 'engine/root'):
        answer = r15_controller(world, 'fresh', ['compose', '--root', root, '--initiative', 'engine',
            '--endpoint', endpoint, '--lifecycle', world.ledger.path])
        text = Path(answer['brief']['path']).read_text()
        assert str(note) not in text
        if endpoint == 'engine/root':
            assert 'message_hold' in text


def test_r15_correlated_malformed_row_does_not_hide_healthy_canonical_work(tmp_path):
    world = Loop(tmp_path); world.team('engine'); world.team('docs')
    bad = world.ledger.ready(request('correlated-malformed'))
    world.ledger.intent(bad); world.ledger.terminal(bad)
    healthy = world.approved(request('healthy-after-malformed', team='docs'))
    paths = sorted((world.ledger.path/'events').glob('*.json'))
    records = [json.loads(path.read_text()) for path in paths]
    terminal = next(r for r in records if r['envelope']['event']['type'] == 'terminal')
    terminal['envelope']['event']['result'] = raw_request({'request_sha256': raw_request(bad)['sha256'],
        'intent_id': 'attempt-1', 'outcome': 'passed', 'exit_code': 'invalid',
        'source': bad['source'], 'evidence': world.ledger.evidence})
    terminal['event_sha256'] = hashlib.sha256(json.dumps(terminal['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    for index, record in enumerate(records):
        if index:
            record['previous'] = hashlib.sha256(json.dumps(records[index-1], sort_keys=True,
                separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        paths[index].write_text(json.dumps(record))
    common = ['--lifecycle', world.ledger.path, '--store', world.workspace.store]
    answer = r15_controller(world, 'router', [*common, 'status', '--wait', '0.1'])
    rows = {r['request_id']: r for r in answer['requests']}
    assert rows[bad['id']]['state'] == 'held', rows
    assert rows[healthy['id']]['state'] == 'ready', rows
    answer = r15_controller(world, 'router', [*common, 'route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'])
    assert [r['request_id'] for r in answer['routed']] == [healthy['id']], answer


@pytest.mark.parametrize('damage', ['missing', 'malformed', 'symlink'])
def test_r15_invalid_activation_record_holds_sweep_but_runs_canonical_jobs(tmp_path, damage):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    path = world.dispatcher_plan
    if damage == 'missing':
        path.unlink()
    elif damage == 'malformed':
        path.write_text('{}')
    else:
        original = path.with_name('original-plan.json'); path.rename(original); path.symlink_to(original)
    world.send('pilot/root', 'pilot/orchestrator', 'retained-plan-error')
    result = world.once(expect=3)
    assert next(r['state'] for r in result['steps'] if r['step'] == 'sweep') == 'skipped', result
    assert next(r['state'] for r in result['steps'] if r['step'] == 'run_open') == 'ok', result
    assert world.woken() == [] and len(world.inbox('pilot/orchestrator')) == 1


def test_r15_correlated_unknown_cannot_use_a_later_owned_hold_to_release_planners(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch(); world.finish_writer()
    world.ledger.event('disposition', status='HOLD', resolution={'kind': 'blocked', 'owner': 'owner',
        'next_decision': 'reconcile', 'condition': 'modelled owned hold', 'evidence': world.ledger.evidence},
        **world.ledger.target(world.change.value))
    paths = sorted((world.ledger.path/'events').glob('*.json'))
    records = [json.loads(path.read_text()) for path in paths]
    terminal = next(r for r in records if r['envelope']['event']['type'] == 'terminal')
    result = json.loads(terminal['envelope']['event']['result']['raw'])
    result['exit_code'] = 'invalid'
    terminal['envelope']['event']['result'] = raw_request(result)
    terminal['event_sha256'] = hashlib.sha256(json.dumps(terminal['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    for index, record in enumerate(records):
        if index:
            record['previous'] = hashlib.sha256(json.dumps(records[index-1], sort_keys=True,
                separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        paths[index].write_text(json.dumps(record))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ('status', 'dispatch', 'status'):
        report = world.dispatch(command=command)
        row = report['small_changes'][0]
        assert row['state'] == 'held' and 'UNKNOWN' in row['detail'], row
        assert row['drafts'] == []
        assert set(report['planning_exclusions']) == {'engine/orchestrator', 'engine/decider', 'engine/lane/fix'}
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r15_invalid_plan_registration_is_unknown_never_an_empty_projection(tmp_path):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    change = SmallChange(world.ledger, request(team='pilot'))
    change.register()
    path = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    record = json.loads(path.read_text())
    assert record['envelope']['event']['type'] == 'small_change_plan'
    record['envelope']['event']['participants']['writer']['cid'] = 'unknown-writer'
    record['event_sha256'] = hashlib.sha256(json.dumps(record['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    path.write_text(json.dumps(record))
    world.send('pilot/root', 'pilot/orchestrator', 'retained-invalid-plan')
    result = world.once(expect=3)
    assert next(r['state'] for r in result['steps'] if r['step'] == 'run_open') == 'ok'
    assert any(r['kind'] == 'planning_exclusions_unavailable' for r in result['holds']), result
    assert world.woken() == [] and len(world.inbox('pilot/orchestrator')) == 1


def test_r15_private_checkout_declaration_holds_its_initiative_without_metadata_or_foreign_refusal(tmp_path):
    world = DispatchWorld(tmp_path)
    world.team('docs')
    healthy = world.approved(request('healthy-beside-private-checkout', team='docs'))
    private = tmp_path/'home/.codex/private-checkout'
    private.mkdir(parents=True)
    world.workspace.run('update', {'initiative': 'engine', 'source': 'owner', 'checkouts': [str(private)]})
    common = ['--lifecycle', world.ledger.path, '--store', world.workspace.store]
    answer = r15_controller(world, 'router', [*common, 'status', '--wait', '0.1'])
    assert answer['small_changes'][0]['state'] == 'held'
    assert 'owner-private host directory is not an input' in answer['small_changes'][0]['detail']
    assert next(r for r in answer['requests'] if r['request_id'] == healthy['id'])['state'] == 'ready'
    answer = r15_controller(world, 'router', [*common, 'route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'])
    assert [r['request_id'] for r in answer['routed']] == [healthy['id']]
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer = r15_controller(world, 'router', [*common, 'dispatch', '--recipes', world.recipes_path,
        '--evidence-only', '--wait', '0.1'])
    assert answer['small_changes'][0]['state'] == 'held'
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r15_stored_mailbox_root_is_preflighted_before_constructor_metadata(tmp_path):
    import shutil
    world = Loop(tmp_path)
    world.team('engine'); public = world.team('docs')
    bad = world.approved(request('private-mailbox-root', team='docs'))
    healthy = world.approved(request('healthy-mailbox-root'))
    private = tmp_path/'home/.codex/retained-mailbox'
    private.parent.mkdir(parents=True)
    shutil.copytree(public, private)
    for path in (world.workspace.store/'events').glob('*.json'):
        event = json.loads(path.read_text())
        if event['kind'] == 'register' and event['data']['id'] == 'docs':
            event['data']['mailbox_root'] = str(private)
            path.write_text(json.dumps(event))
    answer = r15_controller(world, 'router', ['--lifecycle', world.ledger.path,
        '--store', world.workspace.store, 'status', '--wait', '0.1'])
    rows = {r['request_id']: r for r in answer['requests']}
    assert rows[bad['id']]['state'] == 'held'
    assert rows[healthy['id']]['state'] == 'ready'


def test_r15_binding_history_is_validated_once_per_captured_endpoint(tmp_path):
    world = DispatchWorld(tmp_path)
    invoke(world.root, 'publish', {'message_id': 'binding-seed', 'from': 'engine/root', 'to': 'engine/orchestrator',
        'host': 'host-one', 'session': 'engine/root', 'binding_generation': 1, 'type': 'info', 'body': 'inert history'})
    record = next(r for r in world.messages() if r['message']['message_id'] == 'binding-seed')
    header, body = Path(record['path']).read_text()[4:].split('\n---\n\n', 1)
    for n in range(60):
        message = json.loads(header); message['message_id'] = 'binding-inert-'+str(n)
        Path(record['path']).with_name('binding-inert-%03d.md' % n).write_text(
            '---\n'+json.dumps(message)+'\n---\n\n'+body)
    injection = r"""
target = Path(%r)
seen['binding_stats'] = 0
original_stat, original_lstat = os.stat, os.lstat
def observed(original, path, *a, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == target:
        seen['binding_stats'] += 1
    return original(path, *a, **kw)
os.stat = lambda path, *a, **kw: observed(original_stat, path, *a, **kw)
os.lstat = lambda path, *a, **kw: observed(original_lstat, path, *a, **kw)
""" % str(world.root/'bindings/engine/root/000001.json')
    answer, seen = r7_router_probe(world, injection, command='status')
    assert answer['small_changes'][0]['state'] == 'writer_ready'
    assert 0 < seen['binding_stats'] <= 20, seen


@pytest.mark.parametrize('phase', ['intent', 'started'])
def test_r15_verified_message_absence_cannot_release_a_writer_with_recorded_effects(tmp_path, phase):
    world = DispatchWorld(tmp_path)
    world.ledger.intent(world.change.value)
    if phase == 'started':
        world.ledger.event('start', actor=world.ledger.operator, intent_id='attempt-1',
                           **world.ledger.target(world.change.value))
    before = world.ledger.files(), mailbox_snapshot(world.root), world.ledger.status()['consumed']
    for command in ('status', 'dispatch'):
        answer = world.dispatch(command=command)
        assert answer['small_changes'][0]['state'] == 'held'
        assert 'engine/lane/fix' in answer['planning_exclusions'], answer
        assert (world.ledger.files(), mailbox_snapshot(world.root), world.ledger.status()['consumed']) == before


@pytest.mark.parametrize('malformed', [False, True], ids=['accepted-id', 'refused-id'])
def test_r15_journal_event_id_collision_refuses_before_canonical_publication(tmp_path, malformed):
    world = Loop(tmp_path); world.team('engine'); world.team('docs')
    bad = world.ledger.ready(request('collision-source'))
    world.ledger.intent(bad); world.ledger.terminal(bad)
    healthy = world.approved(request('collision-target', team='docs'))
    paths = sorted((world.ledger.path/'events').glob('*.json'))
    records = [json.loads(path.read_text()) for path in paths]
    terminal = next(r for r in records if r['envelope']['event']['type'] == 'terminal')
    # This is the documented canonical identity derived from this actual request,
    # not a guessed unrelated message ID or a successful receipt for bad input.
    terminal['envelope']['id'] = 'route-'+raw_request(healthy)['sha256']
    if malformed:
        result = json.loads(terminal['envelope']['event']['result']['raw'])
        result['exit_code'] = 'invalid'; terminal['envelope']['event']['result'] = raw_request(result)
    terminal['event_sha256'] = hashlib.sha256(json.dumps(terminal['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    for n, record in enumerate(records):
        if n:
            record['previous'] = hashlib.sha256(json.dumps(records[n-1], sort_keys=True,
                separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        paths[n].write_text(json.dumps(record))
    before = world.ledger.files(), mailbox_snapshot(world.mailboxes['docs'])
    answer = r15_controller(world, 'router', ['--lifecycle', world.ledger.path, '--store', world.workspace.store,
        'route', '--actor', 'router-1', '--request', healthy['id'], '--evidence-only', '--wait', '0.1'])
    assert answer['routed'] == [], answer
    assert world.inbox('docs') == []
    assert (world.ledger.files(), mailbox_snapshot(world.mailboxes['docs'])) == before


def test_r15_canonical_publication_rechecks_captured_journal_witnesses(tmp_path):
    world = Loop(tmp_path); root = world.team('engine')
    value = world.approved(request('changed-before-delivery'))
    path = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    injection = r"""
manifest, event_path = Path(%r), Path(%r)
fired = False
old_open = os.open
def changed(path, *a, **kw):
    global fired
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if not fired and actual == manifest:
        fired = True
        record = json.loads(event_path.read_text())
        record['envelope']['event'].update(decision='deny', reason='modelled concurrent denial')
        import hashlib
        record['event_sha256'] = hashlib.sha256(json.dumps(record['envelope'], sort_keys=True,
            separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
        event_path.write_text(json.dumps(record))
    return old_open(path, *a, **kw)
os.open = changed
""" % (str(root/'manifest.json'), str(path))
    probe = R15_CONTROLLER_PROBE.replace("if sys.argv[3] == 'router':", injection+"\nif sys.argv[3] == 'router':")
    before = len(world.ledger.files()), mailbox_snapshot(root)
    answer = r15_controller(world, 'router', ['--lifecycle', world.ledger.path, '--store', world.workspace.store,
        'route', '--actor', 'router-1', '--request', value['id'], '--evidence-only', '--wait', '0.1'], probe=probe)
    assert json.loads(path.read_text())['envelope']['event']['decision'] == 'deny'
    assert answer['routed'] == []
    assert (len(world.ledger.files()), mailbox_snapshot(root)) == before


def test_r15_mailbox_capture_bounds_home_queries_independent_of_inert_history(tmp_path):
    world = DispatchWorld(tmp_path)
    invoke(world.root, 'publish', {'message_id': 'home-query-seed', 'from': 'engine/root', 'to': 'engine/orchestrator',
        'host': 'host-one', 'session': 'engine/root', 'binding_generation': 1, 'type': 'info', 'body': 'inert history'})
    injection = """
old_home = pwd.getpwuid
seen['home_queries'] = 0
def queried(uid):
    seen['home_queries'] += 1
    return old_home(uid)
pwd.getpwuid = queried
"""
    first, before = r7_router_probe(world, injection, command='status')
    seed = next(r for r in world.messages() if r['message']['message_id'] == 'home-query-seed')
    header, body = Path(seed['path']).read_text()[4:].split('\n---\n\n', 1)
    for n in range(60):
        message = json.loads(header); message['message_id'] = 'home-inert-'+str(n)
        Path(seed['path']).with_name('home-inert-%03d.md' % n).write_text(
            '---\n'+json.dumps(message)+'\n---\n\n'+body)
    second, after = r7_router_probe(world, injection, command='status')
    assert first['small_changes'][0]['state'] == second['small_changes'][0]['state'] == 'writer_ready'
    assert before['home_queries'] > 0 and after['home_queries'] > 0
    assert after['home_queries']-before['home_queries'] <= 10, (before, after)


@pytest.mark.parametrize('changed', ['home', 'environment', 'uid'])
def test_r15_captured_privacy_policy_change_refuses_before_publication(tmp_path, changed):
    world = DispatchWorld(tmp_path)
    injection = r"""
import hierarchy_router as owning_router
import hierarchy_fresh_brief as fresh
target = Path(router.__file__).parent/'hierarchy_templates/role-registry.json'
seen['changed'] = False
original_open, original_uid = os.open, os.getuid
kind = os.environ['AEGIS_ROUND10_POLICY_KIND']
policy_os = SimpleNamespace(**{**vars(os), 'environ': dict(os.environ)})
router.os = owning_router.os = fresh.os = policy_os
def opened(path, *a, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%d' % kw['dir_fd']))/actual
    if not seen['changed'] and actual == target:
        seen['changed'] = True
        if kind == 'home':
            router._owner_home = owning_router._owner_home = lambda: Path(sys.argv[2]).parent/'changed-home'
        elif kind == 'environment':
            policy_os.environ['CODEX_HOME'] = str(Path(sys.argv[2]).parent/'changed-config')
        else:
            policy_os.getuid = lambda: original_uid()+1
    return original_open(path, *a, **kw)
policy_os.open = opened
"""
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer, seen = r7_router_probe(world, injection, expect=2,
        environ={**os.environ, 'AEGIS_ROUND10_POLICY_KIND': changed})
    assert seen['changed']
    error = ('owner-home policy changed during capture' if changed == 'home'
             else 'host-home configuration changed during capture')
    assert answer == {'state': 'hold', 'execution_enabled': False, 'error': error}
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


# R16 controls use real protocol records and model only OS observations/failures.
def r16_router(world, args, injection=""):
    script = """import json, os, pwd, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
pwd.getpwuid = lambda uid: SimpleNamespace(pw_dir=sys.argv[2])
import hierarchy_router as router
seen = {}
""" + injection + """
try:
    code = router.main(sys.argv[4:])
finally:
    Path(sys.argv[3]).write_text(json.dumps(seen))
sys.exit(code)
"""
    telemetry = world.tmp/'r16-router-io.json'
    process = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(ROOT/'tools'),
        str(world.tmp/'home'), str(telemetry), '--lifecycle', str(world.ledger.path),
        '--store', str(world.workspace.store), *map(str, args)],
        env=dict(os.environ), capture_output=True, text=True, timeout=40)
    assert process.returncode == 0 and process.stderr == '', process.stdout + process.stderr
    return json.loads(process.stdout), json.loads(telemetry.read_text())


@pytest.mark.parametrize('state', ['ready', 'routed', 'closed', 'denied'])
@pytest.mark.parametrize('damage', ['missing', 'changed', 'sparse', 'fifo', 'symlink'])
def test_r16_canonical_evidence_is_inert_for_status_and_route(tmp_path, state, damage):
    world = Loop(tmp_path); root = world.team('engine')
    value = world.ledger.ready(request('inert-canonical'))
    proof = tmp_path/'canonical-evidence.txt'; proof.write_text('original evidence')
    refs = [{'path': str(proof), 'sha256': hashlib.sha256(proof.read_bytes()).hexdigest()}]
    world.ledger.intent(value)
    world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request({
        'request_sha256': raw_request(value)['sha256'], 'intent_id': 'attempt-1', 'outcome': 'passed',
        'exit_code': 0, 'source': value['source'], 'evidence': refs}), **world.ledger.target(value))
    if state == 'routed':
        world.route()
    elif state == 'denied':
        world.ledger.event('decision', actor=world.ledger.root_actor, decision='deny', reason='owner denial',
                           **world.ledger.target(value))
    elif state == 'closed':
        world.ledger.accepted_delivery(value)
        world.ledger.event('disposition', status='FINAL', resolution={'kind': 'complete', 'evidence': refs},
                           **world.ledger.target(value))
    proof.unlink()
    if damage == 'changed': proof.write_text('changed evidence')
    elif damage == 'sparse':
        with proof.open('wb') as stream: stream.truncate(16 * 1024 * 1024)
    elif damage == 'fifo': os.mkfifo(proof)
    elif damage == 'symlink': proof.symlink_to(world.ledger.evidence_path)
    injection = r"""
target = Path(%r)
seen['metadata'], seen['opens'] = 0, 0
original_stat, original_lstat, original_open = os.stat, os.lstat, os.open
def actual(path, kw):
    if isinstance(path, int): return None
    path = Path(os.fsdecode(path))
    if not path.is_absolute() and kw.get('dir_fd') is not None:
        path = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/path
    return path
def stated(path, *a, **kw):
    if actual(path, kw) == target: seen['metadata'] += 1
    return original_stat(path, *a, **kw)
def lstated(path, *a, **kw):
    if actual(path, kw) == target: seen['metadata'] += 1
    return original_lstat(path, *a, **kw)
def opened(path, *a, **kw):
    if actual(path, kw) == target:
        seen['opens'] += 1
        raise OSError('modelled canonical evidence content must stay inert')
    return original_open(path, *a, **kw)
os.stat, os.lstat, os.open = stated, lstated, opened
""" % str(proof)
    before = world.ledger.files(), mailbox_snapshot(root)
    report, seen = r16_router(world, ['status', '--wait', '0.1'], injection)
    assert seen == {'metadata': 0, 'opens': 0}, seen
    assert report['requests'][0]['state'] == state, report
    routed, seen = r16_router(world, ['route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'], injection)
    assert seen == {'metadata': 0, 'opens': 0}, seen
    assert [r['request_id'] for r in routed['routed']] == ([value['id']] if state == 'ready' else []), routed
    if state != 'ready': assert (world.ledger.files(), mailbox_snapshot(root)) == before


def r16_dependency(world, chain='prerequisite', *, evidence_sizes=None):
    ledger = world.ledger
    ledger.event('disposition', status='HOLD', resolution={'kind': 'blocked', 'owner': 'owner',
        'next_decision': 'retained fixture blocker', 'condition': 'not this test', 'evidence': ledger.evidence},
        **ledger.target(world.change.value))
    proof = world.tmp/'dependency-evidence.txt'; proof.write_text('accepted prerequisite evidence')
    reference = {'path': str(proof), 'sha256': hashlib.sha256(proof.read_bytes()).hexdigest()}
    references = [reference]
    if evidence_sizes is not None:
        references = []
        for n, size in enumerate(evidence_sizes):
            path = proof if n == 0 else proof.with_name('dependency-evidence-%d.txt' % n)
            path.write_bytes(b'x' * size)
            references.append({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    prerequisite = request('r16-prerequisite')
    def settle(value, refs):
        intent = 'attempt-' + value['id']
        ledger.intent(value, intent_id=intent)
        ledger.event('terminal', actor=ledger.operator, result=raw_request({
            'request_sha256': raw_request(value)['sha256'], 'intent_id': intent, 'outcome': 'passed',
            'exit_code': 0, 'source': value['source'], 'evidence': refs}), **ledger.target(value))
        ledger.accepted_delivery(value)
        ledger.event('disposition', status='FINAL', resolution={'kind': 'complete', 'evidence': refs},
                     **ledger.target(value))
    def complete(value, refs):
        saved = ledger.evidence
        ledger.evidence = refs
        try:
            ledger.ready(value); settle(value, refs)
        finally:
            ledger.evidence = saved
    if chain == 'authority':
        prerequisite['authority'] = 'r16-authority'
        authority = request('r16-authority', continuation={'members': [{'id': prerequisite['id'],
            'sha256': raw_request(prerequisite)['sha256'], 'phase': prerequisite['phase'],
            'operation': prerequisite['operation']}], 'max_starts': 2, 'expires_at': '2099-01-01T00:00:00Z'})
        complete(authority, [reference])
        # A continuation uses the approved authority rather than another approval.
        ledger.publish(prerequisite); ledger.admit(prerequisite); settle(prerequisite, ledger.evidence)
    else:
        complete(prerequisite, references)
        if chain == 'transitive':
            following = request('r16-following', prerequisites=[prerequisite['id']])
            complete(following, ledger.evidence)
            prerequisite = following
    change = SmallChange(ledger, request('r16-dependent', prerequisites=[prerequisite['id']]))
    change.register(); change.decide()
    admission = change.admission(); admission['checks'][0]['recipes_sha256'] = world.recipe_hash
    change.admit(admission)
    return change, proof


@pytest.mark.parametrize('chain', ['prerequisite', 'transitive', 'authority'])
@pytest.mark.parametrize('damage', ['steady', 'missing', 'symlink', 'changed', 'oversize', 'fifo'])
def test_r16_dependency_evidence_is_consumed_with_a_bound_before_dispatch(tmp_path, chain, damage):
    world = DispatchWorld(tmp_path)
    change, proof = r16_dependency(world, chain)
    if damage != 'steady':
        proof.unlink()
        if damage == 'symlink': proof.symlink_to(world.ledger.evidence_path)
        elif damage == 'changed': proof.write_text('changed prerequisite evidence')
        elif damage == 'oversize':
            with proof.open('wb') as stream: stream.truncate(2 * 1024 * 1024)
        elif damage == 'fifo': os.mkfifo(proof)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ('status', 'dispatch', 'status', 'dispatch'):
        answer = world.dispatch(command=command)
        row = next(r for r in answer['small_changes'] if r['request_id'] == change.value['id'])
        if damage == 'steady':
            assert row['state'] == ('writer_ready' if command == 'status' and not world.messages('dispatch') else 'writer_sent'), row
        else:
            assert (row['state'], row.get('reason')) == ('held', 'small_change_configuration'), row
            if damage == 'symlink':
                assert row['detail'] == 'symlink paths are not supported: ' + str(proof), row
            else:
                assert str(proof) in row['detail'] or 'evidence' in row['detail'], row
            assert world.messages('dispatch') == [] and world.messages('job_request') == []
            assert row.get('route_receipt') is None, row
            assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r16_changed_captured_dependency_is_rechecked_before_writer_publication(tmp_path):
    world = DispatchWorld(tmp_path)
    change, proof = r16_dependency(world)
    injection = r"""
original_open = os.open
registry = Path(router.__file__).parent/'hierarchy_templates/role-registry.json'
seen['changed'] = False
def opened(path, *a, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == registry and not seen['changed']:
        seen['changed'] = True
        Path(%r).write_text('modelled dependency changed after capture')
    return original_open(path, *a, **kw)
os.open = opened
""" % str(proof)
    journal = world.ledger.files()
    answer, seen = r7_router_probe(world, injection)
    row = next(r for r in answer['small_changes'] if r['request_id'] == change.value['id'])
    assert seen['changed'], seen
    assert (row['state'], row.get('reason')) == ('held', 'small_change_configuration'), row
    assert world.messages('dispatch') == [] and world.messages('job_request') == []
    assert world.ledger.files() == journal


R16_WINDOWS_DEFAULTS = r"""
import ctypes
from types import SimpleNamespace
class WindowsOS:
    name = 'nt'
    def __getattr__(self, name): return getattr(os, name)
router.os = WindowsOS()
def profile(window, identifier, token, flags, buffer):
    assert identifier == 0x28
    buffer.value = str(home)
    return 0
ctypes.windll = SimpleNamespace(shell32=SimpleNamespace(SHGetFolderPathW=profile))
"""


@pytest.mark.parametrize('folder', ['.codex', '.claude'])
@pytest.mark.parametrize('entry', ['router', 'fresh'])
def test_r16_windows_defaults_refuse_private_references_before_metadata(tmp_path, monkeypatch, folder, entry):
    for variable in ('CODEX_HOME', 'CLAUDE_CONFIG_DIR'): monkeypatch.delenv(variable, raising=False)
    world = Loop(tmp_path); root = world.team('engine')
    private = tmp_path/'home'/folder/'proof.txt'; private.parent.mkdir(parents=True)
    private.write_text('modelled Windows owner artifact; never credentials')
    value = world.ledger.ready(request('windows-default', paths=[str(private)]))
    probe = R15_CONTROLLER_PROBE.replace("if sys.argv[3] == 'router':", R16_WINDOWS_DEFAULTS+"\nif sys.argv[3] == 'router':")
    before = world.ledger.files(), mailbox_snapshot(root)
    if entry == 'router':
        answer = r15_controller(world, entry, ['--lifecycle', world.ledger.path, '--store', world.workspace.store, 'status'], probe=probe)
        row = next(r for r in answer['requests'] if r['request_id'] == value['id'])
        assert (row['state'], row.get('reason')) == ('held', 'reference_unavailable'), row
        assert row['detail'] == 'owner-private host directory is not an input', row
        assert (world.ledger.files(), mailbox_snapshot(root)) == before
    else:
        answer = r15_controller(world, entry, ['compose', '--root', root, '--initiative', 'engine',
            '--endpoint', 'engine/orchestrator', '--lifecycle', world.ledger.path], probe=probe)
        assert 'lifecycle_hold' in Path(answer['brief']['path']).read_text()
        assert world.ledger.files() == before[0]


def test_r16_committed_canonical_failure_reports_evidence_and_continues_other_rows(tmp_path):
    world = Loop(tmp_path); world.team('engine'); world.team('docs')
    first = world.approved(request('a-committed'))
    second = world.approved(request('z-independent', team='docs'))
    injection = r"""
import errno, hashlib
seen.update(records=[], failed_syncs=0)
original_link, original_sync = os.link, os.fsync
def linked(src, dst, *a, **kw):
    result = original_link(src, dst, *a, **kw)
    if Path(dst).parent.name == 'events':
        raw = Path(src).read_bytes(); record = json.loads(raw)
        if record['envelope']['event']['type'] == 'route':
            seen['records'].append({'message_id':record['envelope']['id'],
                'evidence':{'path':str(dst),'sha256':hashlib.sha256(raw).hexdigest()}})
    return result
def synced(fd):
    if seen['records'] and not seen['failed_syncs'] and Path(os.readlink('/proc/self/fd/%d' % fd)) == Path(seen['records'][0]['evidence']['path']).parent:
        seen['failed_syncs'] += 1
        raise OSError(errno.EIO, 'modelled canonical post-commit sync failure')
    return original_sync(fd)
os.link, os.fsync = linked, synced
"""
    answer, seen = r16_router(world, ['route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'], injection)
    assert seen['failed_syncs'] == 1 and len(seen['records']) == 2, seen
    assert [r['request_id'] for r in answer['routed']] == [second['id']], answer
    row = next(r for r in answer['requests'] if r['request_id'] == first['id'])
    assert (row['state'], row.get('reason')) == ('held', 'delivery_error'), row
    assert row['partial_publication'] == seen['records'][0], row
    for item in seen['records']:
        assert hashlib.sha256(Path(item['evidence']['path']).read_bytes()).hexdigest() == item['evidence']['sha256']
    assert len(world.inbox('engine')) == len(world.inbox('docs')) == 1
    before = world.ledger.files(), {t: mailbox_snapshot(r) for t, r in world.mailboxes.items()}
    assert world.route()['routed'] == []
    assert world.ledger.files() == before[0]
    assert {t: mailbox_snapshot(r) for t, r in world.mailboxes.items()} == before[1]


@pytest.mark.parametrize('sizes', [[1048577], [600000, 600000]], ids=['one-file', 'aggregate'])
def test_r16_consumed_dependency_budget_refuses_before_content_open(tmp_path, sizes):
    # R17 supersedes the aggregate 1 MiB hold: producer-valid references proceed.
    world = DispatchWorld(tmp_path)
    change, proof = r16_dependency(world, evidence_sizes=sizes)
    target = proof if len(sizes) == 1 else proof.with_name('dependency-evidence-1.txt')
    injection = r"""
target = Path(%r)
seen['opens'] = 0
original_open = os.open
def opened(path, *a, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == target:
        seen['opens'] += 1
    return original_open(path, *a, **kw)
os.open = opened
""" % str(target)
    for command in ('status', 'dispatch'):
        answer, seen = r7_router_probe(world, injection, command=command)
        row = next(r for r in answer['small_changes'] if r['request_id'] == change.value['id'])
        assert row['state'] == ('writer_ready' if command == 'status' else 'writer_sent'), row
        assert seen['opens'] == 1, seen
        assert len(world.messages('dispatch')) == (0 if command == 'status' else 1)


@pytest.mark.parametrize('state', ['routed', 'closed', 'denied'])
def test_r16_private_canonical_evidence_never_overrides_settled_state(tmp_path, state):
    world = Loop(tmp_path); root = world.team('engine')
    value = world.ledger.ready(request('settled-private'))
    if state == 'routed': world.route()
    private = tmp_path/'home/.codex/settled-evidence.txt'
    private.parent.mkdir(parents=True); private.write_text('modelled inert private evidence')
    refs = [{'path': str(private), 'sha256': hashlib.sha256(private.read_bytes()).hexdigest()}]
    world.ledger.intent(value)
    world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request({
        'request_sha256': raw_request(value)['sha256'], 'intent_id': 'attempt-1', 'outcome': 'passed',
        'exit_code': 0, 'source': value['source'], 'evidence': refs}), **world.ledger.target(value))
    if state == 'closed':
        world.ledger.accepted_delivery(value)
        world.ledger.event('disposition', status='FINAL', resolution={'kind': 'complete', 'evidence': world.ledger.evidence},
                           **world.ledger.target(value))
    elif state == 'denied':
        world.ledger.event('decision', actor=world.ledger.root_actor, decision='deny', reason='denied',
                           **world.ledger.target(value))
    before = world.ledger.files(), mailbox_snapshot(root)
    common = ['--lifecycle', world.ledger.path, '--store', world.workspace.store]
    report = r15_controller(world, 'router', [*common, 'status', '--wait', '0.1'])
    assert report['requests'][0]['state'] == state, report
    routed = r15_controller(world, 'router', [*common, 'route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'])
    assert routed['routed'] == [] and routed['requests'][0]['state'] == state, routed
    assert (world.ledger.files(), mailbox_snapshot(root)) == before


@pytest.mark.parametrize('unavailable', [False, True])
def test_r16_modelled_windows_profile_lookup_has_a_positive_control_and_fails_closed(tmp_path, monkeypatch, unavailable):
    for variable in ('CODEX_HOME', 'CLAUDE_CONFIG_DIR'): monkeypatch.delenv(variable, raising=False)
    world = Loop(tmp_path); root = world.team('engine')
    world.approved(request('windows-public'))
    injection = R16_WINDOWS_DEFAULTS.replace('return 0', 'return 1') if unavailable else R16_WINDOWS_DEFAULTS
    probe = R15_CONTROLLER_PROBE.replace("if sys.argv[3] == 'router':", injection+"\nif sys.argv[3] == 'router':")
    before = world.ledger.files(), mailbox_snapshot(root)
    answer = r15_controller(world, 'router', ['--lifecycle', world.ledger.path, '--store', world.workspace.store,
        'status', '--wait', '0.1'], expect=2 if unavailable else 0, probe=probe)
    if unavailable:
        assert answer['state'] == 'hold' and answer['error'] == "cannot determine owner's home folder", answer
    else:
        assert answer['requests'][0]['state'] == 'ready', answer
    assert (world.ledger.files(), mailbox_snapshot(root)) == before


@pytest.mark.parametrize('damage', ['steady', 'plan', 'brief', 'missing'])
def test_r16b_unverified_original_writer_publication_retains_lane_custody(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    original = world.dispatch()
    assert original['small_changes'][0]['writer_publication_verified'] is True, original
    assert 'engine/lane/fix' not in original['planning_exclusions'], original
    writer = world.messages('dispatch')[0]
    if damage == 'plan':
        body = json.loads(writer['message']['body']); body['plan_sha256'] = 'e' * 64
        path = Path(writer['path']); header, _body = path.read_text()[4:].split('\n---\n\n', 1)
        path.write_text('---\n'+header+'\n---\n\n'+json.dumps(body))
    elif damage == 'brief':
        Path(writer['message']['brief']['path']).write_text('changed original publication')
    elif damage == 'missing':
        Path(writer['path']).unlink()
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ('status', 'dispatch', 'status'):
        report = world.dispatch(command=command)
        row = report['small_changes'][0]
        assert bool(row.get('route_receipt')) == (damage == 'steady'), row
        assert ('engine/lane/fix' in report['planning_exclusions']) == (damage != 'steady'), report
        assert row['state'] == ('writer_sent' if damage == 'steady' else 'held'), row
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before
    report, _seen = r10_planning_probe(world, '')
    arguments = json.loads((tmp_path/'r10-sweep-args.json').read_text())
    skips = [arguments[n+1] for n, word in enumerate(arguments[:-1]) if word == '--skip']
    assert ('engine/lane/fix' in skips) == (damage != 'steady'), (report, arguments)


@pytest.mark.parametrize('depth', [80, 1200])
def test_r16b_nested_host_plan_is_a_bounded_planning_hold_and_run_open_continues(tmp_path, depth):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    world.dispatcher_plan.write_text('[' * depth + '0' + ']' * depth)
    world.send('pilot/root', 'pilot/orchestrator', 'retained-nested-plan')
    report = world.once(expect=3)
    states = {r['step']: r['state'] for r in report['steps']}
    assert states['dispatch'] == 'hold' and states['sweep'] == 'skipped' and states['run_open'] == 'ok', report
    assert any(r['kind'] == 'planning_exclusions_unavailable' and 'input nesting exceeds 64 levels' in str(r['detail'])
               for r in report['holds']), report
    assert world.woken() == [] and len(world.inbox('pilot/orchestrator')) == 1


@pytest.mark.parametrize('depth', [80, 1200])
def test_r16b_nested_mailbox_header_holds_only_its_team_and_independent_route_progresses(tmp_path, depth):
    world = Loop(tmp_path); root = world.team('engine'); world.team('docs')
    bad = world.approved(request('a-nested-mailbox'))
    good = world.approved(request('z-healthy-mailbox', team='docs'))
    sent = invoke(root, 'publish', {'message_id': 'nested-note', 'from': 'engine/root', 'to': 'engine/orchestrator',
        'host': 'host-one', 'session': 'engine-root', 'binding_generation': 1, 'type': 'info', 'body': 'retained note'})
    path = Path(sent['path']); header, body = path.read_text()[4:].split('\n---\n\n', 1)
    path.write_text('---\n'+header[:-1]+',"unexpected":'+'['*depth+'0'+']'*depth+'}\n---\n\n'+body)
    before = world.ledger.files(), mailbox_snapshot(root)
    answer, _seen = r16_router(world, ['status', '--wait', '0.1'])
    row = next(r for r in answer['requests'] if r['request_id'] == bad['id'])
    assert (row['state'], row.get('reason')) == ('held', 'team_mailbox_unreadable'), row
    assert 'input nesting exceeds 64 levels' in row['detail'], row
    assert (world.ledger.files(), mailbox_snapshot(root)) == before
    routed, _seen = r16_router(world, ['route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'])
    assert [r['request_id'] for r in routed['routed']] == [good['id']], routed
    assert len(world.inbox('docs')) == 1 and mailbox_snapshot(root) == before[1]


@pytest.mark.parametrize('group', [None, False, True, 0, 1.5, '1'])
def test_r16b_present_process_group_is_exact_even_with_stop_confirmation(tmp_path, group):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    path = folder/'process.json'; process = json.loads(path.read_text()); process['group'] = group
    path.write_text(json.dumps(process))
    assert json.loads((folder/'result.json').read_text())['process_stopped_confirmed'] is True
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ('status', 'dispatch', 'status'):
        row = world.dispatch(command=command)['small_changes'][0]
        assert (row['state'], row.get('reason')) == ('held', 'small_change_receipt_invalid'), row
        assert 'invalid job process group' in row['detail'], row
        assert len(world.messages('dispatch')) == 1
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('name', ['step-01.log', 'step-+1.log', 'step-0.log', 'step-1.txt', 'step-01.out'])
def test_r16b_step_artifacts_have_canonical_one_to_one_producer_names(tmp_path, name):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    if name.endswith('.log'):
        (folder/'step-1.log').rename(folder/name)
    else:
        (folder/name).write_text('unlisted noncanonical artifact')
    receipt = next(r for r in world.messages('job_receipt') if r['message']['receipt']['state'] == 'completed')
    from tools.hierarchy_jobs import Job
    job = Job(world.workspace.store, {'id': 'engine'}, world.messages('job_request')[0]['message'])
    rewrite_message(receipt, lambda m: m['receipt'].update(evidence=job.evidence()))
    r8_refresh_receipt(world, folder)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()['small_changes'][0]
    assert (row['state'], row.get('reason')) == ('held', 'small_change_receipt_invalid'), row
    assert 'completed job artifacts differ from admitted recipe' in row['detail'], row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('folder', ['.codex', '.claude'])
def test_r16b_nested_plan_scope_refuses_before_private_metadata(tmp_path, folder):
    world = Loop(tmp_path); world.team('engine')
    change = SmallChange(world.ledger); change.register()
    private = tmp_path/'home'/folder/'scope'; private.mkdir(parents=True)
    path = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    record = json.loads(path.read_text()); proposal = json.loads(record['envelope']['event']['proposal']['raw'])
    proposal['plan']['path_scopes'] = [[str(private)]]
    record['envelope']['event']['proposal'] = raw_request(proposal)
    record['event_sha256'] = hashlib.sha256(json.dumps(record['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    path.write_text(json.dumps(record))
    before = world.ledger.files(), mailbox_snapshot(world.mailboxes['engine'])
    answer = r15_controller(world, 'router', ['--lifecycle', world.ledger.path, '--store', world.workspace.store,
        'status', '--wait', '0.1'], expect=2)
    assert answer['state'] == 'hold' and answer['source'] == 'journal', answer
    assert (world.ledger.files(), mailbox_snapshot(world.mailboxes['engine'])) == before


@pytest.mark.parametrize('folder', ['.codex', '.claude'])
def test_r16b_empty_mailbox_checkpoint_is_captured_before_any_private_metadata(tmp_path, folder):
    world = Loop(tmp_path); root = world.team('engine'); world.team('docs')
    bad = world.approved(request('a-private-checkpoint'))
    good = world.approved(request('z-independent-checkpoint', team='docs'))
    public = root.parent/'handoff.md'; public.write_text('public handoff')
    checkpoint = {'outgoing_stopped': True, 'sources': [], 'lease_refs': [], 'completed_checks': [],
        'pending_message_ids': [], 'last_acknowledgment_ids': [],
        'briefs': [{'path': str(public), 'sha256': hashlib.sha256(public.read_bytes()).hexdigest()}]}
    invoke(root, 'bind', {'endpoint': 'engine/router', 'host': 'host-one', 'session': 'engine-router-2',
                         'expected_generation': 1, 'checkpoint': checkpoint})
    private = tmp_path/'home'/folder/'handoff.md'; private.parent.mkdir(parents=True)
    private.write_text('modelled owner-private handoff, never credentials')
    path = root/'bindings/engine/router/000002.json'
    record = json.loads(path.read_text())
    record['checkpoint']['briefs'] = [{'path': str(private), 'sha256': hashlib.sha256(private.read_bytes()).hexdigest()}]
    record['checkpoint_sha256'] = hashlib.sha256(json.dumps(record['checkpoint'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    path.write_text(json.dumps(record))
    before = world.ledger.files(), mailbox_snapshot(root)
    common = ['--lifecycle', world.ledger.path, '--store', world.workspace.store]
    report = r15_controller(world, 'router', [*common, 'status', '--wait', '0.1'])
    row = next(r for r in report['requests'] if r['request_id'] == bad['id'])
    assert (row['state'], row.get('reason')) == ('held', 'team_mailbox_unreadable'), row
    assert (world.ledger.files(), mailbox_snapshot(root)) == before
    routed = r15_controller(world, 'router', [*common, 'route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'])
    assert [r['request_id'] for r in routed['routed']] == [good['id']], routed
    assert len(world.inbox('docs')) == 1 and mailbox_snapshot(root) == before[1]


def test_r16b_canonical_status_rechecks_captured_binding_witnesses(tmp_path):
    world = Loop(tmp_path); root = world.team('engine')
    world.approved(request('binding-changes-during-status'))
    injection = r"""
sender = Path(%r)
recipient = Path(%r)
seen['changed'] = False
original_open = os.open
def opened(path, *a, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == recipient and not seen['changed']:
        seen['changed'] = True
        record = json.loads(sender.read_text()); record['session'] = 'changed-captured-session'
        sender.write_text(json.dumps(record))
    return original_open(path, *a, **kw)
os.open = opened
""" % (str(root/'bindings/engine/router/000001.json'), str(root/'bindings/engine/orchestrator/000001.json'))
    before = world.ledger.files()
    answer, seen = r16_router(world, ['status', '--wait', '0.1'], injection)
    assert seen['changed'], seen
    row = answer['requests'][0]
    assert (row['state'], row.get('reason')) == ('held', 'team_mailbox_unreadable'), row
    assert 'captured attachment identity/content metadata changed' in row['detail'], row
    assert world.ledger.files() == before and world.inbox('engine') == []


def test_r16b_retained_json_breadth_is_bounded_before_recursive_schema_consumers(tmp_path):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    path = folder/'result.json'
    path.write_text('[' + '0,' * 1048576 + '0]')
    receipt = next(r for r in world.messages('job_receipt') if r['message']['receipt']['state'] == 'completed')
    rewrite_message(receipt, lambda m: [r.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                                      for r in m['receipt']['evidence'] if r['path'] == str(path)])
    before = world.ledger.files(), mailbox_snapshot(world.root)
    row = world.dispatch()['small_changes'][0]
    assert (row['state'], row.get('reason')) == ('held', 'small_change_receipt_invalid'), row
    assert 'input structure exceeds node limit' in row['detail'], row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('folder', ['.codex', '.claude'])
@pytest.mark.parametrize('position', ['value', 'key'])
def test_r16b_standalone_verify_preflights_nested_string_values(tmp_path, folder, position):
    world = Loop(tmp_path); root = world.team('engine')
    answer = r15_controller(world, 'fresh', ['compose', '--root', root, '--initiative', 'engine',
        '--endpoint', 'engine/orchestrator', '--lifecycle', world.ledger.path])
    private = tmp_path/'home'/folder/'future-input'; private.parent.mkdir(parents=True)
    private.write_text('modelled private value, never credentials')
    lines = Path(answer['brief']['path']).read_text().splitlines()
    n = next(i for i, line in enumerate(lines) if line.startswith('- '))
    entry = json.loads(lines[n][2:])
    entry['nested_scope'] = [[[str(private)]]] if position == 'value' else [{str(private): 'inert string'}]
    lines[n] = '- ' + json.dumps(entry)
    raw = ('\n'.join(lines)+'\n').encode()
    path = root.parent/'nested-input.md'; path.write_bytes(raw)
    report = r15_controller(world, 'fresh', ['verify', '--path', path,
        '--sha256', hashlib.sha256(raw).hexdigest()], expect=2)
    assert report['error'] == 'owner-private host directory is not an input', report


def test_r16b_captured_store_private_mailbox_declaration_holds_only_its_team_during_route(tmp_path):
    import shutil
    world = Loop(tmp_path)
    world.team('engine'); public = world.team('docs')
    bad = world.approved(request('private-declared-mailbox', team='docs'))
    good = world.approved(request('healthy-declared-mailbox'))
    private = tmp_path/'home/.claude/retained-mailbox'
    private.parent.mkdir(parents=True)
    shutil.copytree(public, private)
    for path in (world.workspace.store/'events').glob('*.json'):
        event = json.loads(path.read_text())
        if event['kind'] == 'register' and event['data']['id'] == 'docs':
            event['data']['mailbox_root'] = str(private)
            path.write_text(json.dumps(event))
    before = mailbox_snapshot(public), mailbox_snapshot(private)
    report = r15_controller(world, 'router', ['--lifecycle', world.ledger.path, '--store', world.workspace.store,
        'route', '--actor', 'router-1', '--evidence-only', '--wait', '0.1'])
    assert [r['request_id'] for r in report['routed']] == [good['id']], report
    assert next(r for r in report['requests'] if r['request_id'] == bad['id'])['state'] == 'held', report
    assert len(world.inbox('engine')) == 1
    assert (mailbox_snapshot(public), mailbox_snapshot(private)) == before


def test_r17_producer_sized_provider_log_does_not_block_a_dependent(tmp_path):
    world = DispatchWorld(tmp_path)
    change, _proof = r16_dependency(world, evidence_sizes=[2 * 1024 * 1024])
    report = world.dispatch(command='status')
    row = next(r for r in report['small_changes'] if r['request_id'] == change.value['id'])
    assert row['state'] == 'writer_ready', row
    sent = world.dispatch()
    assert next(r for r in sent['small_changes'] if r['request_id'] == change.value['id'])['state'] == 'writer_sent', sent


def test_r17_unrelated_sparse_evidence_is_never_opened_by_dispatch_composition(tmp_path):
    world = DispatchWorld(tmp_path); world.team('docs')
    value = world.ledger.ready(request('unrelated-sparse-proof', team='docs'))
    proof = tmp_path/'unrelated-sparse.log'
    with proof.open('wb') as stream:
        stream.truncate(1024 ** 4)
    world.ledger.intent(value)
    world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request({
        'request_sha256': raw_request(value)['sha256'], 'intent_id': 'attempt-1', 'outcome': 'passed',
        'exit_code': 0, 'source': value['source'], 'evidence': [{'path': str(proof), 'sha256': '0' * 64}]}),
        **world.ledger.target(value))
    injection = r"""
target = Path(%r)
seen['unrelated_opens'] = 0
original_open = os.open
def opened(path, *args, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == target:
        seen['unrelated_opens'] += 1
        raise OSError('modelled unrelated evidence must never be opened')
    return original_open(path, *args, **kw)
os.open = opened
""" % str(proof)
    report, seen = r7_router_probe(world, injection)
    assert seen['unrelated_opens'] == 0, (report, seen)
    assert report['small_changes'][0]['state'] == 'writer_sent', report
    assert len(world.messages('dispatch')) == 1 and world.messages('job_request') == []
    composed = Path(world.messages('dispatch')[0]['message']['brief']['path']).read_text()
    assert value['id'] not in composed and str(proof) not in composed
    loop, observed = r10_planning_probe(world, injection)
    assert next(r['state'] for r in loop['steps'] if r['step'] == 'run_open') == 'ok', loop
    assert observed['unrelated_opens'] == 0, observed


def test_r17_dependency_disappearing_after_writer_publish_prevents_route_receipt(tmp_path):
    world = DispatchWorld(tmp_path)
    change, proof = r16_dependency(world)
    injection = r"""
proof, lock = Path(%r), Path(%r)
seen.update(published=False, removed=False)
original_link, original_open = os.link, os.open
def linked(src, dst, *args, **kw):
    answer = original_link(src, dst, *args, **kw)
    if 'scw-' in Path(dst).name and Path(dst).suffix == '.md':
        seen['published'] = True
    return answer
def opened(path, *args, **kw):
    if not isinstance(path, int) and Path(path) == lock and seen['published'] and not seen['removed']:
        proof.unlink(); seen['removed'] = True
    return original_open(path, *args, **kw)
os.link, os.open = linked, opened
""" % (str(proof), str(world.ledger.path/'.write.lock'))
    before = world.ledger.files()
    report, seen = r7_router_probe(world, injection)
    assert seen == {'published': True, 'removed': True}, seen
    row = next(r for r in report['small_changes'] if r['request_id'] == change.value['id'])
    assert row['state'] == 'held' and not row.get('route_receipt'), row
    assert not row.get('writer_publication_verified'), row
    assert 'engine/lane/fix' in report['planning_exclusions'], report
    assert world.ledger.files() == before
    original = world.messages('dispatch')
    assert len(original) == 1 and world.messages('job_request') == []
    again = world.dispatch()
    assert 'engine/lane/fix' in again['planning_exclusions'] and world.messages('dispatch') == original, again


@pytest.mark.parametrize('target', ['message', 'brief', 'binding'])
def test_r17_final_writer_witness_refusal_never_releases_the_writer(tmp_path, target):
    world = DispatchWorld(tmp_path); world.dispatch()
    writer = world.messages('dispatch')[0]
    brief = Path(writer['message']['brief']['path'])
    path = {'message': Path(writer['path']), 'brief': brief,
            'binding': world.root/'bindings/engine/orchestrator/000001.json'}[target]
    injection = r"""
target, brief = Path(%r), Path(%r)
seen.update(brief_read=False, changed=False)
original_read, original_stat = os.read, os.stat
def actual(path, kw):
    if isinstance(path, int): return None
    path = Path(os.fsdecode(path))
    if not path.is_absolute() and kw.get('dir_fd') is not None:
        path = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/path
    return path
def read(fd, count):
    raw = original_read(fd, count)
    if raw and Path(os.readlink('/proc/self/fd/%%d' %% fd)) == brief:
        seen['brief_read'] = True
    return raw
def stated(path, *args, **kw):
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if actual(path, kw) == target and seen['brief_read'] and not seen['changed'] and 'run' in names and 'verify' in names and not set(names) & {'prior', 'writer_dispatch', 'progress', 'prepare', 'inspect'}:
        seen['changed'] = True
        target.write_bytes(target.read_bytes()+b' ')
    return original_stat(path, *args, **kw)
os.read, os.stat = read, stated
""" % (str(path), str(brief))
    before = world.ledger.files()
    report, seen = r7_router_probe(world, injection, command='status')
    assert seen == {'brief_read': True, 'changed': True}, seen
    row = report['small_changes'][0]
    assert row['state'] == 'held' and 'captured' in row['detail'], row
    assert not row.get('writer_publication_verified') and not row.get('route_receipt'), row
    assert 'engine/lane/fix' in report['planning_exclusions'], report
    assert world.ledger.files() == before and len(world.messages('dispatch')) == 1


@pytest.mark.parametrize('portable', [False, True])
def test_r17_shared_dependency_hash_is_memoized_per_pass_with_capability_control(tmp_path, portable):
    world = DispatchWorld(tmp_path)
    first, proof = r16_dependency(world)
    second = SmallChange(world.ledger, request('z-r17-dependent', prerequisites=['r16-prerequisite']))
    second.register(); second.decide()
    admission = second.admission(); admission['checks'][0]['recipes_sha256'] = world.recipe_hash
    second.admit(admission)
    injection = (PORTABLE_REFERENCE_PROBE if portable else "") + r"""
target = Path(%r)
seen['bytes'] = 0
original_read = os.read
def read(fd, count):
    raw = original_read(fd, count)
    if Path(os.readlink('/proc/self/fd/%%d' %% fd)) == target:
        seen['bytes'] += len(raw)
    return raw
os.read = read
""" % str(proof)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    report, seen = r7_router_probe(world, injection, command='status')
    selected = {r['request_id']: r for r in report['small_changes']}
    assert selected[first.value['id']]['state'] == selected[second.value['id']]['state'] == 'writer_ready', report
    assert seen['bytes'] == proof.stat().st_size, seen
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('origin', ['policy', 'dependency'])
@pytest.mark.parametrize('portable', [False, True])
def test_r17_producer_reference_limit_refuses_from_metadata_before_open(tmp_path, origin, portable):
    proof = tmp_path/'over-producer-bound.log'
    with proof.open('wb') as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    if origin == 'policy':
        world = Loop(tmp_path, policy_changes={'authority': [{'path': str(proof), 'sha256': '0' * 64}]})
        root = tmp_path/'engine/mailbox'; root.parent.mkdir()
        endpoints = {'engine/'+e: {} for e in ('front-door', 'orchestrator', 'root', 'router', 'decider')}
        endpoints.update({'engine/lane/fix': {'kind': 'implementer'}, 'engine/lane/review0': {'kind': 'reviewer'}})
        invoke(root, 'init', {'schema': 'aegis.hierarchy-pilot/v1', 'endpoints': endpoints,
                             'counterparts': [], 'writer_limit': 3})
        for endpoint in endpoints:
            invoke(root, 'bind', {'endpoint': endpoint, 'host': 'host-one', 'session': endpoint, 'expected_generation': 0})
        world.mailboxes['engine'] = root
        world.workspace.register('engine', mailbox_root=str(root))
        change = SmallChange(world.ledger); change.register(); change.decide(); change.admit()
    else:
        world = DispatchWorld(tmp_path)
        change, retained = r16_dependency(world)
        retained.write_bytes(b'')
        with retained.open('wb') as stream:
            stream.truncate(proof.stat().st_size)
        proof = retained
    injection = (PORTABLE_REFERENCE_PROBE if portable else "") + r"""
target = Path(%r)
seen['opens'] = 0
original_open = os.open
def opened(path, *args, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == target:
        seen['opens'] += 1
        raise OSError('modelled over-limit content must not be opened')
    return original_open(path, *args, **kw)
os.open = opened
""" % str(proof)
    before = world.ledger.files(), mailbox_snapshot(world.mailboxes['engine'])
    report, seen = r16_router(world, ['status', '--wait', '0.1'], injection)
    row = next(r for r in report['small_changes'] if r['request_id'] == change.value['id'])
    assert (row['state'], row.get('reason')) == ('held', 'small_change_configuration'), row
    assert 'lifecycle evidence exceeds 67108864-byte limit' in row['detail'], row
    assert seen['opens'] == 0, seen
    assert (world.ledger.files(), mailbox_snapshot(world.mailboxes['engine'])) == before


@pytest.mark.parametrize('malformed', ['publish-list', 'publish-missing-request', 'publish-null-request'])
def test_r17_argon_malformed_publish_is_a_typed_planning_hold_and_runs_jobs(tmp_path, malformed):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    world.ledger.publish(request('malformed-publish', team='pilot'))
    path = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    record = json.loads(path.read_text())
    event = {'type': 'publish'}
    if malformed != 'publish-missing-request':
        event['request'] = raw_request([]) if malformed == 'publish-list' else None
    record['envelope']['event'] = event
    record['event_sha256'] = hashlib.sha256(json.dumps(record['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    path.write_text(json.dumps(record))
    world.send('pilot/root', 'pilot/orchestrator', 'retained-malformed-publish')
    before = world.ledger.files()
    report = world.once(expect=3)
    states = {row['step']: row['state'] for row in report['steps']}
    assert states['sweep'] == 'skipped' and states['run_open'] == 'ok', report
    assert any(row['kind'] == 'planning_exclusions_unavailable' and row['act'] == 'owner' for row in report['holds']), report
    assert 'Traceback' not in json.dumps(report) and 'AttributeError' not in json.dumps(report), report
    assert world.woken() == [] and len(world.inbox('pilot/orchestrator')) == 1
    assert world.ledger.files() == before


@pytest.mark.parametrize('readiness', ['unacknowledged', 'superseded'])
def test_r17_argon_writer_target_binding_never_releases_unready_or_retired_custody(tmp_path, readiness):
    world = DispatchWorld(tmp_path); world.dispatch()
    writer = world.messages('dispatch')[0]
    binding = r5_rotate(world, 'engine/lane/fix', acknowledge=readiness == 'superseded')
    if readiness == 'unacknowledged':
        body = json.loads(writer['message']['body']); body['target_generation'] = binding['generation']
        lines = Path(writer['message']['brief']['path']).read_text().splitlines()
        for n, line in enumerate(lines):
            if line.startswith('Target generation: '):
                lines[n] = 'Target generation: '+str(binding['generation'])
            elif line.startswith('- {'):
                entry = json.loads(line[2:])
                if entry['kind'] == 'small_change_assignment':
                    entry['target_generation'] = binding['generation']; lines[n] = '- '+json.dumps(entry)
        raw = ('\n'.join(lines)+'\n').encode()
        sha = hashlib.sha256(raw).hexdigest()
        brief = Path(writer['message']['brief']['path']).parent/('fresh-'+sha+'.md'); brief.write_bytes(raw)
        path = Path(writer['path']); header, _body = path.read_text()[4:].split('\n---\n\n', 1)
        header = json.loads(header); header['brief'] = {'path': str(brief), 'sha256': sha}
        header['created_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        path.write_text('---\n'+json.dumps(header)+'\n---\n\n'+json.dumps(body))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ('status', 'dispatch', 'status'):
        report = world.dispatch(command=command)
        row = report['small_changes'][0]
        assert (row['state'], row.get('reason')) == ('held', 'small_change_binding_changed'), row
        assert not row.get('writer_publication_verified') and not row.get('route_receipt'), row
        assert 'engine/lane/fix' in report['planning_exclusions'], report
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r17_changed_shared_reference_mark_never_reuses_an_old_hash(tmp_path):
    world = DispatchWorld(tmp_path)
    _first, proof = r16_dependency(world)
    second = SmallChange(world.ledger, request('z-r17-dependent', prerequisites=['r16-prerequisite']))
    second.register(); second.decide()
    admission = second.admission(); admission['checks'][0]['recipes_sha256'] = world.recipe_hash
    second.admit(admission)
    injection = r"""
proof, events = Path(%r), Path(%r)
seen.update(hashed=False, changed=False)
original_read, original_open = os.read, os.open
def actual(path, kw):
    if isinstance(path, int): return None
    path = Path(os.fsdecode(path))
    if not path.is_absolute() and kw.get('dir_fd') is not None:
        path = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/path
    return path
def read(fd, count):
    raw = original_read(fd, count)
    if raw and Path(os.readlink('/proc/self/fd/%%d' %% fd)) == proof: seen['hashed'] = True
    return raw
def opened(path, *args, **kw):
    candidate = actual(path, kw)
    if candidate is not None and candidate.parent == events and seen['hashed'] and not seen['changed']:
        proof.write_text('r17 changed shared proof'); seen['changed'] = True
    return original_open(path, *args, **kw)
os.read, os.open = read, opened
""" % (str(proof), str(world.workspace.store/'events'))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    report, seen = r7_router_probe(world, injection, command='status')
    assert seen == {'hashed': True, 'changed': True}, seen
    row = next(r for r in report['small_changes'] if r['request_id'] == second.value['id'])
    assert (row['state'], row.get('reason')) == ('held', 'small_change_configuration'), row
    assert 'hash mismatch' in row['detail'] or 'changed' in row['detail'], row
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r17_dependency_check_is_after_the_parent_journal_witness_check(tmp_path):
    world = DispatchWorld(tmp_path)
    change, proof = r16_dependency(world)
    injection = r"""
proof = Path(%r)
seen.update(published=False, removed=False)
original_stat, original_link = os.stat, os.link
def linked(src, dst, *args, **kw):
    result = original_link(src, dst, *args, **kw)
    if 'scw-' in Path(dst).name and Path(dst).suffix == '.md': seen['published'] = True
    return result
def stated(path, *args, **kw):
    result = original_stat(path, *args, **kw)
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if actual == proof and seen['published'] and not seen['removed'] and '_record_under_lock' in names and 'verify' in names and not set(names) & {'verify_dependencies', 'recheck_dependencies'}:
        proof.unlink(); seen['removed'] = True
    return result
os.stat, os.link = stated, linked
""" % str(proof)
    before = world.ledger.files()
    report, seen = r7_router_probe(world, injection)
    assert seen == {'published': True, 'removed': True}, seen
    row = next(r for r in report['small_changes'] if r['request_id'] == change.value['id'])
    assert row['state'] == 'held' and not row.get('route_receipt') and not row.get('writer_publication_verified'), row
    assert 'engine/lane/fix' in report['planning_exclusions'], report
    assert world.ledger.files() == before


def test_r17_mailbox_lock_exit_failure_after_verify_keeps_writer_custody(tmp_path):
    world = DispatchWorld(tmp_path)
    injection = r"""
import errno
target = Path(%r)
seen['failed'] = False
original = os.unlink
def unlink(path, *args, **kw):
    if Path(path) == target and not seen['failed']:
        seen['failed'] = True
        raise OSError(errno.EIO, 'modelled mailbox lock release failure after verify')
    return original(path, *args, **kw)
os.unlink = unlink
""" % str(world.root/'.write.lock')
    report, seen = r7_router_probe(world, injection)
    assert seen['failed'], seen
    assert len(world.messages('dispatch')) == 1 and (world.root/'.write.lock').exists()
    assert report['small_changes'] and all(not r.get('route_receipt') and not r.get('writer_publication_verified')
                                          for r in report['small_changes']), report
    assert 'engine/lane/fix' in report['planning_exclusions'], report


def test_r17_completed_historical_writer_feeds_checks_without_releasing_custody(tmp_path):
    world = DispatchWorld(tmp_path); world.dispatch(); world.finish_writer()
    r3_rebind(world, 'fix')
    report = world.dispatch()
    row = report['small_changes'][0]
    assert row['state'] == 'checking', row
    assert len(world.messages('dispatch')) == 1 and len(world.messages('job_request')) == 1
    assert not row.get('route_receipt') and not row.get('writer_publication_verified'), row
    assert 'engine/lane/fix' in report['planning_exclusions'], report


def test_r17_memoized_reference_rejects_parent_replacement_with_static_refusal(tmp_path):
    world = DispatchWorld(tmp_path)
    parent = tmp_path/'proof-parent'; parent.mkdir()
    # Select the evidence directory for this real public-CLI fixture before
    # creating its records; no retained terminal/review hashes are rewritten.
    fixture_root = world.tmp
    world.tmp = parent
    try:
        _first, retained = r16_dependency(world)
    finally:
        world.tmp = fixture_root
    alternate = tmp_path/'proof-alternate'; alternate.mkdir()
    os.link(retained, alternate/retained.name)
    second = SmallChange(world.ledger, request('z-r17-dependent', prerequisites=['r16-prerequisite']))
    second.register(); second.decide()
    admission = second.admission(); admission['checks'][0]['recipes_sha256'] = world.recipe_hash
    second.admit(admission)
    injection = r"""
proof, parent, alternate, events = Path(%r), Path(%r), Path(%r), Path(%r)
seen.update(hashed=False, swapped=False)
original_read, original_open = os.read, os.open
def read(fd, count):
    raw = original_read(fd, count)
    if raw and Path(os.readlink('/proc/self/fd/%%d' %% fd)) == proof: seen['hashed'] = True
    return raw
def opened(path, *args, **kw):
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual is not None and actual.parent == events and seen['hashed'] and not seen['swapped']:
        parent.rename(parent.with_name('proof-retired')); alternate.rename(parent); seen['swapped'] = True
    return original_open(path, *args, **kw)
os.read, os.open = read, opened
""" % (str(retained), str(parent), str(alternate), str(world.workspace.store/'events'))
    report, seen = r7_router_probe(world, injection, command='status')
    assert seen == {'hashed': True, 'swapped': True}, seen
    row = next(r for r in report['small_changes'] if r['request_id'] == second.value['id'])
    assert (row['state'], row.get('reason')) == ('held', 'small_change_configuration'), row
    assert row['detail'] == 'cached evidence reference path changed', row


def r18_damage_last_event(world, event):
    """Modelled malformed retained input, following real public-CLI records."""
    path = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    record = json.loads(path.read_text())
    record['envelope']['event'] = event
    record['event_sha256'] = hashlib.sha256(json.dumps(record['envelope'], sort_keys=True,
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()
    path.write_text(json.dumps(record))


@pytest.mark.parametrize('kind', ['decision', 'meter', 'succeed'])
def test_r18_argon_invalid_global_or_uncorrelatable_event_refuses_all_public_routes(tmp_path, kind):
    world = DispatchWorld(tmp_path)
    unrelated = request('r18-unrelated', team='docs')
    world.ledger.publish(unrelated)
    if kind == 'decision':
        world.ledger.approve(unrelated)
        event = {'type':kind, 'request_id':unrelated['id'], 'decision':'approve', 'reason':'modelled retained input'}
    elif kind == 'meter':
        world.ledger.event(kind, actor=world.ledger.operator, subject=world.ledger.operator,
                           active_seconds=100, open_since=None)
        event = {'type':kind, 'subject':world.ledger.operator, 'active_seconds':-999,
                 'open_since':None, **world.ledger.target(unrelated)}
    else:
        checkpoint = world.ledger.cli('checkpoint')
        world.ledger.event(kind, actor='router-2', predecessor='router-1', checkpoint_sha256=checkpoint['sha256'])
        event = {'type':kind, 'predecessor':'router-1', 'checkpoint_sha256':checkpoint['sha256'],
                 **world.ledger.target(unrelated)}
    r18_damage_last_event(world, event)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    for command in ('status', 'route', 'dispatch'):
        answer = world.route(expect=2) if command == 'route' else world.dispatch(command=command, expect=2)
        assert answer['state'] == 'hold' and answer['error'] == 'invalid lifecycle event shape', answer
        assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('damage', ['missing-hash', 'wrong-id', 'extra-field'])
def test_r18_malformed_event_keeps_planning_unknown_and_canonical_run_open(tmp_path, damage):
    from tests.integration.test_hierarchy_loop import World
    world = activate_loop(World(tmp_path))
    value = request('r18-invalid-decision', team='pilot')
    world.ledger.ready(value)
    event = {'type':'decision', **world.ledger.target(value), 'decision':'approve', 'reason':'retained'}
    if damage == 'missing-hash': event.pop('request_sha256')
    elif damage == 'wrong-id': event['request_id'] = []
    else: event['owner-private-untrusted-field'] = 'must not echo input'
    r18_damage_last_event(world, event)
    world.send('pilot/root', 'pilot/orchestrator', 'r18-retained-invalid-event')
    before = world.ledger.files()
    answer = world.once(expect=3)
    stages = {r['step']:r['state'] for r in answer['steps']}
    assert stages['sweep'] == 'skipped' and stages['run_open'] == 'ok', answer
    assert any(r['kind'] == 'planning_exclusions_unavailable' for r in answer['holds']), answer
    assert 'Traceback' not in json.dumps(answer) and 'owner-private-untrusted-field' not in json.dumps(answer)
    assert world.woken() == [] and len(world.inbox('pilot/orchestrator')) == 1
    assert world.ledger.files() == before


def test_r18_failed_dependency_stays_failed_after_original_parent_is_restored(tmp_path):
    world = DispatchWorld(tmp_path)
    parent = tmp_path/'r18-proof-parent'; parent.mkdir()
    saved = world.tmp; world.tmp = parent
    try: change, proof = r16_dependency(world)
    finally: world.tmp = saved
    world.dispatch()
    alternate = tmp_path/'r18-proof-alternate'; alternate.mkdir()
    (alternate/proof.name).write_bytes(proof.read_bytes())
    before = world.ledger.files(), mailbox_snapshot(world.root)
    injection = r"""
import hierarchy_fresh_brief as fresh
proof, alternate = Path(%r), Path(%r)
seen['swapped_and_restored'] = False
original = fresh.os
retired = proof.parent.with_name('r18-retired')
swapped = False
def opened(path, *args, **kw):
    global swapped
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if path == proof.parent.name and 'live' in names and 'verify' in names and not seen['swapped_and_restored']:
        proof.parent.rename(retired); alternate.rename(proof.parent); swapped = True
    return original.open(path, *args, **kw)
def stated(path, *args, **kw):
    global swapped
    result = original.stat(path, *args, **kw)
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == proof and swapped:
        proof.parent.rename(alternate); retired.rename(proof.parent)
        swapped = False; seen['swapped_and_restored'] = True
    return result
def fstated(descriptor):
    global swapped
    result = original.fstat(descriptor)
    if swapped and Path(original.readlink('/proc/self/fd/%%d' %% descriptor)) == proof.parent:
        proof.parent.rename(alternate); retired.rename(proof.parent)
        swapped = False; seen['swapped_and_restored'] = True
    return result
fresh.os = SimpleNamespace(**dict(vars(original), open=opened, stat=stated, fstat=fstated))
""" % (str(proof), str(alternate))
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'swapped_and_restored':True}, seen
    row = next(r for r in answer['small_changes'] if r['request_id'] == change.value['id'])
    assert row['state'] == 'held' and not row.get('writer_publication_verified') and not row.get('route_receipt'), row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r18_replay_keeps_gate_only_dependency_witness_after_public_journal_append(tmp_path):
    world = DispatchWorld(tmp_path)
    world.ledger.event('disposition', status='HOLD', resolution={'kind':'blocked', 'owner':'owner',
        'next_decision':'retained fixture hold', 'condition':'not this test', 'evidence':world.ledger.evidence},
        **world.ledger.target(world.change.value))
    proof = tmp_path/'r18-admission-only-proof'; proof.write_text('canonical prerequisite admission proof')
    value = request('r18-prerequisite')
    saved = world.ledger.evidence
    world.ledger.evidence = [{'path':str(proof), 'sha256':hashlib.sha256(proof.read_bytes()).hexdigest()}]
    try: world.ledger.ready(value)
    finally: world.ledger.evidence = saved
    intent = 'r18-prerequisite-effect'
    world.ledger.intent(value, intent_id=intent)
    world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request({
        'request_sha256':raw_request(value)['sha256'], 'intent_id':intent, 'outcome':'passed',
        'exit_code':0, 'source':value['source'], 'evidence':saved}), **world.ledger.target(value))
    world.ledger.accepted_delivery(value)
    world.ledger.event('disposition', status='FINAL', resolution={'kind':'complete', 'evidence':saved},
                       **world.ledger.target(value))
    change = SmallChange(world.ledger, request('r18-dependent', prerequisites=[value['id']]))
    change.register(); change.decide()
    admission = change.admission(); admission['checks'][0]['recipes_sha256'] = world.recipe_hash
    change.admit(admission)
    world.dispatch()
    writer = world.messages('dispatch')[0]['message']
    assert str(proof) not in Path(writer['brief']['path']).read_text()
    world.change = change
    world.finish_writer()
    world.ledger.event('read', actor='router-1', **world.ledger.target(change.value))
    next_event = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    staged = next_event.read_bytes(); next_event.unlink()
    alternate = tmp_path/'r18-same-hash-proof'; alternate.write_bytes(proof.read_bytes())
    injection = r"""
import hierarchy_fresh_brief as fresh
proof, alternate, route, staged = Path(%r), Path(%r), Path(%r), %r
seen['replaced_after_route'] = False
original = fresh.os
def opened(path, *args, **kw):
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if '_replay' in names and 'reload' in names and not seen['replaced_after_route']:
        route.write_bytes(staged); alternate.replace(proof); seen['replaced_after_route'] = True
    return original.open(path, *args, **kw)
fresh.os = SimpleNamespace(**dict(vars(original), open=opened))
""" % (str(proof), str(alternate), str(next_event), staged)
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'replaced_after_route':True}, seen
    row = next(r for r in answer['small_changes'] if r['request_id'] == change.value['id'])
    assert row['state'] == 'held' and not row.get('writer_publication_verified') and not row.get('route_receipt'), row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert len(world.messages('dispatch')) == 1 and world.messages('job_request') == []
    world.dispatch()
    assert len(world.messages('dispatch')) == 1 and len(world.messages('job_request')) == 1
    before = world.ledger.files(), mailbox_snapshot(world.root)
    world.dispatch()
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r18_finalization_failure_cannot_reuse_a_prior_mailbox_absence_proof(tmp_path):
    world = DispatchWorld(tmp_path)
    note = world.root.parent/'r18-handoff.md'; note.write_text('modelled stopped outgoing session')
    invoke(world.root, 'bind', {'endpoint':'engine/lane/fix', 'host':'r18-host', 'session':'r18-session',
        'expected_generation':1, 'checkpoint':{'outgoing_stopped':True, 'sources':[], 'lease_refs':[],
        'completed_checks':[], 'pending_message_ids':[], 'last_acknowledgment_ids':[],
        'briefs':[{'path':str(note), 'sha256':hashlib.sha256(note.read_bytes()).hexdigest()}]}})
    policy = world.ledger.path/'policy.json'
    alternate = tmp_path/'r18-policy-copy'; alternate.write_bytes(policy.read_bytes())
    before = world.ledger.files(), mailbox_snapshot(world.root)
    injection = r"""
import hierarchy_fresh_brief as fresh
policy, alternate = Path(%r), Path(%r)
seen['replaced_at_finalization'] = False
original = fresh.os
def stated(path, *args, **kw):
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    actual = None if isinstance(path, int) else Path(os.fsdecode(path))
    if actual is not None and not actual.is_absolute() and kw.get('dir_fd') is not None:
        actual = Path(os.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/actual
    if actual == policy and 'finalize_writer_release' in names and not seen['replaced_at_finalization']:
        saved = policy.with_name('r18-original-policy')
        policy.rename(saved); alternate.rename(policy)
        try: result = original.stat(path, *args, **kw)
        finally: policy.rename(alternate); saved.rename(policy)
        seen['replaced_at_finalization'] = True
        return result
    return original.stat(path, *args, **kw)
fresh.os = SimpleNamespace(**dict(vars(original), stat=stated))
""" % (str(policy), str(alternate))
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'replaced_at_finalization':True}, seen
    row = answer['small_changes'][0]
    assert row['state'] == 'held' and not row.get('mailbox_history_verified'), row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('kind', ['decision', 'read', 'route', 'admit', 'wait', 'intent', 'start',
    'terminal', 'review', 'delivery', 'disposition', 'resolve', 'associate', 'observe', 'cancel_attempt',
    'delegated_decision', 'small_change_plan', 'small_change_decision', 'small_change_admit'])
def test_r18_every_request_event_checks_its_shape_before_actor_or_target_access(tmp_path, kind):
    world = DispatchWorld(tmp_path)
    r18_damage_last_event(world, {'type':kind, 'request_id':world.change.value['id']})
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer = world.dispatch(command='status', expect=2)
    assert answer['error'] == 'invalid lifecycle event shape', answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('kind', ['meter', 'succeed'])
def test_r18_valid_global_event_remains_global_and_keeps_writer_ready(tmp_path, kind):
    world = DispatchWorld(tmp_path)
    if kind == 'meter':
        world.ledger.event(kind, actor=world.ledger.operator, subject=world.ledger.operator,
                           active_seconds=100, open_since=None)
    else:
        checkpoint = world.ledger.cli('checkpoint')
        world.ledger.event(kind, actor='router-2', predecessor='router-1', checkpoint_sha256=checkpoint['sha256'])
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer = world.dispatch(command='status')
    assert answer['small_changes'][0]['state'] == 'writer_ready', answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


@pytest.mark.parametrize('kind,field,value,error', [
    ('meter', 'subject', {}, 'invalid meter subject'),
    ('meter', 'active_seconds', [], 'invalid lifecycle event shape'),
    ('meter', 'open_since', [], 'invalid lifecycle event shape'),
    ('succeed', 'predecessor', [], 'invalid succession predecessor'),
    ('succeed', 'checkpoint_sha256', {}, 'invalid succession checkpoint sha256'),
    ('decision', 'request_id', [], 'invalid lifecycle request id'),
    ('decision', 'request_sha256', {}, 'invalid lifecycle request sha256')])
def test_r18_complete_event_with_wrong_scalar_type_is_a_static_public_refusal(tmp_path, kind, field, value, error):
    world = DispatchWorld(tmp_path)
    if kind == 'meter':
        world.ledger.event(kind, actor=world.ledger.operator, subject=world.ledger.operator,
                           active_seconds=100, open_since=None)
    elif kind == 'succeed':
        checkpoint = world.ledger.cli('checkpoint')
        world.ledger.event(kind, actor='router-2', predecessor='router-1', checkpoint_sha256=checkpoint['sha256'])
    else:
        unrelated = request('r18-scalar', team='docs')
        world.ledger.publish(unrelated); world.ledger.approve(unrelated)
    path = sorted((world.ledger.path/'events').glob('*.json'))[-1]
    event = json.loads(path.read_text())['envelope']['event']
    event[field] = value
    r18_damage_last_event(world, event)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer = world.dispatch(command='status', expect=2)
    assert answer['error'] == error, answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


# R19: metadata budgets precede every retained artifact content open.
def r19_artifact_io(folder):
    """Module-local OS boundary in an owned child; never read oversized fixture content."""
    return r'''
import hierarchy_small_change_dispatch as dispatch
import hierarchy_fresh_brief as fresh
from types import SimpleNamespace
original = os
folder = Path(%r)
seen.update(artifact_opens=[], artifact_reads=[])
def actual(path, kw):
    if isinstance(path, int): return Path(original.readlink('/proc/self/fd/%%d' %% path))
    value = Path(original.fsdecode(path))
    if not value.is_absolute() and kw.get('dir_fd') is not None:
        value = Path(original.readlink('/proc/self/fd/%%d' %% kw['dir_fd']))/value
    return value
def opened(path, flags, *args, **kw):
    target = actual(path, kw)
    if target.parent == folder:
        seen['artifact_opens'].append(target.name)
    return original.open(path, flags, *args, **kw)
def read(fd, count):
    target = actual(fd, {})
    if target.parent == folder and target.name != 'claim.json':
        seen['artifact_reads'].append({'name':target.name, 'requested':count})
        # The before-fix probe proves the attempted IO without hashing a sparse attacker size.
        if target.stat().st_size > 64 * 1024 * 1024:
            raise OSError('modelled oversized fixture read intercepted')
    return original.read(fd, count)
dispatch.os = SimpleNamespace(**dict(vars(original), open=opened))
fresh.os = SimpleNamespace(**dict(vars(original), read=read))
''' % str(folder)


def r19_damage_artifacts(folder, damage):
    sizes = {'log':{'step-1.log':64*1024*1024+1},
             'out':{'step-1.out':64*1024*1024+1},
             'unexpected':{'step-untrusted-secret':64*1024*1024+1},
             'derivation':{'derivation-untrusted-secret':64*1024*1024+1},
             'sparse':{'step-1.log':1024*1024*1024},
             'aggregate':{'step-%d.log' % n:64*1024*1024 for n in range(1, 6)}}[damage]
    for name, size in sizes.items():
        with (folder/name).open('wb') as stream: stream.truncate(size)
    return ('retained artifact exceeds byte limit' if damage in {'log', 'out', 'sparse'} else
            'retained job evidence exceeds byte limit' if damage == 'aggregate' else
            'completed job artifacts differ from admitted recipe')


@pytest.mark.parametrize('command', ['status', 'dispatch'])
@pytest.mark.parametrize('damage', ['log', 'out', 'unexpected', 'derivation', 'sparse', 'aggregate'])
def test_r19_artifact_metadata_refuses_before_any_content_open(tmp_path, command, damage):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    detail = r19_damage_artifacts(folder, damage)
    before = snapshot_v1_unchanged(world)
    answer, seen = r7_router_probe(world, r19_artifact_io(folder), command=command)
    row = answer['small_changes'][0]
    assert seen['artifact_reads'] == [], seen
    assert set(seen['artifact_opens']) <= {'claim.json'}, seen
    assert (row['state'], row['reason'], row['detail']) == ('held', 'small_change_receipt_invalid', detail), row
    assert snapshot_v1_unchanged(world) == before
    assert len(world.messages('dispatch')) == len(world.messages('job_request')) == 1
    assert folder.is_dir(), 'a refusal must retain the original evidence'


@pytest.mark.parametrize('damage', ['log', 'unexpected', 'derivation', 'sparse', 'aggregate'])
def test_r19_evidence_hold_keeps_unrelated_canonical_run_open(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    detail = r19_damage_artifacts(folder, damage)
    docs = world.team('docs')
    world.workspace.run('update', {'initiative':'docs', 'source':'owner', 'checkouts':[str(world.checkout)]})
    packet = tmp_path/'docs/r19-canonical.md'
    packet.write_text(json.dumps({'schema':'aegis.hierarchy-job-packet/v1', 'recipe':'focused',
        'checkout':str(world.checkout), 'commit':world.revision, 'tree':world.tree}))
    invoke(docs, 'publish', {'message_id':'r19-independent', 'from':'docs/orchestrator', 'to':'docs/root',
        'host':'host-one', 'session':'docs-orchestrator', 'binding_generation':1, 'type':'job_request',
        'body':'independent canonical job', 'brief':{'path':str(packet),
            'sha256':hashlib.sha256(packet.read_bytes()).hexdigest()}})
    before = world.ledger.files(), mailbox_snapshot(world.root)
    injection = r19_artifact_io(folder) + "\nloop.TOOLS['jobs'] = Path(%r)\n" % str(JOBS)
    answer, seen = r10_planning_probe(world, injection)
    row = answer['small_changes'][0]
    assert seen['artifact_reads'] == [] and set(seen['artifact_opens']) <= {'claim.json'}, seen
    assert (row['state'], row['reason'], row['detail']) == ('held', 'small_change_receipt_invalid', detail), row
    run_open = next(s for s in answer['steps'] if s['step'] == 'run_open')
    assert run_open['state'] == 'ok' and {'job':'docs/r19-independent', 'state':'completed'} in run_open['rows'], answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r19_valid_boundary_log_preserves_runner_receipt_and_streamed_tail(tmp_path):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    log = folder/'step-1.log'
    with log.open('wb') as stream:
        for _ in range(64): stream.write(b'x' * (1024*1024))
    r8_refresh_receipt(world, folder)
    answer, seen = r7_router_probe(world, r19_artifact_io(folder))
    assert answer['small_changes'][0]['state'] == 'reviewing', answer
    assert sum(r['requested'] for r in seen['artifact_reads'] if r['name'] == 'step-1.log') <= log.stat().st_size+1, seen
    assert len(world.messages('dispatch')) == 2


def test_r19_cached_dependency_ancestry_failure_cannot_publish_or_release_after_restore(tmp_path):
    world = DispatchWorld(tmp_path)
    world.ledger.event('disposition', status='HOLD', resolution={'kind':'blocked', 'owner':'owner',
        'next_decision':'retained fixture hold', 'condition':'not this test', 'evidence':world.ledger.evidence},
        **world.ledger.target(world.change.value))
    parent, alternate = tmp_path/'r19-proof-parent', tmp_path/'r19-proof-alternate'
    parent.mkdir(); alternate.mkdir()
    proof = parent/'proof'; proof.write_text('completed prerequisite terminal evidence')
    os.link(proof, alternate/'proof')
    value = request('a-prereq')
    saved = world.ledger.evidence
    world.ledger.evidence = [{'path':str(proof), 'sha256':hashlib.sha256(proof.read_bytes()).hexdigest()}]
    try:
        world.ledger.ready(value)
        world.ledger.intent(value, intent_id='r19-prereq-effect')
        world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request({
            'request_sha256':raw_request(value)['sha256'], 'intent_id':'r19-prereq-effect', 'outcome':'passed',
            'exit_code':0, 'source':value['source'], 'evidence':world.ledger.evidence}), **world.ledger.target(value))
        world.ledger.accepted_delivery(value)
        world.ledger.event('disposition', status='FINAL', resolution={'kind':'complete', 'evidence':world.ledger.evidence},
                           **world.ledger.target(value))
    finally: world.ledger.evidence = saved
    change = SmallChange(world.ledger, request('z-change', prerequisites=[value['id']]))
    change.register(); change.decide()
    admission = change.admission(); admission['checks'][0]['recipes_sha256'] = world.recipe_hash
    change.admit(admission)
    injection = r'''
import hierarchy_fresh_brief as fresh
original = os
parent, alternate = Path(%r), Path(%r)
retired = parent.with_name('r19-proof-retired')
watched = None
seen.update(swapped=False, restored=False)
def opened(path, flags, *args, **kw):
    global watched
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if path == parent.name and 'evidence' in names and not seen['swapped']:
        parent.rename(retired); alternate.rename(parent); seen['swapped'] = True
        watched = original.open(path, flags, *args, **kw)
        return watched
    return original.open(path, flags, *args, **kw)
def closed(fd):
    if fd == watched and not seen['restored']:
        parent.rename(alternate); retired.rename(parent); seen['restored'] = True
    return original.close(fd)
fresh.os = SimpleNamespace(**dict(vars(original), open=opened, close=closed))
''' % (str(parent), str(alternate))
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'swapped':True, 'restored':True}, seen
    row = next(r for r in answer['small_changes'] if r['request_id'] == change.value['id'])
    assert row['state'] == 'held' and row['detail'] == 'reference parent changed while opening', row
    assert not row.get('writer_publication_verified') and not row.get('route_receipt'), row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r19_restored_symlinked_runner_claim_does_not_release_original_writer(tmp_path):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    claim = folder/'claim.json'
    injection = r'''
import hierarchy_small_change_dispatch as dispatch
original = os
claim = Path(%r)
saved = claim.with_name('r19-claim-saved')
seen['restored_claim'] = False
def stated(path, *args, **kw):
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if path == 'claim.json' and '_capture' in names and not seen['restored_claim']:
        claim.rename(saved); claim.symlink_to(saved.name)
        try: return original.stat(path, *args, **kw)
        finally:
            claim.unlink(); saved.rename(claim); seen['restored_claim'] = True
    return original.stat(path, *args, **kw)
dispatch.os = SimpleNamespace(**dict(vars(original), stat=stated))
''' % str(claim)
    before = snapshot_v1_unchanged(world)
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'restored_claim':True}, seen
    row = answer['small_changes'][0]
    assert (row['state'], row['reason']) == ('held', 'small_change_receipt_invalid'), row
    assert not row.get('writer_publication_verified') and not row.get('route_receipt'), row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert snapshot_v1_unchanged(world) == before
    assert world.dispatch()['small_changes'][0]['state'] == 'reviewing'
    assert len(world.messages('dispatch')) == 2


def test_r19_transient_capture_read_failure_cannot_release_in_the_same_operation(tmp_path):
    world = DispatchWorld(tmp_path)
    world.dispatch(); world.finish_writer()
    injection = r'''
import hierarchy_fresh_brief as fresh
original = os
recipes = Path(%r)
seen['failed_capture'] = False
def read(fd, size):
    if Path(original.readlink('/proc/self/fd/%%d' %% fd)) == recipes and not seen['failed_capture']:
        seen['failed_capture'] = True
        raise OSError('modelled single capture read failure')
    return original.read(fd, size)
fresh.os = SimpleNamespace(**dict(vars(original), read=read))
''' % str(world.recipes_path)
    before = snapshot_v1_unchanged(world)
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'failed_capture':True}, seen
    row = answer['small_changes'][0]
    assert row['state'] == 'held' and row['detail'] == 'modelled single capture read failure', row
    assert not row.get('writer_publication_verified') and not row.get('route_receipt'), row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert snapshot_v1_unchanged(world) == before


@pytest.mark.parametrize('damage', ['cached-proof', 'shared-policy'])
def test_r19_unread_declaration_cannot_hide_a_failed_authority_witness(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    world.ledger.event('disposition', status='HOLD', resolution={'kind':'blocked', 'owner':'owner',
        'next_decision':'fixture hold', 'condition':'not this test', 'evidence':world.ledger.evidence},
        **world.ledger.target(world.change.value))
    parent = world.root.parent/'r19-authority'; parent.mkdir()
    proof = parent/'proof.md'; proof.write_text('completed prerequisite authority')
    alternate = world.root.parent/'r19-authority-alternate'; alternate.mkdir()
    os.link(proof, alternate/proof.name)
    saved = world.ledger.evidence
    if damage == 'cached-proof':
        value = request('a-prereq')
        world.ledger.evidence = [{'path':str(proof), 'sha256':hashlib.sha256(proof.read_bytes()).hexdigest()}]
        try:
            world.ledger.ready(value); world.ledger.intent(value, intent_id='r19-authority-effect')
            world.ledger.event('terminal', actor=world.ledger.operator, result=raw_request({
                'request_sha256':raw_request(value)['sha256'], 'intent_id':'r19-authority-effect', 'outcome':'passed',
                'exit_code':0, 'source':value['source'], 'evidence':world.ledger.evidence}), **world.ledger.target(value))
            world.ledger.accepted_delivery(value)
            world.ledger.event('disposition', status='FINAL', resolution={'kind':'complete', 'evidence':world.ledger.evidence},
                               **world.ledger.target(value))
        finally: world.ledger.evidence = saved
    change = SmallChange(world.ledger, request('z-change', prerequisites=['a-prereq'] if damage == 'cached-proof' else []))
    change.register(); change.decide()
    admission = change.admission(); admission['checks'][0]['recipes_sha256'] = world.recipe_hash
    change.admit(admission)
    invoke(world.root, 'publish', {'message_id':'r19-unread-note', 'from':'engine/orchestrator', 'to':'engine/lane/fix',
        'host':'host-one', 'session':'engine/orchestrator', 'binding_generation':1, 'type':'brief',
        'body':'untrusted note, never authority', 'brief':{'path':str(proof),
            'sha256':hashlib.sha256(proof.read_bytes()).hexdigest()}})
    injection = r'''
import hierarchy_fresh_brief as fresh
import hierarchy_router as owning_router
original = os
parent, alternate, damage = Path(%r), Path(%r), %r
retired = parent.with_name('r19-authority-retired')
seen.update(triggered=False, restored=False)
watched = None
def frames():
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    return names
def opened(path, flags, *args, **kw):
    global watched
    if damage == 'cached-proof' and path == parent.name and '_unread_attachment' in frames() and not seen['triggered']:
        parent.rename(retired); alternate.rename(parent); seen['triggered'] = True
        watched = original.open(path, flags, *args, **kw)
        return watched
    return original.open(path, flags, *args, **kw)
def closed(fd):
    if fd == watched and not seen['restored']:
        parent.rename(alternate); retired.rename(parent); seen['restored'] = True
    return original.close(fd)
fresh.os = SimpleNamespace(**dict(vars(original), open=opened, close=closed))
user = owning_router._owner_home
def owner_home():
    if damage == 'shared-policy' and '_unread_attachment' in frames() and 'verify' in frames() and not seen['triggered']:
        seen['triggered'] = seen['restored'] = True
        return parent/'modelled-other-home'
    return user()
router._owner_home = owning_router._owner_home = owner_home
''' % (str(parent), str(alternate), damage)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    answer, seen = r7_router_probe(world, injection, expect=2 if damage == 'shared-policy' else 0)
    assert seen == {'triggered':True, 'restored':True}, seen
    if damage == 'shared-policy':
        assert answer == {'state':'hold', 'execution_enabled':False, 'error':'owner-home policy changed during capture'}
    else:
        row = next(r for r in answer['small_changes'] if r['request_id'] == change.value['id'])
        assert row['state'] == 'held', row
        assert not row.get('writer_publication_verified') and not row.get('route_receipt'), row
        assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def test_r19_unread_note_cannot_downgrade_a_failed_retained_packet_capture(tmp_path):
    world = DispatchWorld(tmp_path)
    # Model a mailbox parent containing its store, before any job/slot effects.
    # Relocate the unused fixture store without editing or replacing any ledger record.
    root = world.root
    before_store = {p.name:p.read_bytes() for p in (world.workspace.store/'events').iterdir()}
    store = root.parent/'retained-store'
    world.workspace.store.rename(store); world.workspace.store = store
    assert {p.name:p.read_bytes() for p in (store/'events').iterdir()} == before_store
    folder = formal_completed_job(world)
    packet = folder/'packet.md'
    invoke(root, 'publish', {'message_id':'r19-retained-note', 'from':'engine/orchestrator',
        'to':'engine/lane/review0', 'host':'host-one', 'session':'engine/orchestrator', 'binding_generation':1,
        'type':'brief', 'body':'untrusted note, never a replacement job packet', 'brief':{'path':str(packet),
            'sha256':hashlib.sha256(packet.read_bytes()).hexdigest()}})
    injection = r'''
import hierarchy_fresh_brief as fresh
original = os
packet = Path(%r)
seen['failed_retained_packet'] = False
def read(fd, size):
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if '_unread_attachment' in names and Path(original.readlink('/proc/self/fd/%%d' %% fd)) == packet and not seen['failed_retained_packet']:
        seen['failed_retained_packet'] = True
        raise OSError('modelled retained packet read failure')
    return original.read(fd, size)
fresh.os = SimpleNamespace(**dict(vars(original), read=read))
''' % str(packet)
    before = snapshot_v1_unchanged(world)
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'failed_retained_packet':True}, seen
    row = answer['small_changes'][0]
    assert row['state'] == 'held' and row['reason'] == 'small_change_brief_unverified', row
    assert row['detail'] == 'authoritative brief attachment is unverified', row
    assert row['release_validation_error'] == 'modelled retained packet read failure', row
    assert not row.get('writer_publication_verified') and not row.get('route_receipt'), row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer
    assert snapshot_v1_unchanged(world) == before


@pytest.mark.parametrize('damage', ['cached-proof', 'shared-policy'])
def test_r19_standalone_note_keeps_required_reference_and_policy_failures_on_parent(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    parent = world.root.parent/'r19-standalone-proof'; parent.mkdir()
    proof = parent/'proof.md'; proof.write_text('required current terminal proof')
    alternate = world.root.parent/'r19-standalone-alternate'; alternate.mkdir()
    os.link(proof, alternate/proof.name)
    if damage == 'cached-proof':
        world.dispatch()
        world.finish_writer(evidence=[{'path':str(proof), 'sha256':hashlib.sha256(proof.read_bytes()).hexdigest()}])
    invoke(world.root, 'publish', {'message_id':'r19-standalone-note', 'from':'engine/root',
        'to':'engine/orchestrator', 'host':'host-one', 'session':'engine/root', 'binding_generation':1,
        'type':'brief', 'body':'untrusted note', 'brief':{'path':str(proof),
            'sha256':hashlib.sha256(proof.read_bytes()).hexdigest()}})
    injection = r'''
import pwd
from types import SimpleNamespace
parent, alternate, home, damage = Path(%r), Path(%r), Path(%r), %r
retired = parent.with_name('r19-standalone-retired')
original = os
watched = None
seen.update(triggered=False, restored=False)
def frames():
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    return names
def opened(path, flags, *args, **kw):
    global watched
    if damage == 'cached-proof' and path == parent.name and '_unread_attachment' in frames() and not seen['triggered']:
        parent.rename(retired); alternate.rename(parent); seen['triggered'] = True
        watched = original.open(path, flags, *args, **kw)
        return watched
    return original.open(path, flags, *args, **kw)
def closed(fd):
    if fd == watched and not seen['restored']:
        parent.rename(alternate); retired.rename(parent); seen['restored'] = True
    return original.close(fd)
fresh.os = SimpleNamespace(**dict(vars(original), open=opened, close=closed))
def getpwuid(uid):
    if damage == 'shared-policy' and '_unread_attachment' in frames() and 'verify' in frames() and not seen['triggered']:
        seen['triggered'] = seen['restored'] = True
        return SimpleNamespace(pw_dir=str(parent/'modelled-other-home'))
    return SimpleNamespace(pw_dir=str(home))
pwd.getpwuid = getpwuid
''' % (str(parent), str(alternate), str(tmp_path/'home'), damage)
    before = world.ledger.files(), mailbox_snapshot(world.root)
    code, answer, seen = r8_compose_probe(world, injection)
    assert seen == {'triggered':True, 'restored':True}, seen
    assert code == 2 and 'error' in answer, answer
    assert ('reference parent changed while opening' if damage == 'cached-proof' else 'owner-home policy changed') in answer['error'], answer
    assert (world.ledger.files(), mailbox_snapshot(world.root)) == before


def assert_latch_custody(answer):
    row = answer['small_changes'][0]
    assert row['state'] == 'held', row
    assert 'writer_publication_verified' not in row and 'route_receipt' not in row, row
    assert 'engine/lane/fix' in answer['planning_exclusions'], answer


def test_latch_changed_check_attachment_cannot_release_on_recovery(tmp_path):
    world = DispatchWorld(tmp_path)
    formal_completed_job(world)
    packet = Path(world.messages('job_request')[0]['message']['brief']['path'])
    packet.write_bytes(b'corrupt\n')
    before = snapshot_v1_unchanged(world)
    answer = world.dispatch()
    assert_latch_custody(answer)
    assert 'brief sha256 mismatch' in answer['small_changes'][0]['detail'], answer
    assert answer['small_changes'][0]['mailbox_history_verified'] is True, answer
    assert snapshot_v1_unchanged(world) == before


@pytest.mark.parametrize('boundary', ['_Operation', '_CapturedMailbox'])
@pytest.mark.parametrize('failure_mode', ['validator-refusal', 'exception'])
def test_latch_check_ref_failure_cannot_release_on_recovery(tmp_path, boundary, failure_mode):
    world = DispatchWorld(tmp_path)
    formal_completed_job(world)
    injection = r'''
import hierarchy_fresh_brief as fresh
boundary = getattr(fresh, %r)
original = boundary.check_ref
seen['failed_reference'] = False
def check_ref(self, ref):
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if 'reviewer_dispatch' in names and 'evidence' in names and not seen['failed_reference']:
        seen['failed_reference'] = True
        if %r == 'exception':
            raise ValueError('modelled check_ref refusal without a capture latch')
        # Corrupt this verification input, then run the real boundary validator.
        # Brief.evidence catches the refusal as prose: the parent must retain it.
        damaged = dict(ref)
        if %r == '_Operation':
            damaged['sha256'] = '0' * 64
        else:
            damaged['unexpected'] = True
        return original(self, damaged)
    return original(self, ref)
boundary.check_ref = check_ref
''' % (boundary, failure_mode, boundary)
    before = snapshot_v1_unchanged(world)
    answer, seen = r7_router_probe(world, injection)
    assert seen == {'failed_reference': True}, seen
    assert_latch_custody(answer)
    assert 'release_validation_error' in answer['small_changes'][0], answer
    assert snapshot_v1_unchanged(world) == before


@pytest.mark.parametrize('branch', ['first-live', 'second-live'])
@pytest.mark.parametrize('restore', [False, True])
def test_latch_live_claim_validation_cannot_release_on_recovery(tmp_path, branch, restore):
    world = DispatchWorld(tmp_path)
    folder = formal_completed_job(world)
    for record in world.messages('job_receipt'):
        if record['message']['receipt']['state'] == 'completed':
            Path(record['path']).unlink()
    injection = r'''
import hierarchy_small_change_dispatch as dispatch
import hierarchy_jobs as jobs
claim = Path(%r)/'claim.json'
value = json.loads(claim.read_text())
value.update(pid=os.getpid(), start=jobs.process_start(os.getpid()), process_scope=jobs.process_scope())
claim.write_text(json.dumps(value))
original = dispatch.os
saved = claim.with_name('latch-original-claim')
seen.update(swapped=False, restored=False, probes=0)
start = jobs.process_start
def process_start(pid):
    seen['probes'] += 1
    if %r == 'second-live' and seen['probes'] == 1:
        return None
    return start(pid)
jobs.process_start = process_start

def stated(path, *args, **kw):
    frame, names = sys._getframe(), []
    while frame is not None:
        names.append(frame.f_code.co_name); frame = frame.f_back
    if path == 'claim.json' and 'validate' in names and not seen['swapped']:
        claim.rename(saved); claim.symlink_to(saved.name); seen['swapped'] = True
        try:
            return original.stat(path, *args, **kw)
        finally:
            if %r:
                claim.unlink(); saved.rename(claim); seen['restored'] = True
    return original.stat(path, *args, **kw)
dispatch.os = SimpleNamespace(**dict(vars(original), stat=stated))
''' % (str(folder), branch, restore)
    answer, seen = r7_router_probe(world, injection)
    assert seen['swapped'] and seen['restored'] == restore, seen
    assert seen['probes'] == (1 if branch == 'first-live' else 2), seen
    assert_latch_custody(answer)
    assert answer['small_changes'][0]['detail'] == 'retained claim changed', answer
    assert answer['small_changes'][0]['mailbox_history_verified'] is True, answer


@pytest.mark.parametrize('damage', ['missing', 'changed'])
@pytest.mark.parametrize('changed_first', [False, True])
def test_latch_authoritative_note_has_specific_refusal_and_reconciliation_action(tmp_path, damage, changed_first):
    world = DispatchWorld(tmp_path)
    note = world.root.parent / 'unread-note.md'
    note.write_bytes(b'original typed note\n')
    identifier = 'a-changed-note' if changed_first else 'z-changed-note'
    invoke(world.root, 'publish', {'message_id': identifier, 'from': 'engine/orchestrator',
        'to': 'engine/lane/fix', 'host': 'host-one', 'session': 'engine/orchestrator', 'binding_generation': 1,
        'type': 'brief', 'body': 'typed note',
        'brief': {'path': str(note), 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}})
    intact = world.root.parent / 'intact-note.md'
    intact.write_bytes(b'intact typed note\n')
    other_id = 'z-intact-note' if changed_first else 'a-intact-note'
    invoke(world.root, 'publish', {'message_id': other_id, 'from': 'engine/orchestrator',
        'to': 'engine/lane/fix', 'host': 'host-one', 'session': 'engine/orchestrator', 'binding_generation': 1,
        'type': 'brief', 'body': 'another typed note',
        'brief': {'path': str(intact), 'sha256': hashlib.sha256(intact.read_bytes()).hexdigest()}})
    if damage == 'missing':
        note.unlink()
    else:
        note.write_bytes(b'changed typed note\n')
    before = snapshot_v1_unchanged(world)
    answer = world.dispatch()
    assert_latch_custody(answer)
    row = answer['small_changes'][0]
    assert row['reason'] == 'small_change_brief_unverified', row
    assert row['next_action'] == "reconcile the attachment's original durable reference, then rerun dispatch", row
    assert row['detail'] == 'authoritative brief attachment is unverified', row
    assert row.get('unverified_message_id') == identifier, row
    assert other_id not in json.dumps(row), row
    assert str(note) not in json.dumps(row) and str(intact) not in json.dumps(row), row
    assert snapshot_v1_unchanged(world) == before


@pytest.mark.parametrize('marker', ['ghp_' + 'x' * 30, 'ｇｈｐ＿' + 'ｘ' * 30])
def test_latch_new_brief_refusal_never_echoes_untrusted_path_text(tmp_path, marker):
    world = DispatchWorld(tmp_path)
    # Synthetic token-like directory names, including their compatibility form.
    directory = world.root.parent / marker
    directory.mkdir()
    note = directory / 'notice.md'
    note.write_bytes(b'unread typed note\n')
    invoke(world.root, 'publish', {'message_id': 'latch-no-path-echo', 'from': 'engine/orchestrator',
        'to': 'engine/lane/fix', 'host': 'host-one', 'session': 'engine/orchestrator', 'binding_generation': 1,
        'type': 'brief', 'body': 'typed note',
        'brief': {'path': str(note), 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}})
    note.unlink()
    answer = world.dispatch()
    assert_latch_custody(answer)
    row = answer['small_changes'][0]
    assert row['reason'] == 'small_change_brief_unverified', row
    assert row['detail'] == 'authoritative brief attachment is unverified', row
    assert marker not in json.dumps(answer, ensure_ascii=False), answer


@pytest.mark.parametrize('identifier, shown', [
    ('ghp_' + 'x' * 30, '[REDACTED]'),
    ('a' * 80, 'a' * 80),
])
def test_latch_offending_message_id_is_bounded_and_redacted(tmp_path, identifier, shown):
    world = DispatchWorld(tmp_path)
    note = world.root.parent / 'unread-note.md'
    note.write_bytes(b'original typed note\n')
    invoke(world.root, 'publish', {'message_id': identifier, 'from': 'engine/orchestrator',
        'to': 'engine/lane/fix', 'host': 'host-one', 'session': 'engine/orchestrator', 'binding_generation': 1,
        'type': 'brief', 'body': 'typed note',
        'brief': {'path': str(note), 'sha256': hashlib.sha256(note.read_bytes()).hexdigest()}})
    note.write_bytes(b'changed typed note\n')
    answer = world.dispatch()
    assert_latch_custody(answer)
    row = answer['small_changes'][0]
    assert row['reason'] == 'small_change_brief_unverified', row
    assert row['unverified_message_id'] == shown, row
    if identifier != shown:
        assert identifier not in json.dumps(answer), answer


@pytest.mark.parametrize('damage', ['changed', 'missing'])
def test_latch_r3_open_attachment_refusal_names_its_message(tmp_path, damage):
    world = DispatchWorld(tmp_path)
    packet = world.root.parent / 'open-packet.md'
    # An unrelated open job must remain traceable when it blocks a new writer.
    packet.write_text(json.dumps({'schema': 'aegis.hierarchy-job-packet/v1', 'recipe': 'focused',
        'checkout': str(world.checkout), 'commit': world.revision, 'tree': world.tree}))
    identifier = 'latch-r3-open-job-request'
    invoke(world.root, 'publish', {'message_id': identifier, 'from': 'engine/orchestrator',
        'to': 'engine/root',
        'host': 'host-one', 'session': 'engine/orchestrator', 'binding_generation': 1,
        'type': 'job_request', 'body': 'unrelated open work',
        'brief': {'path': str(packet), 'sha256': hashlib.sha256(packet.read_bytes()).hexdigest()}})
    if damage == 'changed':
        packet.write_bytes(b'changed open packet\n')
    else:
        packet.unlink()
    before = snapshot_v1_unchanged(world)
    answer = world.dispatch()
    row = answer['small_changes'][0]
    assert row['state'] == 'held', row
    assert 'writer_publication_verified' not in row and 'route_receipt' not in row, row
    assert row['reason'] == 'small_change_brief_unverified', row
    assert row.get('unverified_message_id') == identifier, row
    assert row['detail'] == 'authoritative brief attachment is unverified', row
    assert str(packet) not in json.dumps(row), row
    assert snapshot_v1_unchanged(world) == before


@pytest.mark.parametrize("failure", ["none", "enter", "exit"])
def test_mutating_projection_appends_once_when_writer_lock_fails(tmp_path, failure):
    world = DispatchWorld(tmp_path)
    injection = r'''
from contextlib import contextmanager
import hierarchy_small_change_dispatch as dispatch
original = dispatch.writer_lock
seen.update(entered=False, exited=False)
@contextmanager
def writer_lock(root):
    if FAILURE == 'enter':
        raise OSError('fixture writer lock enter refused')
    with original(root):
        seen['entered'] = True
        yield
    seen['exited'] = True
    if FAILURE == 'exit':
        raise OSError('fixture writer lock exit refused')
dispatch.writer_lock = writer_lock
'''.replace('FAILURE', repr(failure))
    answer, seen = r7_router_probe(world, injection)
    assert len(answer['small_changes']) == 1, answer
    row = answer['small_changes'][0]
    assert seen == {'entered': failure != 'enter', 'exited': failure != 'enter'}
    assert len(world.messages('dispatch')) == (0 if failure == 'enter' else 1)
    if failure == 'none':
        assert row['writer_publication_verified'] is True, row
        assert row['route_receipt'], row
    else:
        assert row['state'] == 'held' and row['reason'] == 'small_change_configuration', row
        assert row['detail'] == 'fixture writer lock %s refused' % failure, row
        assert 'writer_publication_verified' not in row and 'route_receipt' not in row, row


@pytest.mark.parametrize('supersede', [False, True], ids=['v1-only', 'v2-supersede'])
def test_bl03_workspace_schemas_replay_through_status_without_mutation(tmp_path, supersede):
    from tools import hierarchy_workspace as workspace
    from tests.integration.test_hierarchy_workspace import event_files

    world = DispatchWorld(tmp_path)
    old = world.workspace.ask('engine', 'heavy', 'bl03-holder')
    new = old
    if supersede:
        new = world.workspace.run('request', {'initiative': 'engine', 'kind': 'heavy',
            'holder': 'bl03-holder', 'supersedes': old})['request']['request_id']
    before = {p.name: p.read_bytes() for p in event_files(world.workspace)}
    ledger = workspace.Store(world.workspace.store).load()
    assert ledger.requests[new]['state'] == 'queued'
    if supersede:
        assert ledger.requests[old]['superseded_by'] == new
        assert ledger.requests[old]['state'] == 'withdrawn'
    assert world.dispatch(command='status')['small_changes'][0]['state'] == 'writer_ready'
    assert {p.name: p.read_bytes() for p in event_files(world.workspace)} == before


@pytest.mark.parametrize('damage', ['unknown-schema', 'wrong-sequence'])
def test_bl03_both_workspace_replay_loaders_refuse_unknown_schema_or_sequence(tmp_path, damage):
    from tests.integration.test_hierarchy_workspace import event_files

    world = DispatchWorld(tmp_path)
    path = event_files(world.workspace)[-1]
    event = json.loads(path.read_text())
    if damage == 'unknown-schema':
        event['schema'] = 'aegis.hierarchy-workspace-event/v999'
    else:
        event['seq'] += 1
    path.write_text(json.dumps(event))
    before = {p.name: p.read_bytes() for p in event_files(world.workspace)}
    assert 'wrong event schema or sequence' in world.workspace.run('status', expect=2)['error']
    assert 'wrong event schema or sequence' in world.dispatch(command='status', expect=2)['error']
    assert {p.name: p.read_bytes() for p in event_files(world.workspace)} == before
