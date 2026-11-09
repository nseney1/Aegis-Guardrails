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
JOBS = ROOT / "tools/hierarchy_jobs.py"


class DispatchWorld(Loop):
    def __init__(self, tmp_path, *, writer_kind="implementer", reviewers=1, checks=1, expires=None,
                 recipe_changes=None, mismatched_check=False, private_evidence=False):
        seed = Ledger(tmp_path, initialize=False)
        actors = {**seed.policy["actors"], "router-2": {**seed.policy["actors"]["router-1"], "generation": 2}}
        super().__init__(tmp_path, policy_changes={"actors": actors,
                         "successors": {**seed.policy["successors"], "router-1": "router-2"}})
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

    def dispatch(self, *, fault=None, expect=0, command="dispatch"):
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
        proc = subprocess.run(argv + args, env=os.environ.copy(), capture_output=True, text=True, timeout=40)
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
    world = World(tmp_path)
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
    world = World(tmp_path)
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
    row = world.dispatch()["small_changes"][0]
    assert (row["state"], row["reason"]) == ("held", "small_change_configuration"), row
    assert (bytes_at(world.root.parent), world.ledger.files()) == before


def test_missing_planning_exclusions_is_a_protocol_refusal_never_an_empty_skip_set(tmp_path):
    from tests.integration.test_hierarchy_loop import World, answering
    world = World(tmp_path)
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
    world = World(tmp_path)
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
    world = World(tmp_path)
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
        "--state-dir", str(tmp_path / "loop-state"), "once"], capture_output=True, text=True,
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
def observe(operation, value):
    if not isinstance(value, (str, bytes, os.PathLike)):
        return
    path = Path(os.fsdecode(value))
    if any(path == root or root in path.parents for root in (journal, store_path)):
        accesses.append({'operation': operation, 'path': str(path)})
# Metadata lookup is discovery too: reject CLI private paths before safe_path's lstat.
original_stat, original_lstat = os.stat, os.lstat
def stat(path, *args, **kwargs):
    observe('stat', path)
    return original_stat(path, *args, **kwargs)
def lstat(path, *args, **kwargs):
    observe('lstat', path)
    return original_lstat(path, *args, **kwargs)
os.stat, os.lstat = stat, lstat
def audit(event, args):
    if event in {'open', 'os.listdir', 'os.scandir', 'os.mkdir', 'os.remove', 'os.rename'} and args:
        observe(event, args[0])
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


def coordination_input_probe_at_home(world, recipes, entry, pwd_home):
    process = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVATE_INPUT_PROBE, str(ROOT / "tools"), entry,
        str(pwd_home), str(world.ledger.path), str(world.workspace.store), str(recipes)],
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
    return World(tmp_path)


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
args = argparse.Namespace(lifecycle=journal, store=store, recipes=recipes, state_dir=state_dir, max_jobs=None)
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
listed = os.listdir
injected = False
def listdir(path):
    global injected
    names = listed(path)
    actual = Path(os.readlink('/proc/self/fd/%d' % path)) if type(path) is int else Path(path)
    if action == 'late-entry' and not injected and actual == Path(watched):
        injected = True
        os.mkfifo(actual / 'step-late')
    return names
os.listdir = listdir
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
    if not registered and Path(path) == Path(root) / '.write.lock':
        registered = True
        p = subprocess.run([sys.executable, '-I', '-B', lifecycle_cli, '--root', journal, 'record',
                            '--event', envelope, '--evidence-only'], env=os.environ.copy(), capture_output=True, text=True)
        assert p.returncode == 0, p.stdout + p.stderr
    return original(path, flags, *args, **kwargs)
os.open = opened
sys.exit(router.main(sys.argv[6:]))
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
args = argparse.Namespace(lifecycle=journal, store=store, recipes=recipes, state_dir=state_dir, max_jobs=None)
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
listed = os.listdir
changed = False
def listdir(directory):
    global changed
    names = listed(directory)
    actual = Path(os.readlink('/proc/self/fd/%d' % directory)) if type(directory) is int else Path(directory)
    if tamper and not changed and actual == Path(last):
        changed = True
        target = Path(first)
        if tamper == 'file':
            with (target / 'step-1.log').open('ab') as stream: stream.write(b'changed after capture')
        else:
            target.rename(target.with_name(target.name + '.retained'))
            target.mkdir()
    return names
os.listdir = listdir
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


def r7_router_probe(world, injection, *, command="dispatch", extra=()):
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
    telemetry = world.tmp / "r7-io.json"
    args = ["--lifecycle", str(world.ledger.path), "--store", str(world.workspace.store), command,
            "--recipes", str(world.recipes_path), "--wait", "0.1"]
    if command == "dispatch":
        args.append("--evidence-only")
    env = {k: v for k, v in os.environ.items()
           if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROUTER), str(world.tmp / "home"),
                        str(telemetry), *args, *extra], env=env, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0 and p.stderr == "", p.stdout + p.stderr
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


def test_r7_public_live_runner_is_running_without_log_capture_or_batch_continuation(tmp_path):
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
    env = {k: v for k, v in os.environ.items()
           if k not in {"CLAUDECODE", "CLAUDE_PID"} and not k.startswith("CLAUDE_CODE_")}
    process = subprocess.Popen([sys.executable, "-I", "-B", str(JOBS), "--store", str(world.workspace.store),
        "--recipes", str(world.recipes_path), "run-open"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.monotonic() + 10
        while not started.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert started.exists(), "public runner did not reach the owned fixture step"
        for command in ("status", "dispatch"):
            row = world.dispatch(command=command)["small_changes"][0]
            assert row["state"] == "checking" and row["checks"][0]["state"] == "running", row
            assert not row["drafts"]
            assert world.messages("job_request") == requests and len(world.messages("dispatch")) == 1
    finally:
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
        assert code != 0 and not answer.get("ok", False), answer
        assert any(word in answer["error"] for word in ("regular file", "symlink", "exceeds 262144")), answer
    assert world.ledger.files() == before[0]
    after = mailbox_snapshot(world.root)
    assert all(after.get(key) == value for key, value in before[1].items())
    assert set(after) - set(before[1]) == ({str(Path(answer["brief"]["path"]).relative_to(world.root.parent))}
                                        if damage == "steady" else set())


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
    world = DispatchWorld(tmp_path)
    world.dispatch()
    world.finish_writer()
    private = world.tmp / "home" / name
    private.mkdir(parents=True)
    config = json.loads(world.recipes_path.read_text())
    config[field] = [str(private)]
    world.recipes_path.write_text(json.dumps(config))
    injection = r"""
old_stat = os.stat
seen['probes'] = 0
def inspected(path, *args, **kw):
    if not isinstance(path, int) and Path(path) == Path(%r): seen['probes'] += 1
    return old_stat(path, *args, **kw)
os.stat = inspected
""" % str(private)
    answer, seen = r7_router_probe(world, injection)
    row = answer["small_changes"][0]
    assert (row["state"], row["reason"], row["detail"]) == ("held", "small_change_configuration", "owner-private host directory is not an input"), row
    assert seen["probes"] == 0 and world.messages("job_request") == [], seen


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
