"""The M1 end-to-end loop on fixtures: owner request to Decider, plus the five failure cases.

M1 definition: aegis-guides/v5.0-m1-definition-20261105.md, loop steps :60-67, failure cases :70-74. Each test
names the lines it covers. The runbook for the real run is docs/hierarchy-m1-loop-runbook.md.

Every tool is the real one, run as a child process: `hierarchy_lifecycle.py record` for the operator's publish,
ROOT's decision connection (`root_decide`) for ROOT, `hierarchy_loop.py once` for routing, the durable sweep and
run-open, `hierarchy_launcher.py start` for the lanes, `hierarchy_workspace.py` and `aegis team claim` for the
operator's lease, and the mailbox adapter for every session write. The sessions are fake hosts: the fake host plays
Claude roles and the fake Codex resumes into the fake host for launcher-started lanes. Each plan is the script a
real session would follow; the commits a real Implementer would write are made by the test. Every child process,
`aegis team claim` included, runs with the same sealed environment: PATH is only the fake binaries plus links to git
and ps, Python is named by its absolute path (`sys.executable`) with PYTHONPATH set to this checkout for `aegis_cli`,
and HOME, CODEX_HOME and CLAUDE_CONFIG_DIR are temporary, so no real model can start. These tests show the tools
carry the loop together on fixtures, not that real sessions behave this way, and they support no enforcement claim
(definition :83).

How the fixture differs from a real run, beyond the fake hosts:
- The first-turn transcript a real Codex lane writes is written by the test (`started`), because the meter reads it.
- The Implementer's own test run (:64) is not done: its result says `lane_check: "not_run: fixture"`, and the red and
  green evidence is the Orchestrator's `targeted-tests` jobs on c1 and c2 instead.
- Readiness is checked by the mailbox for the worktree root, the branch, the base revision and the lease expiry; the
  lease oid is checked for shape only. `Mailbox.readiness` in the pinned `tools/hierarchy_mailbox.py` never reads
  `lease_ref` in git, so a made-up oid of the right shape is accepted. That is a known product gap, not covered here.

Out of scope here, by design: CI on the branch and the owner's merge (:67). Neither can be faked honestly, so the
runbook covers them and the owner records the CI run URL and the merge on the exact commit. The real-session pass
of this loop (:84) is the owner's run.
"""
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_decider import Decider
from tests.integration.test_hierarchy_jobs import JOBS, PACKET_SCHEMA, Shop, verified_evidence
from tests.integration.test_hierarchy_lifecycle import raw_request, request
from tests.integration.test_hierarchy_loop import World, holds
from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke, mailbox_snapshot
from tests.integration.test_hierarchy_mailbox_mcp import payload
from tests.integration.test_hierarchy_provision import provision
from tests.integration.test_hierarchy_sweep import SealedFleet, started


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="run-open reads /proc and the wake supports POSIX process groups only")
LAUNCHER = ROOT / "tools" / "hierarchy_launcher.py"
FAKE_CODEX = Path(__file__).with_name("hierarchy_fake_codex.py")
IMPLEMENTER, REVIEWER = "pilot/lane/f2", "pilot/lane/review"
BRANCH = "feature/pilot-f2"
TEST_PATHS = ["tests/test_app.py", "tests/test_feature.py"]
DIRTY_NONE = hashlib.sha256(b"").hexdigest()
FUTURE = "2099-01-01T00:00:00Z"
# The targeted-tests recipe's one step: run each named test file's test_* functions in the export and write junit.
# A stand-in for pytest, so the job needs nothing outside the fixed environment; the recipe flags are the template's.
RUNNER = r'''
import importlib.util, os, sys
from xml.sax.saxutils import quoteattr
junit, paths = sys.argv[1], sys.argv[2:]
sys.path.insert(0, os.path.join(os.getcwd(), "src"))
cases = []
for path in paths:
    spec = importlib.util.spec_from_file_location(path.replace("/", "_")[:-3], path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in sorted(n for n in vars(module) if n.startswith("test_")):
        try:
            getattr(module, name)()
            cases.append((path, name, False))
        except AssertionError:
            cases.append((path, name, True))
failed = sum(1 for case in cases if case[2])
os.makedirs(os.path.dirname(junit), exist_ok=True)
rows = "".join("<testcase classname=%s name=%s>%s</testcase>" % (quoteattr(p), quoteattr(n), "<failure/>" if f else "")
               for p, n, f in cases)
with open(junit, "w", encoding="utf-8") as stream:
    stream.write('<testsuite name="targeted" tests="%d" failures="%d" errors="0" skipped="0">%s</testsuite>'
                 % (len(cases), failed, rows))
print("%d passed, %d failed" % (len(cases) - failed, failed))
sys.exit(1 if failed else 0)
'''
# Holds the mailbox writer lock once the job's started receipt is out, so its final receipt cannot be published.
# It polls until a deadline and exits non-zero if the started receipt never appears, so a slow machine fails loudly.
HOLD_MAILBOX = ("import glob, sys, time\ndeadline = time.monotonic() + 25\nwhile not glob.glob(%r):\n"
                "    if time.monotonic() > deadline:\n        sys.exit('the started receipt never appeared')\n"
                "    time.sleep(0.01)\nopen(%r, 'x').close()")


class Scenario(SealedFleet):
    """One team, `pilot`: Router, Orchestrator, Decider and ROOT bound with the journal, a project repository, and
    root's recipes. The lanes are started later, by the launcher, as the runbook orders it."""

    flags, loop, once, status, inbox, woken = World.flags, World.loop, World.once, World.status, World.inbox, World.woken
    status_path = World.status_path
    request_job = Shop.request_job
    publish = Shop.publish

    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        (self.bin / "git").symlink_to(shutil.which("git"))
        codex = self.bin / "codex"
        codex.unlink()
        codex.write_text('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, FAKE_CODEX), encoding="utf-8")
        codex.chmod(codex.stat().st_mode | stat.S_IXUSR)
        self.home = tmp_path / "home"
        self.home.mkdir()
        provision("init", self.init_request(roles=["router", "decider"]))
        self.ledger = Decider(tmp_path)
        journal = str(self.ledger.path)
        self.add_role("pilot/front-door", cwd=str(tmp_path))
        self.add_role("pilot/orchestrator", cwd=str(tmp_path))
        self.router_role = self.add_role("pilot/router", cwd=str(tmp_path), lifecycle=journal)
        self.add_role("pilot/decider", cwd=str(tmp_path), lifecycle=journal, actor="decider-1")
        self.root_role = self.add_role("pilot/root", session="root-session", lifecycle=journal, actor="root-1")
        self.checkout = self.make_project()
        self.worktree = tmp_path / "worktrees" / "f2"
        self.register(self.checkout)
        self.recipes_path = tmp_path / "recipes.json"
        tests = Shop.command(["$python", "-B", "-c", RUNNER, "$scratch/junit.xml", "$paths"],
                             require_clean=True, expects_tests=True, keep=["run/junit.xml"])
        self.recipes = {"schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable, "path": ["/usr/bin", "/bin"],
                        "identity": {"name": "Hierarchy Root", "email": "root@example.invalid"},
                        "recipes": {"targeted-tests": tests}}
        self.save_recipes()
        self.state_dir = tmp_path / "loop-state"
        self.threads = {}
        self.decisions = 0

    # -- fixture plumbing -------------------------------------------------------------------------------------------

    def env(self):
        return {**super().env(), "HOME": str(self.home), "TMPDIR": "/tmp"}

    def save_recipes(self):
        self.recipes_path.write_text(json.dumps(self.recipes), encoding="utf-8")

    def make_project(self):
        checkout = self.tmp / "project"
        for path, body in {".aegis/config.json": '{"v":1}\n', ".gitignore": ".aegis/state/\n",
                           "src/app.py": "value = 1\n", "tests/test_app.py": "def test_app():\n    assert True\n"}.items():
            (checkout / path).parent.mkdir(parents=True, exist_ok=True)
            (checkout / path).write_text(body, encoding="utf-8")
        git(checkout, "init", "-q", "-b", "develop")
        git(checkout, "add", ".")
        git(checkout, "commit", "-qm", "base")
        return checkout

    def register(self, *checkouts):
        self.workspace.run("update", {"initiative": "pilot", "source": "owner", "checkouts": [str(c) for c in checkouts]})

    def head(self, checkout=None):
        checkout = checkout or self.worktree
        return {"checkout": str(checkout), "commit": git(checkout, "rev-parse", "HEAD"),
                "tree": git(checkout, "rev-parse", "HEAD^{tree}")}

    def commit(self, files, message):
        """What the Implementer writes in its worktree; a fake host cannot edit files."""
        for path, body in files.items():
            (self.worktree / path).parent.mkdir(parents=True, exist_ok=True)
            (self.worktree / path).write_text(body, encoding="utf-8")
        git(self.worktree, "add", *files)
        git(self.worktree, "commit", "-qm", message)
        return self.head()

    def aegis(self, cwd, *arguments):
        """`aegis` in the sealed environment: fake-only PATH, temporary HOME, this checkout on PYTHONPATH."""
        env = {**self.env(), "PYTHONPATH": str(ROOT)}
        for name in ("AEGIS_WORKSPACE", "AEGIS_MANAGER_CONFIG", "AEGIS_MANAGER_CONFIG_SHA256", "GITHUB_BASE_REF"):
            env.pop(name, None)
        proc = subprocess.run([sys.executable, "-m", "aegis_cli", *arguments, "--json"], cwd=cwd, env=env,
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return json.loads(proc.stdout)

    def launcher(self, *words, expect=0, thread=None):
        env = {**self.env(), "FAKE_CODEX_THREAD": thread or "", "FAKE_CODEX_LOG": str(self.tmp / "fake-codex.log")}
        proc = subprocess.run([sys.executable, "-I", str(LAUNCHER), "--base", str(self.base), *words],
                              capture_output=True, text=True, timeout=30, env=env)
        assert not proc.stderr, proc.stderr
        assert proc.returncode == expect, proc.stdout
        return json.loads(proc.stdout)

    def start_lane(self, endpoint, cwd):
        thread = "019a" + uuid.uuid4().hex[:28]
        path = self.tmp / ("start-%s.json" % uuid.uuid4().hex)
        path.write_text(json.dumps({"endpoint": endpoint, "cwd": str(cwd)}), encoding="utf-8")
        answer = self.launcher("start", "--request", str(path), thread=thread)
        assert (answer["state"], answer["session"]) == ("bound", thread), answer
        started(self, "codex-cli", thread)  # the first turn's transcript, which the meter reads
        self.threads[endpoint] = thread
        return answer

    def launch_records(self, endpoint):
        folder = self.base / "launches" / endpoint.replace("/", "%2F")
        return [json.loads(p.read_text()) for p in sorted(folder.glob("*.json"))] if folder.exists() else []

    def results(self, endpoint):
        path = Path(str(self.log) + "." + endpoint.replace("/", "%2F") + ".results")
        return json.loads(path.read_text()) if path.exists() else {}

    def plan_for(self, endpoint, *calls):
        """Adds calls to an endpoint's plan; each runs once, in the first turn whose inbox satisfies it."""
        plan = json.loads(self.plan_path.read_text())
        plan.setdefault(endpoint, {"calls": []})["calls"] += list(calls)
        self.plan(plan)

    def connection(self, role, server):
        return json.loads(Path(role["connection"]).read_text())["mcpServers"][server]

    def serve(self, definition, calls):
        """Runs a session's own connection the way its host does, and returns (exit code, tool answers)."""
        frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
        frames += [{"jsonrpc": "2.0", "id": i + 2, "method": "tools/call", "params": {"name": n, "arguments": a}}
                   for i, (n, a) in enumerate(calls)]
        proc = subprocess.run([definition["command"], *definition["args"]], capture_output=True, text=True, timeout=20,
                              input="".join(json.dumps(f) + "\n" for f in frames), env=self.env())
        assert not proc.stderr, proc.stderr
        lines = [json.loads(line) for line in proc.stdout.splitlines()]
        return proc.returncode, lines

    def root_decide(self, value, verdict="approve", event_id=None):
        """ROOT's session tool, over ROOT's own generated connection."""
        self.decisions += 1
        arguments = {"event_id": event_id or "root-decision-%d" % self.decisions, "request_id": value["id"],
                     "request_sha256": raw_request(value)["sha256"], "decision": verdict,
                     "reason": "the owner agreed" if verdict == "approve" else "the owner withdrew it"}
        code, lines = self.serve(self.connection(self.root_role, "aegis_decision"), [("root_decide", arguments)])
        assert code == 0, lines
        return payload(lines[-1]), arguments

    def receipts(self, job):
        return [row["message"] for row in self.inbox("pilot/orchestrator")
                if row["message"]["type"] == "job_receipt" and row["message"]["in_reply_to"] == job]

    def evidence(self, job, state):
        [message] = [m for m in self.receipts(job) if m["receipt"]["state"] == state]
        files = verified_evidence({"receipt": message["receipt"]})
        return message, files, json.loads(files["result.json"].read_text())


def feature(s):
    return request("feature-1", team="pilot", owner="pilot/orchestrator", operation="feature", phase="implementation",
                   next_decision="review the lane result",
                   source={"commit": git(s.checkout, "rev-parse", "HEAD"), "tree": git(s.checkout, "rev-parse", "HEAD^{tree}"),
                           "dirty_sha256": DIRTY_NONE},
                   paths=[str(s.worktree / "src"), str(s.worktree / "tests")])


def delegation(s):
    return request("delegation-1", team="pilot", owner="pilot/decider", operation="delegate-merge", phase="integration",
                   next_decision="approve in-scope merges", paths=[str(s.worktree / "src"), str(s.worktree / "tests")],
                   continuation={"members": [], "max_starts": 1, "expires_at": FUTURE})


def merge(s, identifier, head, paths):
    return request(identifier, team="pilot", owner="pilot/orchestrator", operation="merge", phase="integration",
                   next_decision="merge the reviewed commit", paths=paths,
                   source={"commit": head["commit"], "tree": head["tree"], "dirty_sha256": DIRTY_NONE})


def packet(s, head, recipe="targeted-tests"):
    return json.dumps({"schema": PACKET_SCHEMA, "recipe": recipe, **head, "paths": TEST_PATHS})


def job_calls(s, name, head, when):
    """The Orchestrator files a job: a hash-bound packet to its root, then the request naming it."""
    return [{"name": name + "-packet", "tool": "mailbox_publish", "when_inbox": when,
             "arguments": {"message_id": name + "-packet", "to": "pilot/root", "type": "info", "body": packet(s, head)}},
            {"name": name, "tool": "mailbox_publish", "brief_from": name + "-packet", "when_inbox": when,
             "arguments": {"message_id": name, "to": "pilot/root", "type": "job_request",
                           "body": "Run targeted-tests on %s." % head["commit"]}}]


def lane_brief(s, base):
    return "\n".join([
        "# Lane brief: pilot/lane/f2 at %s" % base,
        "Endpoint: pilot/lane/f2", "Endpoint kind: implementer",
        "Goal: add double(x) in src/feature.py.",
        "Acceptance: targeted-tests passes on the exact commit with tests/test_feature.py counted.",
        "Worktree: %s" % s.worktree, "Head branch and base: %s %s" % (BRANCH, base),
        "Owned paths: src/**, tests/**", "Tests: %s" % ", ".join(TEST_PATHS),
        "Write the failing test first, then make it pass."]) + "\n"


# -- the loop, step by step --------------------------------------------------------------------------------------------

def operator_publishes_and_root_approves(s):
    """Step 1 (:60): the operator publishes the agreed request; ROOT approves it with its own session tool."""
    value = feature(s)
    s.ledger.publish(value)
    answer, arguments = s.root_decide(value)
    return value, answer, arguments


def operator_lease_and_worktree(s):
    """Step 3, first half (:63): the operator grants the writer slot, adds the worktree and claims the lease, then
    starts the Implementer with the launcher. This is the runbook's operator step, a deviation from the definition's
    automatic provisioning (owner choice, 2026-11-05)."""
    s.workspace.run("request", {"initiative": "pilot", "kind": "writer", "holder": IMPLEMENTER})
    granted = s.workspace.run("grant-next", kind="writer")["granted"]
    base = git(s.checkout, "rev-parse", "HEAD")
    s.worktree.parent.mkdir(parents=True, exist_ok=True)
    git(s.checkout, "worktree", "add", "-q", "-b", BRANCH, str(s.worktree), "develop")
    lease = s.aegis(s.checkout, "team", "claim", "pilot-f2", "--paths", "src/**", "tests/**", "--owner", IMPLEMENTER,
                    "--role", "implementer", "--branch", BRANCH)["lease"]
    s.register(s.checkout, s.worktree)
    started_lane = s.start_lane(IMPLEMENTER, s.worktree)
    readiness = {"worktree": str(s.worktree), "branch": BRANCH, "base_revision": base,
                 "lease_ref": "refs/aegis/lanes/pilot-f2", "lease_oid": lease["oid"],
                 "lease_expires_at": lease["expires_at"], "owned_paths": lease["paths"],
                 "scan_workspace": str(s.worktree), "scan_evidence": "not_run: fixture",
                 "enforcement_tier": "advisory", "hook_evidence": "not_observed: fixture"}
    return {"granted": granted, "lease": lease, "base": base, "launch": started_lane, "readiness": readiness}


def orchestrator_dispatches(s, base):
    """Step 2 (:61-62): one loop pass routes the request and wakes the Orchestrator, which publishes the lane brief
    and the dispatch that names it."""
    s.plan_for("pilot/orchestrator",
               {"name": "lane-brief", "tool": "mailbox_publish", "when_inbox": {"type": "info"},
                "arguments": {"message_id": "f2-brief", "to": IMPLEMENTER, "type": "info", "body": lane_brief(s, base)}},
               {"name": "dispatch", "tool": "mailbox_publish", "brief_from": "lane-brief", "when_inbox": {"type": "info"},
                "arguments": {"message_id": "f2-dispatch", "to": IMPLEMENTER, "type": "dispatch",
                              "body": "Implement feature-1 as the brief says."}})
    return s.once(expect=3)


RED = {"src/feature.py": "def double(x):\n    return x\n",
       "tests/test_feature.py": "from feature import double\n\n\ndef test_double():\n    assert double(2) == 4\n"}
GREEN = {"src/feature.py": "def double(x):\n    return 2 * x\n"}


def implementer_accepts_with_red(s, readiness):
    """The Implementer accepts on the operator's worktree and lease, and reports its failing test as c1."""
    c1 = s.commit(RED, "test: double(2) is 4 (red)")
    s.plan_for(IMPLEMENTER,
               {"name": "accept", "tool": "mailbox_publish",
                "arguments": {"message_id": "f2-accepted", "to": "pilot/orchestrator", "type": "ack",
                              "acknowledgment": "accepted", "in_reply_to": "f2-dispatch", "body": "Accepted.",
                              "readiness": readiness}},
               {"name": "red", "tool": "mailbox_publish",
                "arguments": {"message_id": "f2-red", "to": "pilot/orchestrator", "type": "info",
                              "body": "Failing test at %s." % c1["commit"]}})
    s.plan_for("pilot/orchestrator", *job_calls(s, "tests-c1", c1, {"type": "ack"}))
    first = s.once(expect=3)    # the lane's turn
    second = s.once(expect=3)   # the Orchestrator's turn files the job, and run-open runs it in the same pass
    return c1, first, second


def implementer_goes_green(s):
    """The Implementer makes the test pass as c2; the Orchestrator files the same job on c2 when c1's receipt fails."""
    c2 = s.commit(GREEN, "feat: double(x) (green)")
    s.plan_for("pilot/orchestrator", *job_calls(s, "tests-c2", c2, {"type": "job_receipt", "state": "failed"}))
    return c2, s.once(expect=3)


def review_and_result(s, c1, c2):
    """Step 4 (:65): the Orchestrator asks the Implementer for its result and the Reviewer for a verdict on c2, with
    the jobs' evidence references; both answer through their own adapters."""
    s.start_lane(REVIEWER, s.checkout)
    _, red_files, _ = s.evidence("tests-c1", "failed")
    _, green_files, _ = s.evidence("tests-c2", "completed")
    refs = {"c1": "%s sha256=%s" % (red_files["result.json"], sha(red_files["result.json"])),
            "c2": "%s sha256=%s" % (green_files["result.json"], sha(green_files["result.json"]))}
    review_brief = ("Review commit %s (tree %s) in %s.\nEvidence: targeted-tests on c1 failed: %s\n"
                    "targeted-tests on c2 completed: %s\n" % (c2["commit"], c2["tree"], s.worktree, refs["c1"], refs["c2"]))
    when = {"type": "job_receipt", "state": "completed"}
    s.plan_for("pilot/orchestrator",
               {"name": "ask-result", "tool": "mailbox_publish", "when_inbox": when,
                "arguments": {"message_id": "f2-report", "to": IMPLEMENTER, "type": "info",
                              "body": "targeted-tests passed on %s; send your result." % c2["commit"]}},
               {"name": "review-brief", "tool": "mailbox_publish", "when_inbox": when,
                "arguments": {"message_id": "review-brief", "to": REVIEWER, "type": "info", "body": review_brief}},
               {"name": "review-dispatch", "tool": "mailbox_publish", "brief_from": "review-brief", "when_inbox": when,
                "arguments": {"message_id": "review-1", "to": REVIEWER, "type": "dispatch", "body": "Review c2."}})
    checks = [{"check": "targeted-tests on c1 (red)", "outcome": "fail", "reference": refs["c1"]},
              {"check": "targeted-tests on c2 (green)", "outcome": "pass", "reference": refs["c2"]}]
    s.plan_for(IMPLEMENTER, {"name": "result", "tool": "mailbox_publish", "when_inbox": {"type": "info"},
                             "arguments": {"message_id": "f2-result", "to": "pilot/orchestrator", "type": "result",
                                           "in_reply_to": "f2-dispatch", "body": "double(x) is in; red then green.",
                                           "result": {"source_revision": c2["commit"], "source_tree": c2["tree"],
                                                      "checks": checks, "lane_check": "not_run: fixture"}}})
    s.plan_for(REVIEWER,
               {"name": "accept", "tool": "mailbox_publish",
                "arguments": {"message_id": "review-accepted", "to": "pilot/orchestrator", "type": "ack",
                              "acknowledgment": "accepted", "in_reply_to": "review-1", "body": "Accepted."}},
               {"name": "verdict", "tool": "mailbox_publish",
                "arguments": {"message_id": "review-verdict", "to": "pilot/orchestrator", "type": "review",
                              "in_reply_to": "review-1", "body": "Accept %s: red on c1, green on c2." % c2["commit"],
                              "result": {"source_revision": c2["commit"], "source_tree": c2["tree"], "checks": checks}}})
    passes = [s.once(expect=3), s.once(expect=3)]   # the Orchestrator's turn, then both lanes' turns
    return refs, passes


def delegate_and_decide(s, c1, c2):
    """Step 4 (:66) and :73: ROOT approves a delegation; the operator publishes the merge request on c2 and one
    outside the delegation; the Orchestrator hands both to the Decider, which approves one and escalates the other."""
    granted = delegation(s)
    s.ledger.publish(granted)
    s.root_decide(granted)
    inside = merge(s, "merge-c2", c2, [str(s.worktree / "src"), str(s.worktree / "tests")])
    again = merge(s, "merge-again", c2, [str(s.worktree / "src")])
    outside = merge(s, "merge-outside", c2, [str(s.tmp / "elsewhere")])
    for value in (inside, again, outside):
        s.ledger.publish(value)
    verdict = next(r for r in s.inbox("pilot/orchestrator") if r["message"]["message_id"] == "review-verdict")
    review = [{"path": verdict["path"], "sha256": sha(Path(verdict["path"]))}]
    s.plan_for("pilot/orchestrator", {"name": "to-decider", "tool": "mailbox_publish", "when_inbox": {"type": "review"},
                                      "arguments": {"message_id": "decide-merges", "to": "pilot/decider", "type": "info",
                                                    "body": "Decide merge-c2 and merge-outside on %s." % c2["commit"]}})

    def decided(target, choice, name, commit=c2["commit"]):
        return {"name": name, "tool": "decider_record",
                "arguments": {"event_id": "decider-" + name, "request_id": target["id"],
                              "request_sha256": raw_request(target)["sha256"], "delegation_id": granted["id"],
                              "delegation_sha256": raw_request(granted)["sha256"], "commit": commit,
                              "review": review, "decision": choice, "reason": "fixture " + choice}}

    # Two refusals inside the delegation's paths: an approval citing c1 instead of the request's source commit, and a
    # second approval once `max_starts: 1` is used up (a separate request, since one request takes one decision).
    s.plan_for("pilot/decider", decided(inside, "approve", "approve-c1", commit=c1["commit"]),
               decided(inside, "approve", "approve-inside"), decided(again, "approve", "approve-again"),
               decided(outside, "approve", "approve-outside"), decided(outside, "escalate", "escalate-outside"))
    passes = [s.once(expect=3), s.once(expect=3), s.once(expect=3)]
    return granted, inside, outside, review, passes


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def through_dispatch(tmp_path):
    s = Scenario(tmp_path)
    value, _, _ = operator_publishes_and_root_approves(s)
    lease = operator_lease_and_worktree(s)
    first = orchestrator_dispatches(s, lease["base"])
    return s, value, lease, first


def through_jobs(tmp_path):
    s, value, lease, _ = through_dispatch(tmp_path)
    c1, _, _ = implementer_accepts_with_red(s, lease["readiness"])
    c2, _ = implementer_goes_green(s)
    return s, value, lease, c1, c2


def errors(s, endpoint):
    return {name: answer for name, answer in s.results(endpoint).items() if "error" in answer}


# -- the happy path ----------------------------------------------------------------------------------------------------

def test_step1_operator_publishes_and_root_approves_with_its_decision_tool(tmp_path):
    """:60 -- the canonical request is a journal `publish` from the operator CLI, and ROOT's approval is a journal
    `decision` recorded through ROOT's own `root_decide` connection; retrying the same event changes nothing."""
    s = Scenario(tmp_path)
    value, answer, arguments = operator_publishes_and_root_approves(s)

    row = s.ledger.status()["requests"]["feature-1"]
    assert row["raw"]["sha256"] == raw_request(value)["sha256"] and row["publisher"] == "coordinator-1"
    assert [(d["request_id"], d["decision"], d["actor"]) for d in s.ledger.status()["decisions"]] == [
        ("feature-1", "approve", "root-1")]
    assert answer["identity"] == "configured" and answer["execution_enabled"] is False
    before = s.ledger.files()
    code, lines = s.serve(s.connection(s.root_role, "aegis_decision"), [("root_decide", arguments)])
    assert code == 0 and payload(lines[-1])["receipt"] == answer["receipt"]
    assert s.ledger.files() == before, "a retried decision is idempotent"


def test_step2_one_pass_routes_and_wakes_the_orchestrator_which_dispatches_the_lane_brief(tmp_path):
    """:61-62 -- one loop pass routes the approved request to `pilot/orchestrator` (a `route-<sha>` info message and a
    journal `route`), the durable sweep wakes the Orchestrator, and its dispatch names a brief with paths, tests and
    acceptance criteria."""
    s, value, _, first = through_dispatch(tmp_path)

    route = next(row for row in first["steps"] if row["step"] == "route")
    assert (route["actor"], route["routed"]) == ("router-1", ["feature-1"])
    assert s.ledger.status()["requests"]["feature-1"]["routed"]["to"] == "pilot/orchestrator"
    [routed] = [r["message"] for r in s.inbox("pilot/orchestrator")]
    assert routed["message_id"] == "route-" + raw_request(value)["sha256"] and routed["from"] == "pilot/router"
    assert s.woken() == ["pilot/orchestrator"]
    assert errors(s, "pilot/orchestrator") == {}
    dispatch = next(r for r in s.inbox(IMPLEMENTER) if r["message"]["type"] == "dispatch")["message"]
    brief = Path(dispatch["brief"]["path"]).read_bytes()
    assert hashlib.sha256(brief).hexdigest() == dispatch["brief"]["sha256"]
    for needed in (b"Owned paths: src/**, tests/**", b"Tests: tests/test_app.py, tests/test_feature.py", b"Acceptance:"):
        assert needed in brief
    assert ("sweep", "still_unread", IMPLEMENTER) in holds(first), "the lane's turn is the next pass"


def test_step3_operator_lease_and_worktree_then_the_implementer_accepts_on_them(tmp_path):
    """:63 -- the operator's writer grant, worktree and Aegis lease (a runbook step: the definition's automatic
    provisioning is a recorded deviation), the launcher's start record for the Implementer, and the Implementer's
    acceptance. The mailbox checks the readiness branch and worktree and refuses an expired lease; the lease oid is
    checked for shape only (the module docstring's known gap)."""
    s, _, lease, _ = through_dispatch(tmp_path)
    wrong_branch = {**lease["readiness"], "branch": "feature/someone-else"}
    expired = {**lease["readiness"], "lease_expires_at": "2000-01-01T00:00:00Z"}
    s.plan_for(IMPLEMENTER, *({"name": name, "tool": "mailbox_publish",
                               "arguments": {"message_id": "f2-" + name, "to": "pilot/orchestrator", "type": "ack",
                                             "acknowledgment": "accepted", "in_reply_to": "f2-dispatch",
                                             "body": "Accepted.", "readiness": readiness}}
                              for name, readiness in (("wrong-branch", wrong_branch), ("expired", expired))))
    implementer_accepts_with_red(s, lease["readiness"])

    assert lease["granted"]["holder"] == IMPLEMENTER and lease["granted"]["kind"] == "writer"
    assert [e["kind"] for e in (json.loads(p.read_text()) for p in sorted((s.workspace.store / "events").iterdir()))
            if e["kind"] in ("request", "grant")] == ["request", "grant"]
    assert git(s.worktree, "branch", "--show-current") == BRANCH
    assert [r["state"] for r in s.launch_records(IMPLEMENTER)] == ["bound"]
    assert {name: answer["error"] for name, answer in errors(s, IMPLEMENTER).items()} == {
        "wrong-branch": "readiness branch does not match worktree", "expired": "readiness lease has expired"}
    assert not {"f2-wrong-branch", "f2-expired"} & {r["message"]["message_id"] for r in s.inbox("pilot/orchestrator")}
    writers = invoke(s.root, "status")["accepted_writers"]
    assert [(w["endpoint"], w["dispatch"]) for w in writers] == [(IMPLEMENTER, "f2-dispatch")]
    accepted = next(r for r in s.inbox("pilot/orchestrator") if r["message"]["message_id"] == "f2-accepted")["message"]
    assert accepted["readiness"]["lease_oid"] == lease["lease"]["oid"]
    assert accepted["verification"]["git_identity"] == "observed"
    resumed = [row for row in s.launches() if row["endpoint"] == IMPLEMENTER]
    assert resumed and all("resume" in row["argv"] and s.threads[IMPLEMENTER] in row["argv"] for row in resumed)


def test_step3_targeted_tests_fail_on_c1_and_pass_on_c2_with_exact_evidence(tmp_path):
    """:63-64 -- the Implementer's red then green, proved by the targeted-tests job the Orchestrator files on each exact
    commit: `require_clean` runs it on an export of the commit, the junit counts are in the receipt and result.json,
    and the result names the recipe file's sha256."""
    s, _, _, c1, c2 = through_jobs(tmp_path)

    red, _, red_result = s.evidence("tests-c1", "failed")
    green, _, green_result = s.evidence("tests-c2", "completed")
    for result, head in ((red_result, c1), (green_result, c2)):
        assert (result["before"]["source_revision"], result["before"]["source_tree"]) == (head["commit"], head["tree"])
        assert result["before"]["dirty_entries"] == 0
    assert red_result["tests"] == {"total": 2, "passed": 1, "failed": 1, "errors": 0, "skipped": 0}
    assert green_result["tests"] == {"total": 2, "passed": 2, "failed": 0, "errors": 0, "skipped": 0}
    assert "Tests: 2 total, 1 passed, 1 failed, 0 errors, 0 skipped." in Path(
        next(r["path"] for r in s.inbox("pilot/orchestrator") if r["message"]["message_id"] == red["message_id"])
    ).read_text()
    for result in (red_result, green_result):
        assert result["recipes_sha256"] == sha(s.recipes_path)
        assert result["source_export"] and result["python"]
        assert "run/junit.xml" in {item["path"] for item in result["kept"]}
    assert errors(s, "pilot/orchestrator") == {}
    assert [r["receipt"]["state"] for r in s.receipts("tests-c1")] == ["started", "failed"]
    assert [r["receipt"]["state"] for r in s.receipts("tests-c2")] == ["started", "completed"]

    # A job whose paths hold no tests exits 0 but proves nothing, so it fails.
    s.request_job("tests-none", "targeted-tests", checkout=s.worktree, paths=["src/feature.py"])
    s.once(expect=3)
    _, _, none_result = s.evidence("tests-none", "failed")
    assert none_result["tests"]["total"] == 0 and none_result["reason"] == "the run reported no tests"


def test_step4_reviewer_names_c2_with_the_job_evidence_and_the_decider_approves_or_escalates(tmp_path):
    """:65-66 and :73 -- the Implementer's result and the Reviewer's verdict both name c2 and cite the jobs' result
    files by sha256; ROOT's delegation lets the Decider approve the merge request on c2 with `decider_record`, the
    journal refuses its approval of a path outside the delegation, of a commit other than the request's source commit
    and of a second request past `max_starts`, and its escalation shows in router escalations."""
    s, _, _, c1, c2 = through_jobs(tmp_path)
    refs, _ = review_and_result(s, c1, c2)
    granted, inside, outside, review, passes = delegate_and_decide(s, c1, c2)

    by_id = {r["message"]["message_id"]: r["message"] for r in s.inbox("pilot/orchestrator")}
    for identifier in ("f2-result", "review-verdict"):
        assert by_id[identifier]["result"]["source_revision"] == c2["commit"]
        assert [c["reference"] for c in by_id[identifier]["result"]["checks"]] == [refs["c1"], refs["c2"]]
    assert by_id["review-verdict"]["type"] == "review" and by_id["review-verdict"]["in_reply_to"] == "review-1"
    for endpoint in ("pilot/orchestrator", IMPLEMENTER, REVIEWER):
        assert errors(s, endpoint) == {}, endpoint
    decider = s.results("pilot/decider")
    assert decider["approve-c1"]["error"] == "reviewed commit is not the target's source commit"
    assert decider["approve-again"]["error"] == "delegation has no approvals left"
    assert decider["approve-outside"]["error"] == "target path is outside the delegation's paths"
    assert "error" not in decider["approve-inside"] and "error" not in decider["escalate-outside"]
    status = s.ledger.status()
    assert [(d["request_id"], d["decision"], d["commit"]) for d in status["delegated_decisions"]] == [
        ("merge-c2", "approve", c2["commit"]), ("merge-outside", "escalate", c2["commit"])]
    assert status["delegated_decisions"][0]["review"] == review
    assert "merge-c2" not in {d["request_id"] for d in status["decisions"]}, "a delegated approval admits nothing"
    escalated = holds(passes[-1])[("router_status", "escalation", "merge-outside")]
    assert escalated["act"] == "root"
    assert {r["request_id"] for r in s.status(expect=3)["last"]["holds"] if r["kind"] == "escalation"} == {"merge-outside"}


# -- the failure cases -------------------------------------------------------------------------------------------------

def test_failure_implementer_session_ends_mid_task_and_the_loop_resumes_it(tmp_path):
    """:70 -- the Implementer's session dies in its turn without reading its dispatch. The loop holds it for ROOT and
    gives it no blind retry; when the Orchestrator follows up, the durable sweep resumes the same Codex thread, which
    then accepts. A turn that ends after reading needs the same follow-up: nothing re-wakes read mail."""
    s, _, lease, _ = through_dispatch(tmp_path)
    s.plan({IMPLEMENTER: {"exit": 9}})

    died = s.once(expect=3)
    assert holds(died)[("sweep", "woken_unread", IMPLEMENTER)]["act"] == "root"
    held = s.once(expect=3)
    assert ("sweep", "ignored_mail", IMPLEMENTER) in holds(held)
    assert len([row for row in s.launches() if row["endpoint"] == IMPLEMENTER]) == 1, "no second turn on its own"

    s.plan({})
    s.plan_for(IMPLEMENTER, {"name": "accept", "tool": "mailbox_publish",
                             "arguments": {"message_id": "f2-accepted", "to": "pilot/orchestrator", "type": "ack",
                                           "acknowledgment": "accepted", "in_reply_to": "f2-dispatch",
                                           "body": "Accepted after resume.", "readiness": lease["readiness"]}})
    s.send("pilot/orchestrator", IMPLEMENTER, "f2-follow-up")
    resumed = s.once(expect=3)

    assert IMPLEMENTER in next(row for row in resumed["steps"] if row["step"] == "sweep")["woken"]
    turns = [row for row in s.launches() if row["endpoint"] == IMPLEMENTER]
    assert len(turns) == 2 and all("resume" in t["argv"] and s.threads[IMPLEMENTER] in t["argv"] for t in turns)
    assert errors(s, IMPLEMENTER) == {}
    assert [w["dispatch"] for w in invoke(s.root, "status")["accepted_writers"]] == ["f2-dispatch"]


def test_failure_lost_deliveries_are_repaired_republished_and_rewoken_without_duplicates(tmp_path, monkeypatch):
    """:71 -- the losses the loop recovers today (owner choice, 2026-11-05): a route delivered but never recorded is
    recorded by the next pass with no second message; a job receipt the mailbox could not take is published by the
    next run-open exactly once; and the receipt, arriving after the Orchestrator's turn, wakes it on the next pass.
    A lost lane `result` or `review` has no detector yet (the runbook says how to handle one)."""
    monkeypatch.syspath_prepend(str(ROOT / "tools"))
    import hierarchy_router

    s = Scenario(tmp_path)
    value, _, _ = operator_publishes_and_root_approves(s)
    target = raw_request(value)
    router = invoke(s.root, "status")["bindings"]["pilot/router"]
    identifier = hierarchy_router.route_id(target["sha256"])
    invoke(s.root, "publish", {"message_id": identifier, "from": "pilot/router", "to": "pilot/orchestrator",
                               "host": router["host"], "session": router["session"],
                               "binding_generation": router["generation"], "type": "info",
                               "body": hierarchy_router.route_body(value["id"], target)})
    assert s.status(expect=3)["state"] == "not_running"
    repaired = s.once()

    route = next(row for row in repaired["steps"] if row["step"] == "route")
    assert route["routed"] == ["feature-1"]
    assert [r["message"]["message_id"] for r in s.inbox("pilot/orchestrator")] == [identifier]
    assert s.ledger.status()["requests"]["feature-1"]["routed"]["to"] == "pilot/orchestrator"

    lock = s.root / ".write.lock"
    published = str(s.root / "pilot" / "orchestrator" / "*-root-to-orchestrator-*.md")
    s.recipes["recipes"]["hold-mailbox"] = Shop.command(["$python", "-c", HOLD_MAILBOX % (published, str(lock))])
    s.save_recipes()
    s.request_job("job-1", "hold-mailbox", checkout=s.checkout)
    run = subprocess.run([sys.executable, "-I", str(JOBS), "--store", str(s.workspace.store), "--recipes",
                          str(s.recipes_path), "--lock-wait", "0.2", "run-open"], capture_output=True, text=True,
                         timeout=60, env=s.env())
    assert run.returncode == 3, run.stdout + run.stderr
    assert json.loads(run.stdout)["rows"][0]["state"] == "settle_pending"
    assert [r["receipt"]["state"] for r in s.receipts("job-1")] == ["started"]
    lock.unlink()
    woken_before = len(s.woken())

    republished = s.once(expect=3)
    assert next(row for row in republished["steps"] if row["step"] == "run_open")["rows"] == [
        {"job": "pilot/job-1", "state": "completed"}]
    rewoken = s.once(expect=3)
    again = s.once(expect=3)

    assert [r["receipt"]["state"] for r in s.receipts("job-1")] == ["started", "completed"], "published exactly once"
    assert "pilot/orchestrator" in next(row for row in rewoken["steps"] if row["step"] == "sweep")["woken"]
    assert len(s.woken()) == woken_before + 2, "one turn for the started receipt, one for the late one, no more"
    assert "pilot/orchestrator" not in next(row for row in again["steps"] if row["step"] == "sweep")["woken"]


def test_failure_stale_and_revoked_sessions_are_refused_with_no_write(tmp_path):
    """:72 -- after the operator rebinds the Implementer (generation 2), the old session's own connection is refused
    by the mailbox fence and nothing is written; ROOT's deny after routing is reported as `revoked_after_route`, the
    route stays, and the Router sends nothing more."""
    s, value, lease, _ = through_dispatch(tmp_path)
    old = s.launch_records(IMPLEMENTER)[0]
    definition = json.loads(Path(old["connection"]).read_text())["mcpServers"]["aegis_mailbox"]
    brief = s.base / "rebind-brief.md"
    brief.write_bytes(b"Implementer handoff.\n")
    successor = "019a" + uuid.uuid4().hex[:28]
    invoke(s.root, "bind", invoke(s.root, "draft-handoff", {
        "endpoint": IMPLEMENTER, "host": "codex-cli", "session": successor, "outgoing_stopped": True,
        "briefs": [{"path": str(brief), "sha256": sha(brief)}]}))
    before = mailbox_snapshot(s.root)

    code, lines = s.serve(definition, [("mailbox_publish", {
        "message_id": "stale-accept", "to": "pilot/orchestrator", "type": "ack", "acknowledgment": "accepted",
        "in_reply_to": "f2-dispatch", "body": "Accepted.", "readiness": lease["readiness"]})])

    refusal = lines[0] if code else payload(lines[-1])
    assert refusal["error"] == "stale or mismatched sender binding", lines
    assert mailbox_snapshot(s.root) == before

    s.root_decide(value, "deny")
    journal = s.ledger.files()
    revoked = s.once(expect=3)
    held = holds(revoked)[("route", "revoked_after_route", "feature-1")]
    assert held["act"] == "router"
    assert s.ledger.status()["requests"]["feature-1"]["routed"]["to"] == "pilot/orchestrator"
    assert len([r for r in s.inbox("pilot/orchestrator") if r["message"]["from"] == "pilot/router"]) == 1
    assert s.ledger.files() == journal, "the loop and the Router record nothing for a revoked request"


def test_failure_an_out_of_delegation_request_reaches_root_and_root_decides(tmp_path):
    """:73 -- the Decider may only escalate a request outside its delegation; the loop raises the escalation for ROOT,
    ROOT approves it with `root_decide`, the hold clears, and the next pass routes it like any approved request."""
    s = Scenario(tmp_path)
    granted = delegation(s)
    s.ledger.publish(granted)
    s.root_decide(granted)
    head = s.head(s.checkout)
    outside = merge(s, "merge-outside", head, [str(s.tmp / "elsewhere")])
    s.ledger.publish(outside)
    target = {"request_id": outside["id"], "request_sha256": raw_request(outside)["sha256"],
              "delegation_id": granted["id"], "delegation_sha256": raw_request(granted)["sha256"],
              "commit": head["commit"], "review": s.ledger.evidence, "reason": "path outside the delegation"}
    s.plan_for("pilot/decider",
               {"name": "approve", "tool": "decider_record",
                "arguments": {"event_id": "decider-approve", **target, "decision": "approve"}},
               {"name": "escalate", "tool": "decider_record",
                "arguments": {"event_id": "decider-escalate", **target, "decision": "escalate"}})
    s.send("pilot/orchestrator", "pilot/decider", "decide-merge-outside")

    s.once()
    raised = s.once(expect=3)
    assert s.results("pilot/decider")["approve"]["error"] == "target path is outside the delegation's paths"
    assert holds(raised)[("router_status", "escalation", "merge-outside")]["act"] == "root"
    assert json.loads(s.status(expect=3)["last"]["holds"][0]["detail"])["reason"] == "path outside the delegation"
    assert s.ledger.status()["requests"]["merge-outside"]["routed"] is None, "an escalation is not an approval"

    s.root_decide(outside)
    cleared = s.once()

    assert ("router_status", "escalation", "merge-outside") not in holds(cleared)
    assert next(row for row in cleared["steps"] if row["step"] == "route")["routed"] == ["merge-outside"]
    [escalation] = json.loads(subprocess.run(
        [sys.executable, "-I", "-B", str(ROOT / "tools" / "hierarchy_router.py"), "--lifecycle", str(s.ledger.path),
         "--store", str(s.workspace.store), "status"], capture_output=True, text=True, timeout=30,
        env=s.env()).stdout)["escalations"]
    assert (escalation["request_id"], escalation["root_decision"]) == ("merge-outside", "approve")


def test_failure_root_and_router_attempts_to_execute_work_are_refused(tmp_path):
    """:74 -- ROOT's connection offers only `root_decide` and refuses mail and execution tools; ROOT's binding cannot
    request a job; the launcher refuses to start ROOT (a `refused` record, no start); the Router's own connection
    cannot dispatch or request a job and the journal refuses its decision or intent; the loop never wakes ROOT. Nothing
    is written by any refused attempt, and no host process starts. Whether a real ROOT or Router sandbox refuses a shell
    call to the job tool is the native probe's question (item 7), not this one's."""
    s = Scenario(tmp_path)
    value = feature(s)
    s.ledger.publish(value)
    journal, mailbox = s.ledger.files(), mailbox_snapshot(s.root)

    code, lines = s.serve(s.connection(s.root_role, "aegis_decision"), [
        ("mailbox_publish", {"message_id": "go", "to": "pilot/orchestrator", "type": "job_request", "body": "Run."}),
        ("workspace_capacity", {})])
    assert code == 0
    assert [payload(line)["error"] for line in lines[1:]] == [
        "unknown ROOT tool: mailbox_publish; ROOT only records decisions",
        "unknown ROOT tool: workspace_capacity; ROOT only records decisions"]

    router = s.connection(s.router_role, "aegis_mailbox")
    brief = {"path": str(s.root / "nowhere.md"), "sha256": "a" * 64}
    code, lines = s.serve(router, [
        ("mailbox_publish", {"message_id": "router-job", "to": "pilot/root", "type": "job_request", "body": "Run.",
                             "brief": brief}),
        ("mailbox_publish", {"message_id": "router-dispatch", "to": IMPLEMENTER, "type": "dispatch", "body": "Do it.",
                             "brief": brief})])
    assert code == 0 and all(line["result"].get("isError") for line in lines[1:]), lines
    assert mailbox_snapshot(s.root) == mailbox and s.ledger.files() == journal

    target = s.ledger.target(value)
    for kind, body in (("decision", {"decision": "approve", "reason": "self-approval"}), ("intent", {"intent_id": "a1"})):
        assert s.ledger.event(kind, actor="router-1", expect=2, **target, **body)["error"] == "role router cannot record " + kind
    assert s.ledger.files() == journal

    root = invoke(s.root, "status")["bindings"]["pilot/root"]
    refused = invoke(s.root, "publish", {"message_id": "root-job", "from": "pilot/root", "to": "pilot/orchestrator",
                                         "host": root["host"], "session": root["session"],
                                         "binding_generation": root["generation"], "type": "job_request", "body": "Run.",
                                         "brief": brief}, ok=False)
    assert "error" in refused

    start = s.tmp / "start-root.json"
    start.write_text(json.dumps({"endpoint": "pilot/root", "cwd": str(s.tmp)}), encoding="utf-8")
    answer = s.launcher("start", "--request", str(start), expect=2)
    assert answer["error"] == "ROOT is the owner's session; bind it with add-role"
    assert [r["state"] for r in s.launch_records("pilot/root")] == ["refused"]
    assert not (s.tmp / "fake-codex.log").exists(), "no host process started"
    assert invoke(s.root, "status")["bindings"]["pilot/root"] == root

    s.send("pilot/orchestrator", "pilot/root", "for-root")
    result = s.once(expect=3)
    assert holds(result)[("sweep", "root_queue", "pilot/root")]["act"] == "root"
    assert [(r["step"], r["kind"]) for r in result["holds"] if r.get("endpoint") == "pilot/root"] == [
        ("sweep", "root_queue")], "the sweep never tries to wake ROOT, so no no_profile or wake row names it"
    assert "pilot/root" not in next(row for row in result["steps"] if row["step"] == "sweep")["woken"]
    assert "pilot/root" not in s.woken() and s.launch_records("pilot/router") == []
