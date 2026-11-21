"""A simulated two-hierarchy wave uses real worktrees, leases and lane checks.

Host labels are fixtures. No host session, hook, CI, owner approval or merge is
observed by this scenario, and it does not implement the actual F2/F6 fixes.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke


def aegis(worktree, *arguments):
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    for name in ("AEGIS_WORKSPACE", "AEGIS_MANAGER_CONFIG", "AEGIS_MANAGER_CONFIG_SHA256", "GITHUB_BASE_REF"):
        env.pop(name, None)
    result = subprocess.run([sys.executable, "-m", "aegis_cli", *arguments, "--json"], cwd=worktree,
                            env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def test_two_hierarchies_keep_assignments_when_one_host_changes(tmp_path):
    root = tmp_path / "mailbox"
    manifest = json.loads((ROOT / "tools/hierarchy_templates/manifest.json").read_text())
    invoke(root, "init", manifest)
    bindings = {}
    for index, endpoint in enumerate(manifest["endpoints"]):
        bindings[endpoint] = {"host": "claude-code" if index % 2 else "codex-cli",
                              "session": endpoint + "-initial", "binding_generation": 1}
        invoke(root, "bind", {"endpoint": endpoint, "host": bindings[endpoint]["host"],
                              "session": bindings[endpoint]["session"], "expected_generation": 0})

    def send(sender, recipient, identifier, kind="info", **extra):
        return invoke(root, "publish", {"message_id": identifier, "from": sender, "to": recipient,
                                        **bindings[sender], "type": kind, "body": "Local protocol fixture; no owner approval.", **extra})

    def brief(name, body):
        path = tmp_path / (name + ".md")
        path.write_text(body)
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    for hierarchy in ("a", "b"):
        intent = brief(hierarchy + "-intent", "Goal: exercise one isolated hierarchy.\nAcceptance: preserve evidence.\n")
        identifier = hierarchy + "-intent"
        send(hierarchy + "/front-door", hierarchy + "/orchestrator", identifier, "brief", brief=intent)
        send(hierarchy + "/orchestrator", hierarchy + "/front-door", identifier + "-acted", "ack",
             in_reply_to=identifier, acknowledgment="completed")

    seed = tmp_path / "seed"
    seed.mkdir()
    git(seed, "init", "-q", "-b", "develop")
    for path, body in {
        ".aegis/config.json": '{"v":1}\n', ".gitignore": ".aegis/state/\n",
        "src/a/value.txt": "baseline a\n", "src/b/value.txt": "baseline b\n",
        ".aegis/rules/personas/persona-repository-baseline.md": (ROOT / ".aegis/rules/personas/persona-repository-baseline.md").read_text(),
    }.items():
        target = seed / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    git(seed, "add", ".aegis/config.json", ".aegis/rules/personas/persona-repository-baseline.md", ".gitignore", "src/a/value.txt", "src/b/value.txt")
    git(seed, "commit", "-qm", "fixture baseline")
    base = git(seed, "rev-parse", "HEAD")
    git(seed, "update-ref", "refs/remotes/origin/develop", base)
    assignments = {}
    for hierarchy, lane in (("a", "f2"), ("b", "f6")):
        endpoint = hierarchy + "/lane/" + lane
        worktree = tmp_path / (hierarchy + "-lane")
        branch = "lane/" + hierarchy + "-" + lane
        git(seed, "worktree", "add", str(worktree), "-b", branch, "origin/develop")
        lane_id = hierarchy + "-" + lane
        lease = aegis(seed, "team", "claim", lane_id, "--paths", "src/" + hierarchy + "/**",
                      "--owner", endpoint, "--role", "lane", "--branch", branch)["lease"]
        scan = aegis(worktree, "scan", "src/" + hierarchy + "/value.txt")
        scan_path = tmp_path / (hierarchy + "-scan.json")
        scan_path.write_text(json.dumps(scan))
        assignment_brief = brief(hierarchy + "-lane-brief", "Endpoint: " + endpoint + "\nBranch: " + branch
                                 + "\nBase: " + base + "\nOwned paths: src/" + hierarchy + "/**\n")
        ready = {"worktree": str(worktree), "branch": branch, "base_revision": base,
                 "lease_ref": "refs/aegis/lanes/" + lane_id, "lease_oid": lease["oid"],
                 "lease_expires_at": lease["expires_at"], "owned_paths": lease["paths"],
                 "scan_workspace": str(worktree), "scan_evidence": str(scan_path),
                 "enforcement_tier": "advisory", "hook_evidence": "not_observed: local fixture"}
        dispatch = hierarchy + "-dispatch"
        send(hierarchy + "/orchestrator", endpoint, dispatch, "dispatch", brief=assignment_brief)
        send(endpoint, hierarchy + "/orchestrator", dispatch + "-accepted", "ack",
             in_reply_to=dispatch, acknowledgment="accepted", readiness=ready)
        assignments[hierarchy] = {"endpoint": endpoint, "worktree": worktree, "lane_id": lane_id,
                                  "dispatch": dispatch, "brief": assignment_brief, "readiness": ready}
    shared = aegis(seed, "team", "list")
    assert len(shared["leases"]) == 2
    assert all(not row["overlaps"] for row in shared["leases"])

    # All three counterpart layers exchange information that is read and acted on.
    for left, right in (("a/front-door", "b/front-door"), ("a/orchestrator", "b/orchestrator"),
                        ("a/lane/f2", "b/lane/f6")):
        for sender, recipient in ((left, right), (right, left)):
            identifier = sender.replace("/", "-") + "-peer"
            send(sender, recipient, identifier)
            inbox = invoke(root, "inbox", endpoint=recipient, limit=100)
            assert identifier in {row["message"]["message_id"] for row in inbox["messages"]}
            send(recipient, sender, identifier + "-acted", "ack", in_reply_to=identifier, acknowledgment="completed")

    assignment = assignments["a"]
    before = {"brief": assignment["brief"].copy(), "readiness": assignment["readiness"].copy(),
              "branch": git(assignment["worktree"], "branch", "--show-current"),
              "lease_oid": git(assignment["worktree"], "rev-parse", assignment["readiness"]["lease_ref"])}
    checkpoint = {"outgoing_stopped": True, "briefs": [assignment["brief"]],
                  "sources": [{"worktree": str(assignment["worktree"]), "source_revision": base,
                               "source_tree": git(assignment["worktree"], "rev-parse", "HEAD^{tree}"),
                               "dirty_state": "clean"}],
                  "lease_refs": [assignment["readiness"]["lease_ref"]], "completed_checks": [assignment["readiness"]["scan_evidence"]],
                  "pending_message_ids": [assignment["dispatch"]], "last_acknowledgment_ids": ["a-dispatch-accepted"]}
    replacement_host = "codex-cli" if bindings[assignment["endpoint"]]["host"] == "claude-code" else "claude-code"
    replacement = invoke(root, "bind", {"endpoint": assignment["endpoint"], "host": replacement_host,
                                        "session": "replacement-session", "expected_generation": 1, "checkpoint": checkpoint})
    invoke(root, "ack-handoff", {"endpoint": assignment["endpoint"], "session": "replacement-session", "generation": 2,
                                 "checkpoint_sha256": replacement["checkpoint_sha256"]})
    bindings[assignment["endpoint"]] = {"host": replacement_host, "session": "replacement-session", "binding_generation": 2}
    assert assignment["brief"] == before["brief"]
    assert assignment["readiness"] == before["readiness"]
    assert git(assignment["worktree"], "branch", "--show-current") == before["branch"]
    assert git(assignment["worktree"], "rev-parse", assignment["readiness"]["lease_ref"]) == before["lease_oid"]

    for hierarchy, item in assignments.items():
        path = item["worktree"] / "src" / hierarchy / "value.txt"
        path.write_text("fixture change " + hierarchy + "\n")
        git(item["worktree"], "add", "src/" + hierarchy + "/value.txt")
        git(item["worktree"], "commit", "-qm", "fixture lane change")
        audit = aegis(item["worktree"], "check", "--lane", item["lane_id"], "--base", base)
        assert audit["status"] == "pass"
        assert audit["provenance"]["paths"] == "lease"
        evidence = tmp_path / (hierarchy + "-lane-check.json")
        evidence.write_text(json.dumps(audit))
        send(item["endpoint"], hierarchy + "/orchestrator", hierarchy + "-result", "result", in_reply_to=item["dispatch"],
             result={"source_revision": git(item["worktree"], "rev-parse", "HEAD"),
                     "source_tree": git(item["worktree"], "rev-parse", "HEAD^{tree}"),
                     "checks": [{"check": "committed-lane-audit", "outcome": "pass", "reference": str(evidence)}],
                     "lane_check": str(evidence)})
    status = invoke(root, "status")
    assert status["bindings"][assignment["endpoint"]]["generation"] == 2
    assert status["native_enforcement_ready"] is False
    assert status["verification"]["fitness_credit"] == 0
    assert status["accepted_writers"] == []
    assert set(status["mailbox_message_counts"]["by_host"]) == {"claude-code", "codex-cli"}
    assert status["mailbox_message_counts"]["by_endpoint"][assignment["endpoint"]] > 0
