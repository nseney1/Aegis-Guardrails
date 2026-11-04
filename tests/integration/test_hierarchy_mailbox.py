"""Exercise the prototype convention through its standalone public CLI."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "tools" / "hierarchy_mailbox.py"
ENDPOINTS = {
    "a/front-door": {}, "a/orchestrator": {},
    "a/lane/f2": {"kind": "implementer"},
    "a/lane/review": {"kind": "reviewer"},
    "b/front-door": {}, "b/orchestrator": {},
    "b/lane/f6": {"kind": "implementer"},
}


def invoke(root, command, request=None, *, ok=True, process_timeout=15, **flags):
    argv = [sys.executable, str(HELPER), "--root", str(root), command]
    if request is not None:
        source = root.parent / "request.json"
        source.write_text(json.dumps(request), encoding="utf-8")
        argv += ["--request", str(source)]
    for name, value in flags.items():
        flag = "--" + name.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif value is not False:
            argv += [flag, str(value)]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(argv, capture_output=True, text=True, timeout=process_timeout, env=env)
    assert result.returncode == (0 if ok else 2), result.stdout[:2048] + result.stderr[:2048]
    data = json.loads(result.stdout)
    assert not result.stderr
    return data


@pytest.fixture
def pilot(tmp_path):
    root = tmp_path / "mailbox"
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "endpoints": ENDPOINTS,
                "counterparts": [["a/front-door", "b/front-door"],
                                 ["a/orchestrator", "b/orchestrator"],
                                 ["a/lane/f2", "b/lane/f6"]], "writer_limit": 3}
    invoke(root, "init", manifest)
    for endpoint in ENDPOINTS:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    brief = tmp_path / "brief.md"
    brief.write_bytes(b"Goal: improve diagnostics.\nAcceptance: retain overlap evidence.\n")
    return root, {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}


def message(sender="a/orchestrator", recipient="a/lane/f2", *, identifier="dispatch-1", kind="info", **extra):
    return {"message_id": identifier, "from": sender, "to": recipient,
            "host": "host-one", "session": sender, "binding_generation": 1,
            "type": kind, "body": "Information, never an approval.", **extra}


def published(root):
    return sorted(root.glob("**/*.md"))


@pytest.mark.parametrize("sender,recipient", [
    ("a/front-door", "a/orchestrator"), ("a/orchestrator", "a/front-door"),
    ("a/orchestrator", "a/lane/f2"), ("a/lane/f2", "a/orchestrator"),
    ("a/front-door", "b/front-door"), ("a/orchestrator", "b/orchestrator"),
    ("a/lane/f2", "b/lane/f6"),
])
def test_vertical_and_explicit_counterpart_routes(pilot, sender, recipient):
    root, _ = pilot
    result = invoke(root, "publish", message(sender, recipient))
    path = Path(result["path"])
    assert path in published(root)
    assert path.suffix == ".md"
    if sender.split("/")[0] != recipient.split("/")[0]:
        assert path.parent == root / "across" / recipient.split("/")[1]
    inbox = invoke(root, "inbox", endpoint=recipient)
    assert [row["message"]["message_id"] for row in inbox["messages"]] == ["dispatch-1"]


@pytest.mark.parametrize("sender,recipient", [
    ("a/front-door", "a/lane/f2"), ("a/lane/f2", "b/orchestrator"),
    ("a/orchestrator", "b/lane/f6"), ("a/lane/review", "b/lane/f6"),
    ("a/lane/f2", "a/lane/review"),
])
def test_diagonal_or_unmapped_routes_publish_nothing(pilot, sender, recipient):
    root, _ = pilot
    result = invoke(root, "publish", message(sender, recipient), ok=False)
    assert result["error"] == "route is not vertical or an explicit counterpart"
    assert published(root) == []


def test_dispatch_is_hash_bound_and_immutable(pilot):
    root, brief = pilot
    request = message(kind="dispatch", brief=brief)
    result = invoke(root, "publish", request)
    original = Path(result["path"]).read_bytes()
    request["body"] = "Replacement content"
    refused = invoke(root, "publish", request, ok=False)
    assert refused["error"] == "message_id already exists: dispatch-1"
    assert Path(result["path"]).read_bytes() == original
    Path(brief["path"]).write_bytes(b"Changed after dispatch\r\n")
    request["message_id"] = "dispatch-2"
    refused = invoke(root, "publish", request, ok=False)
    assert refused["error"] == "brief sha256 mismatch"
    assert len(published(root)) == 1


@pytest.mark.parametrize("change,error", [
    ({"path": "missing.md"}, "file unavailable"),
    ({"sha256": "0" * 64}, "brief sha256 mismatch"),
])
def test_missing_or_mismatched_brief_is_refused(pilot, change, error):
    root, brief = pilot
    if change.get("path") == "missing.md":
        change = {"path": str(root.parent / "missing.md")}
    result = invoke(root, "publish", message(kind="dispatch", brief={**brief, **change}), ok=False)
    assert error in result["error"]
    assert published(root) == []


def test_acknowledgments_are_separate_recipient_claims(pilot):
    root, _ = pilot
    invoke(root, "publish", message())
    received = message("a/lane/f2", "a/orchestrator", identifier="received-1", kind="ack",
                       in_reply_to="dispatch-1", acknowledgment="received")
    invoke(root, "publish", received)
    completed = {**received, "message_id": "completed-1", "acknowledgment": "completed"}
    invoke(root, "publish", completed)
    rows = invoke(root, "inbox", endpoint="a/orchestrator")["messages"]
    assert {row["message"]["acknowledgment"] for row in rows} == {"received", "completed"}
    assert all(row["message"]["authority"] == "information_only" for row in rows)
    forged = {**received, "message_id": "forged", "from": "a/lane/review", "session": "a/lane/review"}
    result = invoke(root, "publish", forged, ok=False)
    assert result["error"] == "reply endpoints do not reverse the referenced message"


def test_host_replacement_preserves_brief_and_rejects_stale_session(pilot):
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [],
                  "lease_refs": ["refs/aegis/lanes/a-f2"], "completed_checks": [],
                  "pending_message_ids": ["dispatch-1"], "last_acknowledgment_ids": []}
    replacement = invoke(root, "bind", {"endpoint": "a/lane/f2", "host": "host-two",
                                        "session": "replacement", "expected_generation": 1,
                                        "checkpoint": checkpoint})
    assert replacement["generation"] == 2
    assert replacement["ready"] is False
    old = message("a/lane/f2", "b/lane/f6", identifier="old")
    assert invoke(root, "publish", old, ok=False)["error"] == "stale or mismatched sender binding"
    new = {**old, "message_id": "new", "host": "host-two", "session": "replacement", "binding_generation": 2}
    assert invoke(root, "publish", new, ok=False)["error"] == "handoff checkpoint has not been acknowledged"
    invoke(root, "ack-handoff", {"endpoint": "a/lane/f2", "session": "replacement", "generation": 2,
                                 "checkpoint_sha256": replacement["checkpoint_sha256"]})
    invoke(root, "publish", new)
    rows = invoke(root, "inbox", endpoint="a/lane/f2")["messages"]
    assert rows[0]["message"]["brief"] == brief
    assert replacement["checkpoint"]["lease_refs"] == checkpoint["lease_refs"]
    assert len(published(root)) == 2


def test_checkpoint_requires_quiescence_and_matching_generation(pilot):
    root, _ = pilot
    request = {"endpoint": "a/front-door", "host": "host-two", "session": "replacement",
               "expected_generation": 1}
    assert invoke(root, "bind", request, ok=False)["error"] == "replacement requires a checkpoint"
    request["expected_generation"] = 0
    assert invoke(root, "bind", request, ok=False)["error"] == "binding generation changed"


def git(root, *args):
    return subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                           "-c", "commit.gpgsign=false", *args], cwd=root, text=True,
                          capture_output=True, check=True, timeout=10).stdout.strip()


def readiness(tmp_path, name="writing-lane", branch="feature/a-f2"):
    worktree = tmp_path / name
    worktree.mkdir()
    git(worktree, "init", "-q")
    git(worktree, "switch", "-c", branch)
    (worktree / "source.txt").write_text("baseline\n")
    git(worktree, "add", "source.txt")
    git(worktree, "commit", "-qm", "baseline")
    revision = git(worktree, "rev-parse", "HEAD")
    return {"worktree": str(worktree), "branch": branch, "base_revision": revision,
            "lease_ref": "refs/aegis/lanes/a-f2", "lease_oid": "a" * 40,
            "lease_expires_at": "2099-01-01T00:00:00Z", "owned_paths": ["source.txt"],
            "scan_workspace": str(worktree), "scan_evidence": "evidence/scan.json",
            "enforcement_tier": "advisory", "hook_evidence": "evidence/hook-unavailable.json"}


def test_writing_lane_acceptance_requires_readiness_and_checks_git_identity(pilot, tmp_path):
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    request = message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                      in_reply_to="dispatch-1", acknowledgment="accepted")
    assert invoke(root, "publish", request, ok=False)["error"] == "writing lane acceptance requires readiness"
    request["readiness"] = readiness(tmp_path)
    request["readiness"]["branch"] = "wrong-branch"
    assert invoke(root, "publish", request, ok=False)["error"] == "readiness branch does not match worktree"
    request["readiness"]["branch"] = "feature/a-f2"
    result = invoke(root, "publish", request)
    assert result["message"]["verification"]["git_identity"] == "observed"
    assert result["message"]["verification"]["scan"] == "sender_claim"
    assert result["message"]["verification"]["fitness_credit"] == 0


def test_read_only_reviewer_needs_no_writing_lease(pilot):
    root, brief = pilot
    invoke(root, "publish", message(recipient="a/lane/review", kind="dispatch", brief=brief))
    request = message("a/lane/review", "a/orchestrator", identifier="accepted", kind="ack",
                      in_reply_to="dispatch-1", acknowledgment="accepted")
    result = invoke(root, "publish", request)
    assert "readiness" not in result["message"]


def test_completion_requires_source_and_check_evidence(pilot, tmp_path):
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    request = message("a/lane/f2", "a/orchestrator", identifier="result", kind="result", in_reply_to="dispatch-1")
    assert invoke(root, "publish", request, ok=False)["error"] == "lane completion requires source and check evidence"
    request["result"] = {"source_revision": "a" * 40, "source_tree": "b" * 40,
                         "checks": [{"check": "affected-tests", "outcome": "pass", "reference": "evidence/tests.json"}],
                         "lane_check": "evidence/lane.json"}
    assert invoke(root, "publish", request, ok=False)["error"] == "dispatch has not been accepted"
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                                    in_reply_to="dispatch-1", acknowledgment="accepted", readiness=readiness(tmp_path)))
    result = invoke(root, "publish", request)
    assert result["message"]["verification"]["tests"] == "sender_claim"
    assert result["message"]["verification"]["human_approval"] == "not_established"


@pytest.mark.parametrize("extra", [{"approved": True}, {"type": "approval"}, {"message_id": "../escape"}])
def test_unsupported_authority_or_traversal_is_refused(pilot, extra):
    root, _ = pilot
    assert "error" in invoke(root, "publish", {**message(), **extra}, ok=False)
    assert published(root) == []


def test_status_and_inbox_are_read_only_and_corruption_is_explicit(pilot):
    root, _ = pilot
    result = invoke(root, "publish", message())
    before = {p.relative_to(root): (p.read_bytes(), p.stat().st_mtime_ns)
              for p in root.rglob("*") if p.is_file()}
    invoke(root, "status")
    invoke(root, "inbox", endpoint="a/lane/f2")
    after = {p.relative_to(root): (p.read_bytes(), p.stat().st_mtime_ns)
             for p in root.rglob("*") if p.is_file()}
    assert after == before
    Path(result["path"]).write_text("truncated message")
    assert "malformed mailbox message" in invoke(root, "inbox", endpoint="a/lane/f2", ok=False)["error"]


def test_duplicate_json_keys_nonfinite_and_symlink_inputs_are_refused(pilot, tmp_path):
    root, brief = pilot
    source = tmp_path / "invalid.json"
    for raw, expected in [('{' + '"message_id":"one","message_id":"two"}', "duplicate JSON key"),
                          ('{"value":NaN}', "non-finite JSON")]:
        source.write_text(raw)
        result = invoke(root, "publish", request=None, request_file=source, ok=False)
        assert expected in result["error"]
    link = tmp_path / "linked-brief.md"
    link.symlink_to(brief["path"])
    result = invoke(root, "publish", message(kind="dispatch", brief={**brief, "path": str(link)}), ok=False)
    assert "symlink" in result["error"]
    assert published(root) == []


@pytest.mark.parametrize("extra,error", [
    ({"type": []}, "unsupported message type"),
    ({"type": "ack", "acknowledgment": [], "in_reply_to": "missing"}, "ack requires a stage"),
])
def test_nonscalar_protocol_values_fail_as_json_without_publication(pilot, extra, error):
    root, _ = pilot
    assert error in invoke(root, "publish", {**message(), **extra}, ok=False)["error"]
    assert published(root) == []


def test_completed_dispatch_cannot_be_accepted_again(pilot, tmp_path):
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    accepted = message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                       in_reply_to="dispatch-1", acknowledgment="accepted", readiness=readiness(tmp_path))
    invoke(root, "publish", accepted)
    result = {"source_revision": "a" * 40, "source_tree": "b" * 40,
              "checks": [{"check": "tests", "outcome": "pass", "reference": "evidence/tests.json"}],
              "lane_check": "evidence/lane.json"}
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="completed", kind="result",
                                    in_reply_to="dispatch-1", result=result))
    accepted["message_id"] = "accepted-again"
    assert invoke(root, "publish", accepted, ok=False)["error"] == "dispatch is already completed"


def test_writing_lanes_cannot_share_a_worktree(pilot, tmp_path):
    root, brief = pilot
    ready = readiness(tmp_path)
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="accepted-a", kind="ack",
                                    in_reply_to="dispatch-1", acknowledgment="accepted", readiness=ready))
    invoke(root, "publish", message("b/orchestrator", "b/lane/f6", identifier="dispatch-b", kind="dispatch", brief=brief))
    request = message("b/lane/f6", "b/orchestrator", identifier="accepted-b", kind="ack",
                      in_reply_to="dispatch-b", acknowledgment="accepted", readiness=ready)
    assert invoke(root, "publish", request, ok=False)["error"] == "writing lanes must use separate worktrees, branches and leases"


@pytest.mark.parametrize("field,value,error", [
    ("enforcement_tier", [], "invalid enforcement tier"),
    ("lease_expires_at", "2099-01-01Z", "invalid UTC timestamp"),
])
def test_malformed_readiness_is_refused_without_traceback(pilot, tmp_path, field, value, error):
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    ready = readiness(tmp_path)
    ready[field] = value
    request = message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                      in_reply_to="dispatch-1", acknowledgment="accepted", readiness=ready)
    assert error in invoke(root, "publish", request, ok=False)["error"]


def test_active_handoff_preserves_assignment_and_successor_can_complete(pilot, tmp_path):
    root, brief = pilot
    ready = readiness(tmp_path)
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                                    in_reply_to="dispatch-1", acknowledgment="accepted", readiness=ready))
    snapshot = {"worktree": ready["worktree"], "source_revision": git(ready["worktree"], "rev-parse", "HEAD"),
                "source_tree": git(ready["worktree"], "rev-parse", "HEAD^{tree}"), "dirty_state": "clean"}
    checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [], "lease_refs": [],
                  "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": ["accepted"]}
    request = {"endpoint": "a/lane/f2", "host": "host-two", "session": "successor",
               "expected_generation": 1, "checkpoint": checkpoint}
    assert invoke(root, "bind", request, ok=False)["error"] == "checkpoint omits active dispatch"
    checkpoint["pending_message_ids"] = ["dispatch-1"]
    assert invoke(root, "bind", request, ok=False)["error"] == "checkpoint omits active lease"
    checkpoint["lease_refs"] = [ready["lease_ref"]]
    assert invoke(root, "bind", request, ok=False)["error"] == "checkpoint omits active source snapshot"
    checkpoint["sources"] = [snapshot]
    git(ready["worktree"], "switch", "-c", "unexpected-branch")
    assert invoke(root, "bind", request, ok=False)["error"] == "checkpoint branch changed since acceptance"
    git(ready["worktree"], "switch", ready["branch"])
    before = (brief.copy(), ready.copy())
    binding = invoke(root, "bind", request)
    invoke(root, "ack-handoff", {"endpoint": request["endpoint"], "session": "successor", "generation": 2,
                                 "checkpoint_sha256": binding["checkpoint_sha256"]})
    result = {"source_revision": snapshot["source_revision"], "source_tree": snapshot["source_tree"],
              "checks": [{"check": "tests", "outcome": "not_run", "reference": "evidence/not-run.json"}],
              "lane_check": "evidence/lane.json"}
    completed = message("a/lane/f2", "a/orchestrator", identifier="result", kind="result",
                        in_reply_to="dispatch-1", result=result)
    completed.update(host="host-two", session="successor", binding_generation=2)
    invoke(root, "publish", completed)
    assert (brief, ready) == before
    assert invoke(root, "status")["bindings"]["a/lane/f2"]["generation"] == 2


def test_concurrent_publication_has_one_complete_winner(pilot, tmp_path):
    root, _ = pilot
    source = tmp_path / "concurrent.json"
    source.write_text(json.dumps(message()))
    argv = [sys.executable, str(HELPER), "--root", str(root), "publish", "--request", str(source)]
    processes = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    outputs = [process.communicate(timeout=15) for process in processes]
    assert sorted(p.returncode for p in processes) == [0, 2]
    failures = [json.loads(out)["error"] for p, (out, err) in zip(processes, outputs) if p.returncode == 2]
    assert failures[0] == "message_id already exists: dispatch-1" or "writer is busy" in failures[0]
    assert all(not err for out, err in outputs)
    rows = invoke(root, "inbox", endpoint="a/lane/f2")["messages"]
    assert len(rows) == 1
    assert rows[0]["message"]["body"] == message()["body"]
    assert not list(root.glob("**/.pending-*"))


def test_inbox_pagination_has_explicit_remaining_and_hash_verified_briefs(pilot):
    root, brief = pilot
    for identifier in ("one", "two", "three"):
        invoke(root, "publish", message(identifier=identifier, brief=brief))
    first = invoke(root, "inbox", endpoint="a/lane/f2", limit=2)
    assert [r["message"]["message_id"] for r in first["messages"]] == ["one", "two"]
    assert first["remaining"] == 1
    assert first["next_after"] == "two"
    second = invoke(root, "inbox", endpoint="a/lane/f2", after=first["next_after"], include_briefs=True)
    assert [r["message"]["message_id"] for r in second["messages"]] == ["three"]
    assert second["messages"][0]["brief_text"] == Path(brief["path"]).read_text()
    assert second["remaining"] == 0
    Path(brief["path"]).write_text("Changed brief\n")
    assert invoke(root, "inbox", endpoint="a/lane/f2", include_briefs=True, ok=False)["error"] == "brief sha256 mismatch"


def test_corrupt_binding_history_is_not_silently_skipped(pilot):
    root, _ = pilot
    (root / "bindings" / "a" / "orchestrator" / "000001.json").write_text('{"truncated":')
    assert "error" in invoke(root, "status", ok=False)


def test_writer_cap_is_separate_from_read_only_reviews(pilot, tmp_path):
    original, brief = pilot
    root = tmp_path / "small-mailbox"
    manifest = json.loads((original / "manifest.json").read_text())
    manifest["writer_limit"] = 1
    invoke(root, "init", manifest)
    for endpoint in manifest["endpoints"]:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint, "expected_generation": 0})
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="accept-a", kind="ack",
                                    in_reply_to="dispatch-1", acknowledgment="accepted", readiness=readiness(tmp_path)))
    invoke(root, "publish", message(recipient="a/lane/review", identifier="review-dispatch", kind="dispatch", brief=brief))
    invoke(root, "publish", message("a/lane/review", "a/orchestrator", identifier="accept-review", kind="ack",
                                    in_reply_to="review-dispatch", acknowledgment="accepted"))
    invoke(root, "publish", message("b/orchestrator", "b/lane/f6", identifier="dispatch-b", kind="dispatch", brief=brief))
    ready = readiness(tmp_path, "other-lane", "feature/b-f6")
    ready["lease_ref"] = "refs/aegis/lanes/b-f6"
    result = invoke(root, "publish", message("b/lane/f6", "b/orchestrator", identifier="accept-b", kind="ack",
                                             in_reply_to="dispatch-b", acknowledgment="accepted", readiness=ready), ok=False)
    assert result["error"] == "concurrent writer limit reached"
    assert len(invoke(root, "status")["accepted_writers"]) == 1


def test_git_identity_preserves_spaces_in_worktree_paths(pilot, tmp_path):
    root, brief = pilot
    folder = "writing lane" if os.name == "nt" else "writing lane "
    ready = readiness(tmp_path, folder)
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    result = invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                                             in_reply_to="dispatch-1", acknowledgment="accepted", readiness=ready))
    assert result["message"]["readiness"]["worktree"] == str(tmp_path / folder)


def test_completion_refuses_a_brief_changed_after_acceptance(pilot, tmp_path):
    root, brief = pilot
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                                    in_reply_to="dispatch-1", acknowledgment="accepted", readiness=readiness(tmp_path)))
    Path(brief["path"]).write_text("Scope changed without redispatch\n")
    result = {"source_revision": "a" * 40, "source_tree": "b" * 40,
              "checks": [{"check": "tests", "outcome": "pass", "reference": "evidence/tests.json"}],
              "lane_check": "evidence/lane.json"}
    request = message("a/lane/f2", "a/orchestrator", identifier="result", kind="result",
                      in_reply_to="dispatch-1", result=result)
    assert invoke(root, "publish", request, ok=False)["error"] == "brief sha256 mismatch"
    assert len(invoke(root, "status")["accepted_writers"]) == 1


def test_reviewer_readiness_is_rejected_before_it_can_poison_history(pilot):
    root, brief = pilot
    invoke(root, "publish", message(recipient="a/lane/review", kind="dispatch", brief=brief))
    request = message("a/lane/review", "a/orchestrator", identifier="accepted", kind="ack",
                      in_reply_to="dispatch-1", acknowledgment="accepted", readiness={"forged": True})
    result = invoke(root, "publish", request, ok=False)
    assert result["error"] == "reviewer acceptance must not include writing readiness"
    assert invoke(root, "status")["messages"] == 1


@pytest.mark.skipif(os.name == "nt", reason="fake executable fixture uses a POSIX shebang")
def test_git_readiness_timeout_is_an_explicit_failure(pilot, tmp_path, monkeypatch):
    root, brief = pilot
    ready = readiness(tmp_path)
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    executable = tmp_path / "bin"
    executable.mkdir()
    fake_git = executable / "git"
    fake_git.write_text("#!" + sys.executable + "\nimport time\ntime.sleep(10)\n")
    fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(executable) + os.pathsep + os.environ.get("PATH", ""))
    request = message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                      in_reply_to="dispatch-1", acknowledgment="accepted", readiness=ready)
    assert invoke(root, "publish", request, ok=False)["error"] == "git identity check timed out"
    assert invoke(root, "status")["messages"] == 1


@pytest.mark.parametrize("kind,error", [("directory", "input must be a regular file"),
                                        ("oversized", "input exceeds 262144 bytes")])
def test_nonregular_and_oversized_requests_leave_no_message(pilot, tmp_path, kind, error):
    root, _ = pilot
    source = root
    if kind == "oversized":
        source = tmp_path / "oversized.json"
        source.write_bytes(b" " * 262145)
    assert invoke(root, "publish", request_file=source, ok=False)["error"] == error
    assert invoke(root, "status")["messages"] == 0


def test_malformed_manifest_does_not_create_partial_mailbox(tmp_path):
    root = tmp_path / "mailbox"
    manifest = json.loads((ROOT / "tools/hierarchy_templates/manifest.json").read_text())
    manifest["endpoints"]["a/lane/f2"]["kind"] = []
    assert invoke(root, "init", manifest, ok=False)["error"] == "invalid lane kind"
    assert not root.exists()


def test_a_manifest_may_allow_the_owners_five_writers_but_not_six(tmp_path):
    manifest = json.loads((ROOT / "tools/hierarchy_templates/manifest.json").read_text())
    manifest["writer_limit"] = 5
    invoke(tmp_path / "five", "init", manifest)
    assert json.loads((tmp_path / "five" / "manifest.json").read_text())["writer_limit"] == 5
    manifest["writer_limit"] = 6
    assert invoke(tmp_path / "six", "init", manifest, ok=False)["error"] == "invalid writer_limit"
    assert not (tmp_path / "six").exists()


def test_unicode_checkpoint_expansion_cannot_publish_an_unreadable_binding(pilot, tmp_path):
    root, brief = pilot
    checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [], "lease_refs": [],
                  "completed_checks": ["é" * 4096] * 29, "pending_message_ids": [], "last_acknowledgment_ids": []}
    request = {"endpoint": "a/front-door", "host": "host-two", "session": "replacement",
               "expected_generation": 1, "checkpoint": checkpoint}
    source = tmp_path / "unicode-request.json"
    raw = json.dumps(request, ensure_ascii=False).encode("utf-8")
    assert len(raw) < 262144
    source.write_bytes(raw)
    result = invoke(root, "bind", request_file=source, ok=False)
    assert result["error"] == "record exceeds 262144 bytes"
    assert invoke(root, "status")["bindings"]["a/front-door"]["generation"] == 1
    assert not (root / "bindings/a/front-door/000002.json").exists()


@pytest.mark.parametrize("kind", ["messages", "bindings"])
def test_full_history_refuses_append_and_remains_readable(pilot, kind):
    root, brief = pilot
    if kind == "messages":
        seed = invoke(root, "publish", message(identifier="seed"))
        header = {key: value for key, value in seed["message"].items() if key != "body"}
        folder = Path(seed["path"]).parent
        for number in range(1, 10000):
            header["message_id"] = "capacity-%05d" % number
            raw = "---\n" + json.dumps(header, sort_keys=True) + "\n---\n\n" + seed["message"]["body"]
            (folder / ("20261101T000000000000Z-orchestrator-to-lane-capacity-%05d.md" % number)).write_bytes(raw.encode("utf-8"))
        result = invoke(root, "publish", message(identifier="overflow"), ok=False, process_timeout=60)
        assert result["error"] == "mailbox history limit reached"
        assert invoke(root, "status", process_timeout=60)["messages"] == 10000
    else:
        folder = root / "bindings/a/front-door"
        seed = json.loads((folder / "000001.json").read_text())
        checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [], "lease_refs": [],
                      "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
        canonical = json.dumps(checkpoint, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        for number in range(2, 10001):
            record = {**seed, "generation": number, "checkpoint": checkpoint,
                      "checkpoint_sha256": hashlib.sha256(canonical).hexdigest()}
            (folder / ("%06d.json" % number)).write_text(json.dumps(record))
        request = {"endpoint": "a/front-door", "host": "host-two", "session": "replacement",
                   "expected_generation": 10000, "checkpoint": checkpoint}
        result = invoke(root, "bind", request, ok=False, process_timeout=60)
        assert result["error"] == "binding history limit reached"
        assert invoke(root, "status", process_timeout=60)["bindings"]["a/front-door"]["generation"] == 10000
        assert not (folder / "010001.json").exists()


# Public P1 contract, deliberately independent of the product's internal constants.
INBOX_WIRE_BUDGET = 4194304
WIRE_PAYLOADS = [
    pytest.param("x" * 262144, id="ascii"),
    pytest.param("é" * 131072, id="unicode"),
    pytest.param('é"\\\n😀' * 26000, id="escapes"),
]


def mailbox_snapshot(root):
    """Include referenced briefs and request fixtures as well as durable mailbox files."""
    return {p.relative_to(root.parent).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.parent.rglob("*")
            if p.is_file() and p.relative_to(root.parent).parts[0] != "wire-evidence"}


def record_wire_process(root, argv, result, stdin=None):
    """Retain exact subprocess evidence even when the next behavioral assertion fails."""
    directory = root.parent / "wire-evidence"
    directory.mkdir(exist_ok=True)
    call = directory / ("%04d" % len(list(directory.iterdir())))
    call.mkdir()
    (call / "stdout.bin").write_bytes(result.stdout)
    (call / "stderr.bin").write_bytes(result.stderr)
    (call / "command.json").write_text(json.dumps({"argv": argv, "returncode": result.returncode}) + "\n")
    if stdin is not None:
        (call / "stdin.bin").write_bytes(stdin)
    return call


def wire_brief(root, name, content):
    path = root.parent / name
    raw = content.encode("utf-8")
    assert len(raw) <= 262144  # A valid existing input, without relaxing its bound.
    path.write_bytes(raw)
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


def seed_wire_inbox(root, content, *, endpoint="a/lane/f2", count=20, final_content=None):
    final_content = content if final_content is None else final_content
    shared = wire_brief(root, root.name + "-wire-shared.md", content)
    final = wire_brief(root, root.name + "-wire-final.md", final_content)
    rows = []
    for number in range(count):
        reference = final if number == count - 1 else shared
        request = message(recipient=endpoint, identifier="wire-%03d" % number, brief=reference)
        request["body"] = 'Record %d: é, "quotes", \\backslash,\n😀\r\n' % number
        receipt = invoke(root, "publish", request)
        assert hashlib.sha256(Path(receipt["path"]).read_bytes()).hexdigest() == receipt["sha256"]
        rows.append({"path": receipt["path"], "message": receipt["message"],
                     "brief_text": final_content if number == count - 1 else content})
    return rows


def wire_peer_mailbox(root, name):
    peer = root.parent / name
    manifest = json.loads((root / "manifest.json").read_text())
    invoke(peer, "init", manifest)
    for endpoint in manifest["endpoints"]:
        invoke(peer, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    return peer


def checkpoint_wire_binding(root, content, copies, *, endpoint="a/lane/f2"):
    reference = wire_brief(root, "wire-checkpoint.md", content)
    checkpoint = {"outgoing_stopped": True, "briefs": [reference] * copies,
                  "sources": [], "lease_refs": [], "completed_checks": [],
                  "pending_message_ids": [], "last_acknowledgment_ids": []}
    binding = invoke(root, "bind", {"endpoint": endpoint, "host": "host-two", "session": "replacement",
                                   "expected_generation": 1, "checkpoint": checkpoint})
    assert binding["checkpoint"] == checkpoint
    assert binding["ready"] is False
    return binding


def cli_inbox_wire(root, *, endpoint="a/lane/f2", include_briefs=True, limit=None, after=None, ok=True):
    argv = [sys.executable, "-B", str(HELPER), "--root", str(root), "inbox", "--endpoint", endpoint]
    if include_briefs:
        argv.append("--include-briefs")
    if limit is not None:
        argv += ["--limit", str(limit)]
    if after is not None:
        argv += ["--after", after]
    result = subprocess.run(argv, capture_output=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    evidence = record_wire_process(root, argv, result)
    assert result.returncode == (0 if ok else 2), (str(evidence), result.stdout[:2048], result.stderr[:2048])
    assert result.stderr == b""
    assert result.stdout.endswith(b"\n")
    assert len(result.stdout.splitlines(keepends=True)) == 1
    return result.stdout, json.loads(result.stdout.decode("utf-8"))


@pytest.mark.parametrize("content", WIRE_PAYLOADS)
def test_cli_bounded_inbox_wire_pages_are_lossless(pilot, content):
    root, _ = pilot
    expected = seed_wire_inbox(root, content)
    binding = invoke(root, "status")["bindings"]["a/lane/f2"]
    before = mailbox_snapshot(root)
    received, cursor = [], None
    for page_number in range(len(expected) + 1):
        raw, page = cli_inbox_wire(root, after=cursor)
        assert len(raw) <= INBOX_WIRE_BUDGET, "CLI inbox wire budget exceeded; raw evidence: " + str(root.parent / "wire-evidence")
        assert page["endpoint"] == "a/lane/f2"
        assert page["binding"] == binding
        assert page["checkpoint_briefs"] == []
        assert page["messages"], "nonempty eligible history must make cursor progress"
        end = len(received) + len(page["messages"])
        assert page["messages"] == expected[len(received):end]
        received.extend(page["messages"])
        assert page["remaining"] == len(expected) - len(received)
        if page_number == 0:
            assert 0 < len(page["messages"]) < 20
        if not page["remaining"]:
            assert page["next_after"] is None
            break
        assert page["next_after"] == received[-1]["message"]["message_id"]
        assert page["next_after"] != cursor
        cursor = page["next_after"]
    assert received == expected
    for limit in (1, 100):
        raw, page = cli_inbox_wire(root, include_briefs=False, limit=limit)
        count = min(limit, len(expected))
        assert len(raw) <= INBOX_WIRE_BUDGET
        assert page["messages"] == [{"path": r["path"], "message": r["message"]} for r in expected[:count]]
        assert page["remaining"] == len(expected) - count
        assert page["next_after"] == (expected[count - 1]["message"]["message_id"] if page["remaining"] else None)
    raw, exhausted = cli_inbox_wire(root, after=expected[-1]["message"]["message_id"])
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert exhausted == {"endpoint": "a/lane/f2", "binding": binding, "checkpoint_briefs": [],
                         "messages": [], "remaining": 0, "next_after": None}
    assert mailbox_snapshot(root) == before


def test_cli_bounded_inbox_checkpoint_metadata_is_mandatory(pilot):
    root, _ = pilot
    binding = checkpoint_wire_binding(root, "x" * 262144, 20)
    before = mailbox_snapshot(root)
    raw, error = cli_inbox_wire(root, ok=False)
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert error == {"error": "inbox response metadata exceeds 4194304 bytes"}
    raw, small = cli_inbox_wire(root, include_briefs=False)
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert small == {"endpoint": "a/lane/f2", "binding": binding, "checkpoint_briefs": [],
                     "messages": [], "remaining": 0, "next_after": None}
    assert mailbox_snapshot(root) == before  # No implicit handoff ack, rewrite or history append.


def test_cli_bounded_inbox_exact_wire_boundary(pilot):
    root, _ = pilot
    # Equal-length root names preserve framing overhead. Calibrate only from bytes
    # emitted by the public CLI; do not reproduce its serializer or budget formula.
    seed = wire_peer_mailbox(root, "edge-seed")
    seed_wire_inbox(seed, "x" * 262144, count=16, final_content="x" * 200000)
    raw, page = cli_inbox_wire(seed, limit=100)
    assert len(page["messages"]) == 16
    padding = INBOX_WIRE_BUDGET - len(raw)
    assert 0 < padding < 262144 - 200000
    fit = wire_peer_mailbox(root, "edge-fit0")
    expected = seed_wire_inbox(fit, "x" * 262144, count=16, final_content="x" * (200000 + padding))
    raw, page = cli_inbox_wire(fit, limit=100)
    assert len(raw) == INBOX_WIRE_BUDGET  # Includes the terminating newline.
    assert page["messages"] == expected
    assert page["remaining"] == 0 and page["next_after"] is None
    over = wire_peer_mailbox(root, "edge-over")
    expected = seed_wire_inbox(over, "x" * 262144, count=16, final_content="x" * (200001 + padding))
    before = mailbox_snapshot(over)
    raw, page = cli_inbox_wire(over, limit=100)
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert page["messages"] == expected[:-1]
    assert page["remaining"] == 1
    assert page["next_after"] == expected[-2]["message"]["message_id"]
    raw, last = cli_inbox_wire(over, limit=100, after=page["next_after"])
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert last["messages"] == expected[-1:]
    assert last["remaining"] == 0 and last["next_after"] is None
    assert mailbox_snapshot(over) == before


def test_cli_bounded_inbox_first_message_cannot_be_skipped(pilot):
    root, _ = pilot
    binding = checkpoint_wire_binding(root, "x" * 262144, 15)
    raw, metadata = cli_inbox_wire(root)
    assert len(raw) <= INBOX_WIRE_BUDGET  # Observe fitting mandatory state through the public CLI.
    assert metadata["binding"] == binding
    assert metadata["messages"] == []
    assert metadata["checkpoint_briefs"] == [
        {**reference, "text": "x" * 262144} for reference in binding["checkpoint"]["briefs"]]
    expected = seed_wire_inbox(root, "x" * 262144, count=2)
    before = mailbox_snapshot(root)
    raw, error = cli_inbox_wire(root, ok=False)
    assert len(raw) <= INBOX_WIRE_BUDGET
    assert error == {"error": "inbox first message cannot fit 4194304 byte response budget"}
    _, small = cli_inbox_wire(root, include_briefs=False)
    assert small["messages"] == [{"path": r["path"], "message": r["message"]} for r in expected]
    assert small["binding"] == binding
    assert small["remaining"] == 0 and small["next_after"] is None
    assert mailbox_snapshot(root) == before


@pytest.mark.parametrize("limit", [0, 101])
def test_cli_bounded_inbox_retains_limit_errors(pilot, limit):
    root, _ = pilot
    before = mailbox_snapshot(root)
    _, error = cli_inbox_wire(root, limit=limit, ok=False)
    assert error == {"error": "invalid inbox limit"}
    assert mailbox_snapshot(root) == before


@pytest.mark.parametrize("cursor", ["missing", "foreign"])
def test_cli_bounded_inbox_retains_cursor_errors(pilot, cursor):
    root, _ = pilot
    seed_wire_inbox(root, "x" * 262144)
    invoke(root, "publish", message(recipient="a/lane/review", identifier="foreign"))
    before = mailbox_snapshot(root)
    _, error = cli_inbox_wire(root, after=cursor, ok=False)
    assert error == {"error": "inbox cursor does not name a received message"}
    assert mailbox_snapshot(root) == before


def corrupt_wire_fixture(root, rows, kind):
    if kind == "missing-brief":
        path = Path(rows[-1]["message"]["brief"]["path"])
        path.unlink()
        return "file unavailable: " + str(path)
    if kind in {"first-brief", "deferred-brief"}:
        row = rows[0] if kind == "first-brief" else rows[-1]
        Path(row["message"]["brief"]["path"]).write_bytes(b"Changed after publication\n")
        return "brief sha256 mismatch"
    if kind == "history":
        path = Path(rows[-1]["path"])
        path.write_bytes(b"truncated message")
        return "malformed mailbox message: " + str(path) + ": missing header"
    path = root / "bindings/a/lane/f2/000001.json"
    binding = json.loads(path.read_text())
    binding["endpoint"] = "b/lane/f6"
    path.write_text(json.dumps(binding))
    return "malformed role binding"


@pytest.mark.parametrize("kind", ["first-brief", "deferred-brief", "missing-brief", "history", "binding"])
def test_cli_bounded_inbox_does_not_hide_corruption(pilot, kind):
    root, _ = pilot
    rows = seed_wire_inbox(root, "x" * 262144)
    error = corrupt_wire_fixture(root, rows, kind)
    before = mailbox_snapshot(root)
    _, result = cli_inbox_wire(root, ok=False)
    assert result == {"error": error}
    assert mailbox_snapshot(root) == before


def test_binding_only_inbox_is_small_hash_checked_and_read_only(pilot):
    root, _ = pilot
    for identifier in ("one", "two", "three"):
        invoke(root, "publish", message(identifier=identifier))
    binding = checkpoint_wire_binding(root, "x" * 200000, 2)
    brief = binding["checkpoint"]["briefs"][0]
    before = mailbox_snapshot(root)
    view = invoke(root, "inbox", endpoint="a/lane/f2", binding_only=True)
    assert view == {"endpoint": "a/lane/f2", "binding": binding, "messages_total": 3,
                    "checkpoint_briefs": [{**brief, "ok": True}, {**brief, "ok": True}]}
    assert len(json.dumps(view)) < 4096  # A 200 KB brief is hashed, never returned.
    assert mailbox_snapshot(root) == before
    assert invoke(root, "inbox", endpoint="a/lane/review", binding_only=True) == {
        "endpoint": "a/lane/review", "binding": invoke(root, "status")["bindings"]["a/lane/review"],
        "checkpoint_briefs": [], "messages_total": 0}
    Path(brief["path"]).write_text("Changed after the handoff\n")
    changed = invoke(root, "inbox", endpoint="a/lane/f2", binding_only=True)
    assert changed["checkpoint_briefs"] == [{**brief, "ok": False}, {**brief, "ok": False}]
    Path(brief["path"]).unlink()
    assert invoke(root, "inbox", endpoint="a/lane/f2", binding_only=True)["checkpoint_briefs"][0]["ok"] is False


def stdin_argv(root, command):
    return [sys.executable, "-B", str(HELPER), "--root", str(root), command, "--request", "-"]


def invoke_stdin(root, command, raw, *, ok=True):
    result = subprocess.run(stdin_argv(root, command), input=raw, capture_output=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == (0 if ok else 2), result.stdout[:2048] + result.stderr[:2048]
    assert result.stderr == b""
    return json.loads(result.stdout)


def test_publish_and_ack_handoff_read_the_request_from_stdin(pilot):
    root, brief = pilot
    receipt = invoke_stdin(root, "publish", json.dumps(message()).encode("utf-8"))
    assert hashlib.sha256(Path(receipt["path"]).read_bytes()).hexdigest() == receipt["sha256"]
    assert receipt["message"]["message_id"] == "dispatch-1"
    checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [], "lease_refs": [],
                  "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
    replacement = invoke(root, "bind", {"endpoint": "a/lane/f2", "host": "host-two", "session": "replacement",
                                        "expected_generation": 1, "checkpoint": checkpoint})
    ack = {"endpoint": "a/lane/f2", "session": "replacement", "generation": 2,
           "checkpoint_sha256": replacement["checkpoint_sha256"]}
    assert invoke_stdin(root, "ack-handoff", json.dumps(ack).encode("utf-8")) == {
        "endpoint": "a/lane/f2", "generation": 2, "ready": True, "observed_sources": []}


@pytest.mark.parametrize("command,raw,error", [
    ("publish", b" " * 262145, "input exceeds 262144 bytes"),
    ("publish", b"", "Expecting value: line 1 column 1 (char 0)"),
    ("ack-handoff", b'{"endpoint": "a", "endpoint": "b"}', "duplicate JSON key: endpoint"),
    ("bind", b"{}", "--request - (stdin) is only for publish and ack-handoff"),
    ("draft-handoff", b"{}", "--request - (stdin) is only for publish and ack-handoff"),
    ("init", b"{}", "--request - (stdin) is only for publish and ack-handoff"),
], ids=["oversized", "empty", "duplicate-key", "bind", "draft-handoff", "init"])
def test_stdin_requests_are_bounded_strict_and_limited_to_two_commands(pilot, command, raw, error):
    root, _ = pilot
    before = mailbox_snapshot(root)
    assert invoke_stdin(root, command, raw, ok=False) == {"error": error}
    assert mailbox_snapshot(root) == before
    assert not (root / ".write.lock").exists()


def test_held_open_stdin_never_holds_the_writer_lock(pilot):
    root, _ = pilot
    raw = json.dumps(message()).encode("utf-8")
    process = subprocess.Popen(stdin_argv(root, "publish"), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        process.stdin.write(raw[:10])
        process.stdin.flush()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            assert process.poll() is None
            assert not (root / ".write.lock").exists()
            time.sleep(0.05)
        invoke(root, "publish", message(identifier="other-writer"))  # Not refused as busy meanwhile.
        stdout, stderr = process.communicate(input=raw[10:], timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert process.returncode == 0 and stderr == b""
    assert json.loads(stdout)["message"]["message_id"] == "dispatch-1"


@pytest.mark.parametrize("argv,error", [
    (["--root", "rel/mailbox", "status"], "--root must be absolute without traversal: got 'rel/mailbox'"),
    (["--root", "/abs/../mailbox", "status"], "--root must be absolute without traversal: got '/abs/../mailbox'"),
    (["publish", "--request", "rel.json"], "--request must be absolute without traversal: got 'rel.json'"),
    (["init", "--request", "requests/x.json"], "--request must be absolute without traversal: got 'requests/x.json'"),
    (["bind", "--request", "/abs/../x.json"], "--request must be absolute without traversal: got '/abs/../x.json'"),
])
def test_cli_path_refusals_name_the_argument_and_its_value(pilot, argv, error):
    root, _ = pilot
    if argv[0] != "--root":
        argv = ["--root", str(root), *argv]
    before = mailbox_snapshot(root)
    result = subprocess.run([sys.executable, "-B", str(HELPER), *argv], capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2 and not result.stderr
    assert json.loads(result.stdout) == {"error": error}
    assert mailbox_snapshot(root) == before


def test_inbox_help_states_the_limit_default_and_maximum():
    result = subprocess.run([sys.executable, "-B", str(HELPER), "--root", "/unused", "inbox", "--help"],
                            capture_output=True, text=True, timeout=15, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0 and not result.stderr
    assert "default 20, maximum 100" in " ".join(result.stdout.split())


@pytest.mark.parametrize("flags", [{"include_briefs": True}, {"limit": 5}, {"after": "one"},
                                   {"mark_read": True, "delivery_dir": "/tmp/unused"}])
def test_binding_only_inbox_refuses_paging_flags(pilot, flags):
    root, _ = pilot
    invoke(root, "publish", message(identifier="one"))
    result = invoke(root, "inbox", endpoint="a/lane/f2", binding_only=True, ok=False, **flags)
    assert result == {"error": "--binding-only takes no --include-briefs, --limit, --after or --mark-read"}
