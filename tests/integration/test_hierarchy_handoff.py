"""Handoffs bind through a dirty-state digest and one command rotates several endpoints."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, git, invoke, message, pilot, readiness  # noqa: F401


HANDOFF = ROOT / "tools" / "hierarchy_handoff.py"


def raw_status(worktree):
    return subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=worktree,
                          capture_output=True, check=True, timeout=30).stdout


def active_writer(pilot, tmp_path):  # noqa: F811
    root, brief = pilot
    ready = readiness(tmp_path)
    invoke(root, "publish", message(kind="dispatch", brief=brief))
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="accepted", kind="ack",
                                    in_reply_to="dispatch-1", acknowledgment="accepted", readiness=ready))
    return root, brief, ready


def draft(root, endpoint="a/lane/f2", **changes):
    return {"endpoint": endpoint, "host": "host-two", "session": "successor", "outgoing_stopped": True, **changes}


def mailbox_files(root):
    return {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.skipif(os.name == "nt", reason="the deep path fixture exceeds Windows path limits")
def test_a_dirty_state_over_three_megabytes_binds_through_a_digest(pilot, tmp_path):  # noqa: F811
    root, _, ready = active_writer(pilot, tmp_path)
    worktree = Path(ready["worktree"])
    deep = worktree.joinpath(*["d" * 200] * 10)
    deep.mkdir(parents=True)
    for index in range(1500):
        (deep / ("%04d.txt" % index)).touch()
    raw = raw_status(worktree)
    assert len(raw) > 3000000
    evidence = tmp_path / "evidence"
    request = invoke(root, "draft-handoff", draft(root, evidence_dir=str(evidence)), process_timeout=60)
    source = request["checkpoint"]["sources"][0]
    assert source["dirty_state_sha256"] == hashlib.sha256(raw).hexdigest()
    assert source["dirty_entries"] == 1500
    assert "dirty_state" not in source
    assert Path(source["dirty_evidence"]).read_bytes() == raw
    binding = invoke(root, "bind", request, process_timeout=60)
    assert binding["generation"] == 2 and binding["ready"] is False
    invoke(root, "ack-handoff", {"endpoint": "a/lane/f2", "session": "successor", "generation": 2,
                                 "checkpoint_sha256": binding["checkpoint_sha256"]}, process_timeout=60)
    assert invoke(root, "status", process_timeout=60)["bindings"]["a/lane/f2"]["ready"] is True


@pytest.mark.parametrize("place,error", [
    (lambda root: root / "a" / "lane", "evidence directory must be outside the mailbox root"),
    (lambda root: root.parent, "evidence directory must not contain the mailbox root"),
])
def test_status_evidence_cannot_land_in_or_above_mailbox_history(pilot, tmp_path, place, error):  # noqa: F811
    root, _, ready = active_writer(pilot, tmp_path)
    (Path(ready["worktree"]) / "untracked.txt").write_text("makes the status non-empty")
    refused = invoke(root, "draft-handoff", draft(root, evidence_dir=str(place(root))), ok=False)
    assert refused["error"] == error
    assert invoke(root, "inbox", endpoint="a/lane/f2")["messages"]


def test_status_that_changes_after_the_draft_is_refused(pilot, tmp_path):  # noqa: F811
    root, _, ready = active_writer(pilot, tmp_path)
    request = invoke(root, "draft-handoff", draft(root))
    (Path(ready["worktree"]) / "appeared-later.txt").write_text("new")
    refused = invoke(root, "bind", request, ok=False)
    assert refused["error"] == "checkpoint source snapshot does not match worktree"
    assert invoke(root, "status")["bindings"]["a/lane/f2"]["generation"] == 1


def test_leading_status_whitespace_is_preserved(pilot, tmp_path):  # noqa: F811
    root, _, ready = active_writer(pilot, tmp_path)
    worktree = Path(ready["worktree"])
    (worktree / "source.txt").write_text("changed\n")
    raw = raw_status(worktree)
    assert raw.startswith(b" M source.txt")
    request = invoke(root, "draft-handoff", draft(root))
    assert request["checkpoint"]["sources"][0]["dirty_state_sha256"] == hashlib.sha256(raw).hexdigest()
    assert request["checkpoint"]["sources"][0]["dirty_entries"] == 1
    assert invoke(root, "bind", request)["generation"] == 2


def test_renames_count_as_one_status_entry(pilot, tmp_path):  # noqa: F811
    root, _, ready = active_writer(pilot, tmp_path)
    git(ready["worktree"], "mv", "source.txt", "renamed.txt")
    source = invoke(root, "draft-handoff", draft(root))["checkpoint"]["sources"][0]
    assert source["dirty_entries"] == 1


def test_a_clean_worktree_has_zero_entries_and_a_stable_digest(pilot, tmp_path):  # noqa: F811
    root, _, _ = active_writer(pilot, tmp_path)
    source = invoke(root, "draft-handoff", draft(root))["checkpoint"]["sources"][0]
    assert source["dirty_entries"] == 0
    assert source["dirty_state_sha256"] == hashlib.sha256(b"").hexdigest()


def test_literal_and_digest_bindings_coexist_in_history(pilot, tmp_path):  # noqa: F811
    root, brief, ready = active_writer(pilot, tmp_path)
    worktree = ready["worktree"]
    literal = {"worktree": worktree, "source_revision": git(worktree, "rev-parse", "HEAD"),
               "source_tree": git(worktree, "rev-parse", "HEAD^{tree}"), "dirty_state": "clean"}
    checkpoint = {"outgoing_stopped": True, "briefs": [brief], "sources": [literal],
                  "lease_refs": [ready["lease_ref"]], "completed_checks": [],
                  "pending_message_ids": ["dispatch-1"], "last_acknowledgment_ids": ["accepted"]}
    first = invoke(root, "bind", {"endpoint": "a/lane/f2", "host": "host-two", "session": "literal-successor",
                                  "expected_generation": 1, "checkpoint": checkpoint})
    assert first["generation"] == 2
    second = invoke(root, "bind", invoke(root, "draft-handoff", draft(root)))
    assert second["generation"] == 3
    assert invoke(root, "status")["bindings"]["a/lane/f2"]["generation"] == 3


@pytest.mark.parametrize("change,error", [
    ({"dirty_state": "clean"}, "checkpoint source mixes literal and digest dirty state"),
    ({"dirty_state_sha256": "not-a-digest"}, "invalid dirty state digest"),
    ({"dirty_entries": -1}, "invalid dirty entries"),
    ({"dirty_entries": True}, "invalid dirty entries"),
    ({"dirty_entries": None}, "invalid dirty entries"),
    ({"dirty_evidence": ""}, "invalid dirty evidence"),
    ({"unexpected": 1}, "unexpected fields"),
])
def test_malformed_digest_sources_are_refused(pilot, tmp_path, change, error):  # noqa: F811
    root, _, _ = active_writer(pilot, tmp_path)
    request = invoke(root, "draft-handoff", draft(root))
    request["checkpoint"]["sources"][0].update(change)
    refused = invoke(root, "bind", request, ok=False)
    assert error in refused["error"]
    assert invoke(root, "status")["bindings"]["a/lane/f2"]["generation"] == 1


def test_a_missing_dirty_field_is_refused(pilot, tmp_path):  # noqa: F811
    root, _, _ = active_writer(pilot, tmp_path)
    request = invoke(root, "draft-handoff", draft(root))
    del request["checkpoint"]["sources"][0]["dirty_state_sha256"]
    assert "invalid dirty state digest" in invoke(root, "bind", request, ok=False)["error"]


def test_the_draft_collects_the_assignment_and_writes_nothing_to_the_mailbox(pilot, tmp_path):  # noqa: F811
    root, brief, ready = active_writer(pilot, tmp_path)
    before = mailbox_files(root)
    request = invoke(root, "draft-handoff", draft(root, completed_checks=["focused tests passed"]))
    assert mailbox_files(root) == before
    checkpoint = request["checkpoint"]
    assert request["expected_generation"] == 1
    assert checkpoint["outgoing_stopped"] is True
    assert checkpoint["briefs"] == [brief]
    assert checkpoint["lease_refs"] == [ready["lease_ref"]]
    assert checkpoint["pending_message_ids"] == ["dispatch-1"]
    assert checkpoint["last_acknowledgment_ids"] == ["accepted"]
    assert checkpoint["completed_checks"] == ["focused tests passed"]
    assert checkpoint["sources"][0]["worktree"] == ready["worktree"]


def test_the_orchestrator_draft_also_covers_its_active_lane(pilot, tmp_path):  # noqa: F811
    root, _, ready = active_writer(pilot, tmp_path)
    request = invoke(root, "draft-handoff", draft(root, endpoint="a/orchestrator"))
    assert request["checkpoint"]["pending_message_ids"] == ["dispatch-1"]
    assert request["checkpoint"]["sources"][0]["worktree"] == ready["worktree"]
    assert invoke(root, "bind", request)["generation"] == 2


def orchestrator_successor(root, brief, ready, shape="digest"):
    """Bind the orchestrator's successor at generation 2, unacked, over a snapshot of the lane as it is now."""
    if shape == "digest":
        request = invoke(root, "draft-handoff", draft(root, endpoint="a/orchestrator"))
    else:
        worktree = ready["worktree"]
        literal = {"worktree": worktree, "source_revision": git(worktree, "rev-parse", "HEAD"),
                   "source_tree": git(worktree, "rev-parse", "HEAD^{tree}"), "dirty_state": "clean"}
        request = {"endpoint": "a/orchestrator", "host": "host-two", "session": "successor", "expected_generation": 1,
                   "checkpoint": {"outgoing_stopped": True, "briefs": [brief], "sources": [literal],
                                  "lease_refs": [ready["lease_ref"]], "completed_checks": [],
                                  "pending_message_ids": ["dispatch-1"], "last_acknowledgment_ids": ["accepted"]}}
    binding = invoke(root, "bind", request)
    assert binding["generation"] == 2 and binding["ready"] is False
    return {"endpoint": "a/orchestrator", "session": "successor", "generation": 2,
            "checkpoint_sha256": binding["checkpoint_sha256"]}


def orchestrator_ack(root):
    return root / "bindings" / "a" / "orchestrator" / "000002.ack"


def commit(worktree, text, subject):
    (Path(worktree) / "source.txt").write_text(text)
    git(worktree, "commit", "-qam", subject)
    return git(worktree, "rev-parse", "HEAD")


@pytest.mark.parametrize("shape", ["digest", "literal"])
def test_an_unacked_successor_acks_while_its_lane_moves_forward(pilot, tmp_path, shape):  # noqa: F811
    # Given a successor whose checkpoint snapshots the accepted lane at commit A, clean
    root, brief, ready = active_writer(pilot, tmp_path)
    worktree = ready["worktree"]
    snapshot = git(worktree, "rev-parse", "HEAD")
    ack = orchestrator_successor(root, brief, ready, shape)
    # When the lane commits B on A and leaves one dirty file
    head = commit(worktree, "moved forward\n", "B")
    assert git(worktree, "rev-parse", "HEAD^") == snapshot
    (Path(worktree) / "notes.txt").write_text("still editing\n")
    acknowledged = invoke(root, "ack-handoff", ack)
    # Then the ack passes, reports what it saw, and the .ack file keeps exactly its four keys
    assert acknowledged["ready"] is True
    assert acknowledged["observed_sources"] == [{
        "worktree": worktree, "source_revision": head, "source_tree": git(worktree, "rev-parse", "HEAD^{tree}"),
        "dirty_entries": 1, "dirty_state_sha256": hashlib.sha256(raw_status(worktree)).hexdigest()}]
    assert json.loads(orchestrator_ack(root).read_text(encoding="utf-8")) == ack
    assert sorted(ack) == ["checkpoint_sha256", "endpoint", "generation", "session"]
    assert invoke(root, "status")["bindings"]["a/orchestrator"]["ready"] is True


@pytest.mark.parametrize("shape", ["digest", "literal"])
def test_a_lane_reset_off_its_snapshot_refuses_the_ack(pilot, tmp_path, shape):  # noqa: F811
    root, brief, ready = active_writer(pilot, tmp_path)
    worktree = ready["worktree"]
    baseline = git(worktree, "rev-parse", "HEAD")
    commit(worktree, "A\n", "A")
    ack = orchestrator_successor(root, brief, ready, shape)
    git(worktree, "reset", "-q", "--hard", baseline)
    commit(worktree, "C, a sibling of A\n", "C")
    refused = invoke(root, "ack-handoff", ack, ok=False)
    assert refused["error"] == "checkpoint source moved off its snapshot: " + worktree
    assert not orchestrator_ack(root).exists()
    assert invoke(root, "status")["bindings"]["a/orchestrator"]["ready"] is False


def test_a_snapshot_revision_git_cannot_read_is_a_git_failure_not_a_lineage_refusal(pilot, tmp_path):  # noqa: F811
    root, brief, ready = active_writer(pilot, tmp_path)
    worktree = ready["worktree"]
    baseline = git(worktree, "rev-parse", "HEAD")
    commit(worktree, "A\n", "A")
    ack = orchestrator_successor(root, brief, ready)
    git(worktree, "reset", "-q", "--hard", baseline)
    git(worktree, "reflog", "expire", "--expire=now", "--all")
    git(worktree, "gc", "-q", "--prune=now")
    refused = invoke(root, "ack-handoff", ack, ok=False)
    assert refused["error"] == "git identity check failed"
    assert not orchestrator_ack(root).exists()


def test_a_lane_on_another_branch_refuses_the_ack(pilot, tmp_path):  # noqa: F811
    root, brief, ready = active_writer(pilot, tmp_path)
    ack = orchestrator_successor(root, brief, ready)
    git(ready["worktree"], "switch", "-q", "-c", "elsewhere")
    refused = invoke(root, "ack-handoff", ack, ok=False)
    assert refused["error"] == "checkpoint branch changed since acceptance"
    assert not orchestrator_ack(root).exists()


def test_bind_still_refuses_a_lane_that_moved_forward(pilot, tmp_path):  # noqa: F811
    root, _, ready = active_writer(pilot, tmp_path)
    request = invoke(root, "draft-handoff", draft(root, endpoint="a/orchestrator"))
    commit(ready["worktree"], "moved forward\n", "B")
    refused = invoke(root, "bind", request, ok=False)
    assert refused["error"] == "checkpoint source snapshot does not match worktree"
    assert invoke(root, "status")["bindings"]["a/orchestrator"]["generation"] == 1


def test_a_dispatch_closed_by_its_result_is_not_checked_at_ack(pilot, tmp_path):  # noqa: F811
    root, brief, ready = active_writer(pilot, tmp_path)
    worktree = ready["worktree"]
    ack = orchestrator_successor(root, brief, ready)
    result = {"source_revision": git(worktree, "rev-parse", "HEAD"),
              "source_tree": git(worktree, "rev-parse", "HEAD^{tree}"),
              "checks": [{"check": "tests", "outcome": "pass", "reference": "evidence/tests.json"}],
              "lane_check": "evidence/lane.json"}
    invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="result", kind="result",
                                    in_reply_to="dispatch-1", result=result))
    git(worktree, "switch", "-q", "--orphan", "elsewhere")
    (Path(worktree) / "notes.txt").write_text("no commit, other branch, dirty\n")
    acknowledged = invoke(root, "ack-handoff", ack)
    assert acknowledged["ready"] is True
    assert acknowledged["observed_sources"] == []


def test_the_draft_requires_a_stopped_outgoing_session(pilot, tmp_path):  # noqa: F811
    root, _, _ = active_writer(pilot, tmp_path)
    refused = invoke(root, "draft-handoff", draft(root, outgoing_stopped=False), ok=False)
    assert refused["error"] == "outgoing session must be stopped before replacement"


def test_a_draft_with_no_brief_anywhere_is_refused_until_one_is_given(pilot):  # noqa: F811
    root, brief = pilot
    refused = invoke(root, "draft-handoff", draft(root, endpoint="b/front-door"), ok=False)
    assert refused["error"] == "checkpoint requires brief references"
    request = invoke(root, "draft-handoff", draft(root, endpoint="b/front-door", briefs=[brief]))
    assert request["checkpoint"]["briefs"] == [brief]
    assert invoke(root, "bind", request)["generation"] == 2


def test_the_draft_lists_unread_messages_when_delivery_is_tracked(pilot, tmp_path):  # noqa: F811
    root, brief = pilot
    invoke(root, "publish", message(recipient="a/lane/review", identifier="unread-note"))
    delivery = tmp_path / "delivery"
    request = invoke(root, "draft-handoff", draft(root, endpoint="a/lane/review", briefs=[brief],
                                                  delivery_dir=str(delivery)))
    assert request["checkpoint"]["pending_message_ids"] == ["unread-note"]


@pytest.mark.parametrize("change,error", [
    ({"briefs": 5}, "invalid briefs"),
    ({"briefs": ["not-an-object"]}, "expected a JSON object"),
    ({"evidence_dir": 5}, "invalid evidence_dir"),
    ({"delivery_dir": 5}, "invalid delivery_dir"),
    ({"completed_checks": "not-a-list"}, "invalid completed_checks"),
    ({"host": 5}, "invalid host"),
    ({"session": ""}, "invalid session"),
    ({"extra": True}, "unexpected fields"),
])
def test_malformed_draft_requests_fail_as_json(pilot, change, error):  # noqa: F811
    root, brief = pilot
    request = {**draft(root, endpoint="a/front-door", briefs=[brief]), **change}
    assert error in invoke(root, "draft-handoff", request, ok=False)["error"]


def test_a_draft_for_an_unbound_or_unknown_endpoint_is_refused(pilot):  # noqa: F811
    root, _ = pilot
    refused = invoke(root, "draft-handoff", draft(root, endpoint="a/lane/none"), ok=False)
    assert "unknown endpoint" in refused["error"]


def make_root(parent, hierarchy):
    parent.mkdir()
    root = parent / "mailbox"
    endpoints = {hierarchy + "/front-door": {}, hierarchy + "/orchestrator": {}}
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": endpoints,
                          "counterparts": [], "writer_limit": 3})
    for endpoint in endpoints:
        invoke(root, "bind", {"endpoint": endpoint, "host": "host-one", "session": endpoint,
                              "expected_generation": 0})
    brief = parent / "brief.md"
    brief.write_bytes(b"Owner intent.\n")
    return root, {"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}


def handoff(tmp_path, spec, expected):
    path = tmp_path / "handoff-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", str(HANDOFF), "--spec", str(path)], capture_output=True,
                            text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not result.stderr, result.stderr
    assert result.returncode == expected, result.stdout
    return json.loads(result.stdout)


@pytest.fixture
def roots(tmp_path):
    return [make_root(tmp_path / name, name) for name in ("alpha", "beta", "gamma")]


def spec_for(roots, **changes):
    entries = [{"root": str(root), "endpoint": root.parent.name + "/front-door", "briefs": [brief],
                "completed_checks": ["outgoing stopped"]} for root, brief in roots]
    return {"schema": "aegis.hierarchy-handoff/v1", "host": "host-two", "session": "new-front-door",
            "outgoing_stopped": True, "entries": entries, **changes}


def test_one_command_rotates_every_endpoint_and_acknowledgment_stays_separate(tmp_path, roots):
    result = handoff(tmp_path, spec_for(roots), 0)
    assert [row["ok"] for row in result["entries"]] == [True, True, True]
    for (root, _), row in zip(roots, result["entries"]):
        endpoint = root.parent.name + "/front-door"
        binding = invoke(root, "status")["bindings"][endpoint]
        assert binding["generation"] == 2 and binding["session"] == "new-front-door"
        assert binding["ready"] is False
        assert row["acknowledge"] == {"endpoint": endpoint, "session": "new-front-door", "generation": 2,
                                      "checkpoint_sha256": binding["checkpoint_sha256"]}
    root, _ = roots[0]
    stale = message("alpha/front-door", "alpha/orchestrator", identifier="stale")
    assert invoke(root, "publish", stale, ok=False)["error"] == "stale or mismatched sender binding"
    new = {**stale, "message_id": "new", "host": "host-two", "session": "new-front-door", "binding_generation": 2}
    assert invoke(root, "publish", new, ok=False)["error"] == "handoff checkpoint has not been acknowledged"
    invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])
    invoke(root, "publish", new)


def test_a_failure_on_one_endpoint_does_not_hide_or_block_the_others(tmp_path, roots):
    spec = spec_for(roots)
    spec["entries"][1]["endpoint"] = "beta/lane/none"
    result = handoff(tmp_path, spec, 3)
    rows = result["entries"]
    assert [row["ok"] for row in rows] == [True, False, True]
    assert "unknown endpoint" in rows[1]["error"]
    assert rows[1]["endpoint"] == "beta/lane/none"
    assert invoke(roots[1][0], "status")["bindings"]["beta/front-door"]["generation"] == 1
    assert invoke(roots[2][0], "status")["bindings"]["gamma/front-door"]["generation"] == 2


def test_a_busy_mailbox_is_reported_and_a_rerun_does_not_advance_finished_endpoints(tmp_path, roots):
    lock = roots[1][0] / ".write.lock"
    lock.write_text("fixture active writer")
    first = handoff(tmp_path, spec_for(roots), 3)
    assert [row["ok"] for row in first["entries"]] == [True, False, True]
    assert "writer is busy" in first["entries"][1]["error"]
    lock.unlink()
    second = handoff(tmp_path, spec_for(roots), 0)
    assert [row["ok"] for row in second["entries"]] == [True, True, True]
    assert [row.get("already_bound", False) for row in second["entries"]] == [True, False, True]
    assert second["entries"][0]["acknowledge"] == first["entries"][0]["acknowledge"]
    for root, _ in roots:
        assert invoke(root, "status")["bindings"][root.parent.name + "/front-door"]["generation"] == 2


@pytest.mark.parametrize("change,error", [
    ({"outgoing_stopped": False}, "outgoing session must be stopped before replacement"),
    ({"schema": "other"}, "unsupported handoff spec schema"),
    ({"entries": []}, "handoff spec requires entries"),
    ({"session": ""}, "invalid session"),
    ({"extra": True}, "unexpected fields"),
])
def test_an_invalid_spec_changes_nothing(tmp_path, roots, change, error):
    result = handoff(tmp_path, spec_for(roots, **change), 2)
    assert error in result["error"]
    for root, _ in roots:
        assert invoke(root, "status")["bindings"][root.parent.name + "/front-door"]["generation"] == 1


def test_an_entry_with_a_relative_root_or_extra_field_is_reported_per_entry(tmp_path, roots):
    spec = spec_for(roots)
    spec["entries"][0]["root"] = "relative/mailbox"
    spec["entries"][1]["run"] = "rm -rf /"
    rows = handoff(tmp_path, spec, 3)["entries"]
    assert "path must be absolute" in rows[0]["error"]
    assert "unexpected fields" in rows[1]["error"]
    assert rows[2]["ok"] is True


def test_an_entry_kind_must_match_the_manifest_kind(tmp_path, pilot):  # noqa: F811
    root, brief = pilot
    entries = [{"root": str(root), "endpoint": endpoint, "kind": kind, "briefs": [brief]} for endpoint, kind in (
        ("a/lane/review", "reviewer"), ("a/lane/f2", "reviewer"), ("a/orchestrator", "implementer"))]
    spec = {"schema": "aegis.hierarchy-handoff/v1", "host": "host-two", "session": "new-lane",
            "outgoing_stopped": True, "entries": entries}
    rows = handoff(tmp_path, spec, 3)["entries"]
    assert rows[0]["ok"] is True and rows[0]["generation"] == 2
    assert rows[1] == {"root": str(root), "endpoint": "a/lane/f2", "ok": False,
                       "error": "kind 'reviewer' does not match the manifest kind 'implementer' of a/lane/f2"}
    assert rows[2]["error"] == "kind 'implementer' does not match the manifest kind (none) of a/orchestrator"
    bindings = invoke(root, "status")["bindings"]
    assert (bindings["a/lane/f2"]["generation"], bindings["a/orchestrator"]["generation"]) == (1, 1)


@pytest.mark.parametrize("value", ["requests/x.json", "/abs/../x.json"])
def test_a_relative_or_traversing_spec_is_refused_by_name_and_value(value):
    result = subprocess.run([sys.executable, "-I", str(HANDOFF), "--spec", value], capture_output=True,
                            text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2 and not result.stderr
    assert json.loads(result.stdout) == {"error": "--spec must be absolute without traversal: got " + repr(value)}
