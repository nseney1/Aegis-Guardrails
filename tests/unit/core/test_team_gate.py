"""Unit tests for exact-tree local gate receipt reuse decisions (TP-4-a).

Filesystem-backed cases skip when descriptor-relative no-follow operations are
unavailable; the unsupported-platform path patches the module capability probe
and runs on every platform. No test requires Git history or spawns processes.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
from pathlib import Path
import pytest

from tests.conftest import symlink_or_skip
from aegis_core import team_gate
from aegis_core import team_profile
from aegis_core.redaction import RedactionRefusal


TREE_A = "a" * 40
TREE_B = "b" * 40
TREE_SHA256 = "c" * 64
COMMIT_A = "1" * 40
LOCAL_CMD = ("/usr/bin/python3", "tools/check_gate.py", "--suite", "unit")


def make_store(root: Path) -> Path:
    if not team_gate.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    return root.resolve()


def _secret_token() -> str:
    return "gh" + "p_" + ("A1b2C3d4E" * 4)


def _gate_config(**overrides):
    base = {
        "name": "full",
        "runner": "local",
        "selector": "whole",
        "must_pass": True,
        "reuse_identical_tree": True,
    }
    base.update(overrides)
    return base


def _junit_xml(*, tests: int = 5, failures: int = 0, errors: int = 0, skipped: int = 0) -> bytes:
    body = (
        '<testsuite name="gate" tests="%d" failures="%d" errors="%d" skipped="%d"/>'
        % (tests, failures, errors, skipped)
    )
    return body.encode("utf-8")


def _clean_witness(tree: str = TREE_A, commit: str = COMMIT_A):
    return {
        "worktree": "/work/checkout",
        "source_revision": commit,
        "source_tree": tree,
        "dirty_state_sha256": team_gate.EMPTY_STATUS,
        "dirty_entries": 0,
        "dirty_content_sha256": team_gate.EMPTY_STATUS,
    }


def _gate_receipt(
    *,
    tree: str = TREE_A,
    command=LOCAL_CMD,
    gate=None,
    shard: str = "default",
    state: str = "completed",
    exit_code=0,
    attempt: int = 1,
    finished_at: str = "2026-11-24T02:00:00Z",
    tests=None,
    junit_xml=None,
    extra=None,
):
    cfg = _gate_config() if gate is None else copy.deepcopy(gate)
    snapshot = {
        key: cfg[key]
        for key in cfg
        if key in cfg
    }
    row = {
        "schema": "aegis.team.gate.receipt/v1",
        "tree": tree,
        "command": [list(command)] if command and isinstance(command[0], str) else [list(step) for step in command],
        "gate": snapshot,
        "shard": shard,
        "state": state,
        "exit_code": exit_code,
        "attempt": attempt,
        "finished_at": finished_at,
        "before": _clean_witness(tree, "1" * len(tree)),
        "after": _clean_witness(tree, "1" * len(tree)),
        "process_stopped_confirmed": True,
    }
    if tests is False:
        pass
    elif tests is not None:
        row["tests"] = dict(tests)
    elif state == "completed":
        row["tests"] = {"total": 5, "passed": 5, "failed": 0, "errors": 0, "skipped": 0}
    if junit_xml is not None:
        row["junit_xml"] = junit_xml
    if extra:
        row.update(extra)
    return row


def _job_result_receipt(
    *,
    tree: str = TREE_A,
    command=LOCAL_CMD,
    gate=None,
    shard: str = "default",
    state: str = "completed",
    exit_code=0,
    attempt: int = 1,
    finished_at: str = "2026-11-24T02:00:00Z",
    tests=None,
    before=None,
    after=None,
    kept=None,
    reason=None,
):
    cfg = _gate_config() if gate is None else copy.deepcopy(gate)
    snapshot = {
        key: cfg[key]
        for key in cfg
        if key in cfg
    }
    witness_before = _clean_witness(tree) if before is None else before
    witness_after = _clean_witness(tree) if after is None else after
    steps_argv = [list(command)] if isinstance(command[0], str) else [list(step) for step in command]
    step_code = 0 if state == "completed" else (exit_code if isinstance(exit_code, int) else 1)
    row = {
        "schema": team_gate.RESULT_SCHEMA,
        "job": "pilot/gate-1",
        "state": state,
        "exit_code": exit_code,
        "reason": reason,
        "gate": snapshot,
        "shard": shard,
        "attempt": attempt,
        "steps": [{"argv": argv, "exit_code": step_code, "timed_out": False} for argv in steps_argv],
        "before": witness_before,
        "after": witness_after,
        "commit": None,
        "process_stopped_confirmed": True,
        "finished_at": finished_at,
    }
    if tests is not False:
        row["tests"] = (
            dict(tests)
            if tests is not None
            else {"total": 4, "passed": 4, "failed": 0, "errors": 0, "skipped": 0}
        )
    if kept is not None:
        row["kept"] = kept
    return row


_REQUEST = {"tree": TREE_A, "command": LOCAL_CMD, "gate": _gate_config()}


def _owner_evidence(rows, payloads=None):
    """Build trusted test inputs separately from the data passed to the reader."""
    admissions, completions = {}, {}
    for index, row in enumerate(rows):
        key = str(index)
        witness = row.get("before") or _clean_witness(row.get("tree", TREE_A))
        command = row["command"] if "command" in row else [step["argv"] for step in row["steps"]]
        admissions[key] = {
            "before": copy.deepcopy(witness), "command": copy.deepcopy(command),
            "gate": copy.deepcopy(row["gate"]), "shard": row["shard"], "attempt": row.get("attempt"),
            "expects_tests": row["schema"] == team_gate.GATE_RECEIPT_SCHEMA, "job": row.get("job"),
            "origin": "direct" if row.get("job") is None else "producer",
        }
        completions[key] = {
            "state": row["state"], "finished_at": row.get("finished_at"), "verified": True, "settled": True,
            "result_sha256": team_gate.evidence_digest(payloads[index] if payloads is not None else row),
        }
    return {"admissions": admissions, "completions": completions}


def _review_fixture(reviews):
    fields = ("role", "reviewer", "family", "tree", "attempt", "finished_at")
    rows = [{"state": "completed", "reviewer": "r-13", "family": "review-family", **entry} for entry in reviews]
    bindings = {
        str(index): {**{field: row.get(field) for field in fields}, "verified": True,
                     "result_sha256": team_gate.evidence_digest(row)}
        for index, row in enumerate(rows)
    }
    return rows, bindings


def _decide(rows, *, reviews=None, **request):
    owner = _owner_evidence(rows) if all(type(row) is dict for row in rows) else {}
    if reviews is not None and all("attempt" in row for row in reviews):
        reviews, owner["review_evidence"] = _review_fixture(reviews)
    return team_gate.decide_reuse(rows, reviews=reviews, author_family="writer-family", **request, **owner)


def _decide_files(root, paths, **request):
    # These are files the test just wrote beneath its own fixture directory.
    payloads = [(root / path).read_bytes() for path in paths]
    owner = _owner_evidence([json.loads(payload) for payload in payloads], payloads)
    return team_gate.decide_reuse_files(root, paths, **request, **owner)


def _stored_receipt(root, *, shard="default", attempt=1, gate=None, folder="pilot/gate-1", direct=False):
    """Write equivalent direct and producer evidence, including a confined report."""
    artifact_dir = folder + "/evidence"
    junit = root / artifact_dir / "run" / "junit.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    xml = (
        b'<testsuites><testsuite tests="2" failures="0" errors="0" skipped="1">'
        b'<testcase name="first"/><testcase name="second"><skipped/></testcase></testsuite></testsuites>'
    )
    junit.write_bytes(xml)
    counts = {"total": 2, "passed": 1, "failed": 0, "errors": 0, "skipped": 1}
    kept = [{"path": "run/junit.xml", "copy": str(junit), "sha256": hashlib.sha256(xml).hexdigest(), "bytes": len(xml)}]
    stamp = f"2026-11-24T02:00:00.{attempt:06d}Z"
    if direct:
        row = result = _gate_receipt(gate=gate, shard=shard, attempt=attempt, finished_at=stamp,
                                     tests=counts, extra={"kept": kept})
    else:
        row = _job_result_receipt(gate=gate, shard=shard, attempt=attempt, finished_at=stamp, tests=counts, kept=kept)
        row["job"] = folder
        result = {key: val for key, val in row.items() if key not in ("gate", "shard", "attempt")}
        result.update(recipe="full-suite", recipes_sha256="e" * 64, python={"version": "3.12.3"})
        result["source_export"] = {
            "commit": row["before"]["source_revision"], "tree": row["before"]["source_tree"],
            "entries": 7, "bytes": 900, "removed": True,
        }
    payload = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    result_path = folder + "/result.json"
    (root / result_path).write_bytes(payload)
    owner = _owner_evidence([row], [payload])
    owner["admissions"]["0"].update(expects_tests=True, artifact_dir=artifact_dir)
    return result_path, result, owner


@pytest.mark.parametrize("tree", [TREE_A, TREE_SHA256], ids=["sha1", "sha256"])
@pytest.mark.parametrize("kind", ["gate_receipt", "job_result"])
def test_exact_tree_single_shard_requires_launch_proof_without_mutating_inputs(tree, kind):
    gate = _gate_config(selector="list", tests=["tests/unit/core/test_team_gate.py"], python="/usr/bin/python3")
    command = ["/usr/bin/python3", "tools/check_gate.py", "tests/unit/core/test_team_gate.py"]
    commit = "1" * len(tree)
    if kind == "gate_receipt":
        receipt = _gate_receipt(tree=tree, command=command, gate=gate)
    else:
        witness = _clean_witness(tree=tree, commit=commit)
        receipt = _job_result_receipt(tree=tree, command=command, gate=gate, before=witness, after=witness)
    snapshot = copy.deepcopy((gate, command, [receipt]))

    decision = _decide([receipt], tree=tree, command=command, gate=gate)

    assert (gate, command, [receipt]) == snapshot
    assert decision["schema"] == team_gate.GATE_SCHEMA
    assert decision["status"] == "ok"
    if kind == "job_result":
        assert (decision["decision"], decision["evidence_state"], decision["reason"]) == (
            "run", "stale", "stale_incomplete",
        )
        assert decision["tree"] == tree
        assert decision["passed_shards"] == [] and decision["incomplete_shards"] == ["default"]
        assert decision["tests"] is None
        return
    assert decision["reusable"] is True
    assert decision["decision"] == "reuse"
    assert decision["evidence_state"] == "pass"
    assert decision["reason"] == "exact_tree_pass"
    assert decision["tree"] == tree
    assert decision["required_shards"] == ["default"]
    assert decision["passed_shards"] == ["default"]
    assert decision["missing_shards"] == []
    assert decision["red_shards"] == []
    assert decision["incomplete_shards"] == []
    assert decision["stale_count"] == 0
    assert decision["superseded_pass_count"] == 0
    assert decision["tests"]["passed"] >= 4


def test_multi_shard_requires_all_shards_and_aggregates_counts():
    shards = ("unit-core", "unit-rest", "integration", "contract")
    gate = _gate_config(shards=list(shards))
    receipts = [
        _gate_receipt(
            gate=gate,
            shard=shard,
            tests={"total": idx + 2, "passed": idx + 1, "failed": 0, "errors": 0, "skipped": 1},
        )
        for idx, shard in enumerate(shards, start=1)
    ]

    full = _decide(receipts, tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert full["reusable"] is True
    assert full["decision"] == "reuse"
    assert full["passed_shards"] == list(shards)
    assert full["tests"] == {"total": 18, "passed": 14, "failed": 0, "errors": 0, "skipped": 4}

    partial = _decide(receipts[:-1], tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert partial["reusable"] is False
    assert partial["decision"] == "run"
    assert partial["evidence_state"] == "partial"
    assert partial["reason"] == "partial_evidence"
    assert partial["passed_shards"] == list(shards[:-1])
    assert partial["missing_shards"] == ["contract"]


def test_unlabelled_or_extra_shard_never_satisfies_named_required_shard():
    required = ("shard-a", "shard-b")
    gate = _gate_config(shards=list(required))
    receipts = [
        _gate_receipt(gate=gate, shard="shard-a"),
        _gate_receipt(gate=gate, shard="default"),
        _gate_receipt(gate=gate, shard="shard-extra"),
    ]

    decision = _decide(
        receipts, tree=TREE_A, command=LOCAL_CMD, gate=gate, required_shards=required
    )
    assert decision["reusable"] is False
    assert decision["evidence_state"] == "partial"
    assert decision["reason"] == "partial_evidence"
    assert decision["passed_shards"] == ["shard-a"]
    assert decision["missing_shards"] == ["shard-b"]
    assert decision["stale_count"] == 2


@pytest.mark.parametrize(
    "variant,expected_reason",
    [
        ("different_tree", "stale_tree"),
        ("dirty_content", "stale_dirty_tree"),
        ("dirty_state", "stale_dirty_tree"),
        ("dirty_entries", "stale_dirty_tree"),
        ("witness_drift", "red_evidence"),
        ("different_command", "stale_command"),
        ("different_step_count", "stale_command"),
        ("different_gate_name", "stale_config"),
        ("different_selector", "stale_config"),
        ("different_tests", "stale_config"),
        ("different_python", "stale_config"),
        ("different_must_pass", "stale_config"),
    ],
)
def test_stale_evidence_variants_do_not_reuse(variant, expected_reason):
    gate = _gate_config(selector="list", tests=["tests/a.py", "tests/b.py"], python="/usr/bin/python3")
    command = ("/usr/bin/python3", "tools/run.py", "tests/a.py", "tests/b.py")
    if variant == "different_tree":
        receipt = _job_result_receipt(tree=TREE_B, command=command, gate=gate)
    elif variant == "dirty_content":
        dirty = {**_clean_witness(TREE_A), "dirty_content_sha256": "f" * 64}
        receipt = _job_result_receipt(tree=TREE_A, command=command, gate=gate, before=dirty, after=dirty)
    elif variant == "dirty_state":
        dirty = {**_clean_witness(TREE_A), "dirty_state_sha256": "e" * 64}
        receipt = _job_result_receipt(tree=TREE_A, command=command, gate=gate, before=dirty, after=dirty)
    elif variant == "dirty_entries":
        dirty = {**_clean_witness(TREE_A), "dirty_entries": 1}
        receipt = _job_result_receipt(tree=TREE_A, command=command, gate=gate, before=dirty, after=dirty)
    elif variant == "witness_drift":
        after = {**_clean_witness(TREE_A), "source_revision": "2" * 40}
        receipt = _job_result_receipt(
            tree=TREE_A, command=command, gate=gate, before=_clean_witness(TREE_A), after=after
        )
    elif variant == "different_command":
        receipt = _gate_receipt(
            tree=TREE_A, command=("/usr/bin/python3", "tools/run.py", "tests/a.py"), gate=gate
        )
    elif variant == "different_step_count":
        receipt = _gate_receipt(
            tree=TREE_A, command=[list(command), ["/usr/bin/python3", "tools/extra.py"]], gate=gate
        )
    elif variant == "different_gate_name":
        receipt = _gate_receipt(tree=TREE_A, command=command, gate={**gate, "name": "quick"})
    elif variant == "different_selector":
        other = {k: v for k, v in gate.items() if k != "tests"}
        other["selector"] = "impacted"
        receipt = _gate_receipt(tree=TREE_A, command=command, gate=other)
    elif variant == "different_tests":
        receipt = _gate_receipt(
            tree=TREE_A, command=command, gate={**gate, "tests": ["tests/b.py", "tests/a.py"]}
        )
    elif variant == "different_python":
        receipt = _gate_receipt(tree=TREE_A, command=command, gate={**gate, "python": "/opt/py39/bin/python3"})
    else:
        receipt = _gate_receipt(tree=TREE_A, command=command, gate={**gate, "must_pass": False})

    decision = _decide([receipt], tree=TREE_A, command=command, gate=gate)
    assert decision["reusable"] is False
    assert decision["decision"] == "run"
    if variant == "witness_drift":
        assert decision["evidence_state"] == "red"
        assert decision["stale_count"] == 0
    else:
        assert decision["evidence_state"] == "stale"
        assert decision["stale_count"] == 1
    assert decision["reason"] == expected_reason


@pytest.mark.parametrize("configured", [False, None])
def test_reuse_disabled_in_gate_config_never_reuses(configured):
    gate = _gate_config()
    if configured is None:
        del gate["reuse_identical_tree"]
    else:
        gate["reuse_identical_tree"] = False
    receipt = _gate_receipt(gate=gate)

    decision = _decide([receipt], tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert decision["reusable"] is False
    assert decision["decision"] == "run"
    assert decision["evidence_state"] == "reuse_disabled"
    assert decision["reason"] == "reuse_disabled"


@pytest.mark.parametrize(
    "case",
    [
        "failed_state",
        "refused_state",
        "timed_out_state",
        "cancelled_state",
        "zero_total_tests",
        "all_skipped_zero_passed",
        "test_failures",
        "test_errors",
        "junit_malformed_xml",
        "junit_doctype",
        "junit_entity",
        "junit_non_utf8",
        "junit_oversized",
    ],
)
def test_red_evidence_cases_never_reuse(case):
    if case == "failed_state":
        receipt = _gate_receipt(state="failed", exit_code=1, tests=False)
    elif case == "refused_state":
        receipt = _gate_receipt(state="refused", exit_code=None, tests=False)
    elif case == "timed_out_state":
        receipt = _gate_receipt(state="timed_out", exit_code=124, tests=False)
    elif case == "cancelled_state":
        receipt = _gate_receipt(state="cancelled", exit_code=130, tests=False)
    elif case == "zero_total_tests":
        receipt = _gate_receipt(tests={"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0})
    elif case == "all_skipped_zero_passed":
        receipt = _gate_receipt(tests={"total": 4, "passed": 0, "failed": 0, "errors": 0, "skipped": 4})
    elif case == "test_failures":
        receipt = _gate_receipt(tests={"total": 4, "passed": 3, "failed": 1, "errors": 0, "skipped": 0})
    elif case == "test_errors":
        receipt = _gate_receipt(tests={"total": 4, "passed": 3, "failed": 0, "errors": 1, "skipped": 0})
    elif case == "junit_malformed_xml":
        receipt = _gate_receipt(tests=False, junit_xml=b"<testsuite tests='1'")
    elif case == "junit_doctype":
        receipt = _gate_receipt(
            tests=False,
            junit_xml=b'<!DOCTYPE testsuite><testsuite tests="1" failures="0" errors="0" skipped="0"/>',
        )
    elif case == "junit_entity":
        receipt = _gate_receipt(
            tests=False,
            junit_xml=b'<!ENTITY x "y"><testsuite tests="1" failures="0" errors="0" skipped="0"/>',
        )
    elif case == "junit_non_utf8":
        receipt = _gate_receipt(tests=False, junit_xml=b"\xff\xfe<testsuite/>")
    else:
        receipt = _gate_receipt(tests=False, junit_xml=b"x" * (team_gate.MAX_JUNIT_BYTES + 1))

    if case.startswith("junit_"):
        with pytest.raises(team_gate.GateRefusal) as error:
            _decide([receipt], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
        expected_code = "limit_exceeded" if case == "junit_oversized" else "invalid_receipt"
        assert (error.value.code, error.value.exit_code) == (expected_code, 1)
        return
    decision = _decide([receipt], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert decision["reusable"] is False
    assert decision["decision"] == "run"
    assert decision["evidence_state"] == "red"
    assert decision["reason"] == "red_evidence"
    assert decision["red_shards"] == ["default"]


def test_completed_receipt_without_test_counts_or_junit_is_incomplete():
    receipt = _gate_receipt(tests=False)
    decision = _decide([receipt], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert decision["reusable"] is False
    assert decision["decision"] == "run"
    assert decision["evidence_state"] == "stale"
    assert decision["reason"] == "missing_test_evidence"
    assert decision["incomplete_shards"] == ["default"]


def test_nested_junit_suites_sum_leaf_suites_only():
    xml = (
        b'<testsuites tests="7"><testsuite name="parent" tests="7" failures="0" errors="0" skipped="1">'
        b'<testsuite name="leaf-a" tests="3" failures="0" errors="0" skipped="1"/>'
        b'<testsuite name="leaf-b" tests="4" failures="0" errors="0" skipped="0"/>'
        b"</testsuite></testsuites>"
    )
    counts, problem = team_gate.junit_counts(xml)
    assert problem is None
    assert counts == {"total": 7, "passed": 6, "failed": 0, "errors": 0, "skipped": 1}

    receipt = _gate_receipt(tests=counts, junit_xml=xml)
    decision = _decide([receipt], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert (decision["reason"], decision["tests"]) == ("stale_incomplete", None)
    receipt.pop("junit_xml")
    decision = _decide([receipt], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert decision["reusable"] is True
    assert decision["tests"] == counts


def test_latest_applicable_attempt_supersedes_older_pass_and_ties_favor_red():
    older_pass = _gate_receipt(attempt=1, finished_at="2026-11-24T01:00:00Z")
    newer_red = _gate_receipt(
        attempt=2, state="failed", exit_code=1, tests=False, finished_at="2026-11-24T02:00:00Z"
    )
    for ordering in ([older_pass, newer_red], [newer_red, older_pass]):
        superseded = _decide(ordering, tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
        assert superseded["reusable"] is False
        assert superseded["evidence_state"] == "red"
        assert superseded["reason"] == "red_evidence"
        assert superseded["superseded_pass_count"] == 1

    newer_running = _gate_receipt(
        attempt=2, state="running", exit_code=None, tests=False, finished_at="2026-11-24T02:00:00Z"
    )
    in_flight = _decide(
        [older_pass, newer_running], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config()
    )
    assert in_flight["reusable"] is False
    assert in_flight["evidence_state"] == "stale"
    assert in_flight["reason"] == "stale_incomplete"
    assert in_flight["superseded_pass_count"] == 1
    assert in_flight["incomplete_shards"] == ["default"]

    same_attempt_red = _gate_receipt(
        attempt=1, state="failed", exit_code=1, tests=False, finished_at="2026-11-24T01:00:00Z"
    )
    for ordering in ([older_pass, same_attempt_red], [same_attempt_red, older_pass]):
        tied = _decide(ordering, tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
        assert tied["reusable"] is False
        assert tied["evidence_state"] == "red"
        assert tied["reason"] == "red_evidence"


def test_timestamp_ordering_when_attempt_is_absent_and_stale_tree_does_not_poison_current_pass():
    stale_other_tree_red = _gate_receipt(
        tree=TREE_B, state="failed", exit_code=1, tests=False, finished_at="2026-11-24T03:00:00Z"
    )
    del stale_other_tree_red["attempt"]
    early_red = _gate_receipt(
        tree=TREE_A, state="failed", exit_code=1, tests=False, finished_at="2026-11-24T01:00:00Z"
    )
    del early_red["attempt"]
    later_pass = _gate_receipt(tree=TREE_A, finished_at="2026-11-24T02:00:00Z")
    del later_pass["attempt"]

    recovered = _decide(
        [stale_other_tree_red, later_pass, early_red],
        tree=TREE_A,
        command=LOCAL_CMD,
        gate=_gate_config(),
    )
    assert recovered["reusable"] is True
    assert recovered["decision"] == "reuse"
    assert recovered["stale_count"] == 1
    assert recovered["superseded_pass_count"] == 0


def test_red_shard_takes_precedence_over_missing_shard():
    gate = _gate_config(shards=["shard-1", "shard-2", "shard-3"])
    receipts = [
        _gate_receipt(gate=gate, shard="shard-1"),
        _gate_receipt(gate=gate, shard="shard-2", state="failed", exit_code=1, tests=False),
    ]
    decision = _decide(receipts, tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert decision["reusable"] is False
    assert decision["decision"] == "run"
    assert decision["evidence_state"] == "red"
    assert decision["reason"] == "red_evidence"
    assert decision["passed_shards"] == ["shard-1"]
    assert decision["red_shards"] == ["shard-2"]
    assert decision["missing_shards"] == ["shard-3"]


def test_missing_evidence_and_multi_shard_retry_progression(tmp_path):
    root = make_store(tmp_path)
    gate = _gate_config(shards=["unit", "integration"])
    paths = ["receipts/unit-1.json", "receipts/integration-1.json"]

    empty = _decide([], tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert (empty["reusable"], empty["evidence_state"], empty["reason"]) == (
        False,
        "missing",
        "missing_evidence",
    )

    with pytest.raises(team_gate.GateRefusal) as absent:
        team_gate.decide_reuse_files(root, paths, tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert (absent.value.code, absent.value.exit_code) == ("missing_receipt", 1)

    (root / "receipts").mkdir(mode=0o700)
    (root / "receipts" / "unit-1.json").write_bytes(
        json.dumps(_gate_receipt(gate=gate, shard="unit", attempt=1)).encode("utf-8")
    )
    step1 = _decide_files(root, paths[:1], tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert (step1["reusable"], step1["evidence_state"], step1["reason"]) == (
        False,
        "partial",
        "partial_evidence",
    )

    (root / "receipts" / "integration-1.json").write_bytes(
        json.dumps(
            _gate_receipt(gate=gate, shard="integration", attempt=1, state="failed", exit_code=1, tests=False)
        ).encode("utf-8")
    )
    step2 = _decide_files(root, paths, tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert (step2["reusable"], step2["evidence_state"], step2["reason"]) == (
        False,
        "red",
        "red_evidence",
    )

    retry_paths = [*paths, "receipts/integration-2.json"]
    (root / "receipts" / "integration-2.json").write_bytes(
        json.dumps(_gate_receipt(gate=gate, shard="integration", attempt=2)).encode("utf-8")
    )
    step3 = _decide_files(root, retry_paths, tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert (step3["reusable"], step3["decision"], step3["reason"]) == (
        True,
        "reuse",
        "exact_tree_pass",
    )

    requalify_paths = [*retry_paths, "receipts/unit-2.json"]
    (root / "receipts" / "unit-2.json").write_bytes(
        json.dumps(
            _gate_receipt(gate=gate, shard="unit", attempt=2, state="failed", exit_code=1, tests=False)
        ).encode("utf-8")
    )
    step4 = _decide_files(root, requalify_paths, tree=TREE_A, command=LOCAL_CMD, gate=gate)
    assert (step4["reusable"], step4["evidence_state"], step4["reason"], step4["superseded_pass_count"]) == (
        False,
        "red",
        "red_evidence",
        1,
    )


@pytest.mark.parametrize("direct", [False, True], ids=["producer", "direct"])
def test_confined_kept_junit_file_verified_and_hash_mismatch_rejected(tmp_path, direct):
    root = make_store(tmp_path)
    result_path, receipt, owner = _stored_receipt(root, direct=direct)
    good = team_gate.decide_reuse_files(root, [result_path], **_REQUEST, **owner)
    assert (good["reason"], good["tests"]) == ("stale_incomplete", None)

    path = Path(receipt["kept"][0]["copy"])
    assert team_gate.junit_counts(path.read_bytes()) == (
        {"total": 2, "passed": 1, "failed": 0, "errors": 0, "skipped": 1}, None,
    )
    path.write_bytes(path.read_bytes().replace(b"second", b"forged"))
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.decide_reuse_files(root, [result_path], **_REQUEST, **owner)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


def test_remote_runner_plugins_are_superseded_and_refused():
    token = _secret_token()
    with pytest.raises(team_gate.GateRefusal) as exc_info:
        _decide(
            [_gate_receipt()],
            tree=TREE_A,
            command=LOCAL_CMD,
            gate=_gate_config(runner="remote-pool"),
        )
    err = exc_info.value
    assert err.code == "unsupported_runner"
    assert err.exit_code == 2
    assert err.as_dict()["status"] == "refused"
    assert "remote-pool" not in str(err)

    with pytest.raises(team_gate.GateRefusal) as bad_runner:
        team_gate.validate_gate_config(_gate_config(runner=token))
    assert bad_runner.value.code in ("unsupported_runner", "invalid_gate_config")
    assert token not in json.dumps(bad_runner.value.as_dict())


def test_unavailable_review_results_honor_voting_vs_non_voting_policy():
    receipt = _gate_receipt()
    review_policy = {
        "require_cross_family": True,
        "extra_lens_blocks_on": "confirmed",
        "lenses": [
            {"name": "audit.voting", "voting": True},
            {"name": "audit.advisory", "voting": False},
        ],
    }

    non_voting_unavailable = [
        {"role": "reviewer.correctness", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "reviewer.security", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "audit.voting", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "lens.extra", "verdict": "unavailable", "tree": TREE_A, "attempt": 1},
        {"role": "audit.advisory", "verdict": "skipped", "tree": TREE_A, "attempt": 1},
    ]
    allowed = _decide(
        [receipt],
        tree=TREE_A,
        command=LOCAL_CMD,
        gate=_gate_config(),
        reviews=non_voting_unavailable,
        review_policy=review_policy,
    )
    assert allowed["reusable"] is True
    assert allowed["decision"] == "reuse"
    assert allowed["unavailable_reviews"] == ["audit.advisory", "lens.extra"]

    extra_confirmed = [*non_voting_unavailable[:-2], {"role": "lens.extra", "verdict": "confirmed", "tree": TREE_A, "attempt": 2}]
    blocked = _decide(
        [receipt],
        tree=TREE_A,
        command=LOCAL_CMD,
        gate=_gate_config(),
        reviews=extra_confirmed,
        review_policy=review_policy,
    )
    assert blocked["reusable"] is False
    assert blocked["decision"] == "run"
    assert blocked["evidence_state"] == "review_blocked"
    assert blocked["reason"] == "review_blocked"

    voting_unavailable = [
        {"role": "reviewer.correctness", "verdict": "unavailable", "tree": TREE_A, "attempt": 1},
        {"role": "reviewer.security", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "audit.voting", "verdict": "accept", "tree": TREE_A, "attempt": 1},
    ]
    held = _decide(
        [receipt],
        tree=TREE_A,
        command=LOCAL_CMD,
        gate=_gate_config(),
        reviews=voting_unavailable,
        review_policy=review_policy,
    )
    assert held["reusable"] is False
    assert held["decision"] == "hold"
    assert held["evidence_state"] == "review_unavailable"
    assert held["reason"] == "review_unavailable"

    retried_reviews = [
        *voting_unavailable,
        {"role": "reviewer.correctness", "verdict": "accept", "tree": TREE_A, "attempt": 2},
    ]
    retried = _decide(
        [receipt],
        tree=TREE_A,
        command=LOCAL_CMD,
        gate=_gate_config(),
        reviews=retried_reviews,
        review_policy=review_policy,
    )
    assert retried["reusable"] is True
    assert retried["decision"] == "reuse"

    with pytest.raises(team_gate.GateRefusal) as forged:
        _decide(
            [receipt],
            tree=TREE_A,
            command=LOCAL_CMD,
            gate=_gate_config(),
            reviews=[
                {
                    "role": "reviewer.correctness",
                    "verdict": "unavailable",
                    "voting": False,
                    "tree": TREE_A,
                }
            ],
        )
    assert forged.value.code == "invalid_review"


@pytest.mark.parametrize(
    "limit_kind",
    ["bytes", "depth", "nodes", "items", "string"],
)
def test_json_preflight_enforces_limits_before_allocation(monkeypatch, limit_kind):
    def forbidden(*_args, **_kwargs):
        pytest.fail("strict_loads called before preflight resource refusal")

    monkeypatch.setattr(team_gate, "strict_loads", forbidden)
    if limit_kind == "bytes":
        monkeypatch.setattr(team_gate, "MAX_RECEIPT_BYTES", 16)
        payload = json.dumps(_gate_receipt()).encode("utf-8")
    elif limit_kind == "depth":
        monkeypatch.setattr(team_gate, "MAX_DEPTH", 2)
        payload = b'{"a":{"b":{"c":1}}}'
    elif limit_kind == "nodes":
        monkeypatch.setattr(team_gate, "MAX_NODES", 4)
        payload = b'{"a":1,"b":2,"c":3}'
    elif limit_kind == "items":
        monkeypatch.setattr(team_gate, "MAX_ITEMS", 2)
        payload = b'{"a":[1,2,3]}'
    else:
        monkeypatch.setattr(team_gate, "MAX_STRING", 8)
        payload = b'{"a":"0123456789"}'

    with pytest.raises(team_gate.GateRefusal) as exc_info:
        team_gate.parse_json(payload)
    assert exc_info.value.code == "limit_exceeded"


@pytest.mark.parametrize(
    "raw,expected_code",
    [
        (b'{"a":1,"a":2}', "invalid_json"),
        (b'{"a":NaN}', "invalid_json"),
        (b'{"a":1e999}', "invalid_json"),
        (b"\xff\xfe", "invalid_json"),
        (b"[1, 2, 3]", "invalid_receipt"),
    ],
)
def test_malformed_json_and_non_object_receipts_refuse_without_echo(raw, expected_code):
    secret = _secret_token()
    if expected_code == "invalid_json" and raw.startswith(b"{"):
        raw = raw[:-1] + (',"note":"' + secret + '"}').encode("utf-8")
    with pytest.raises(team_gate.GateRefusal) as exc_info:
        _decide([raw], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert exc_info.value.code == expected_code
    assert secret not in str(exc_info.value)
    assert secret not in json.dumps(exc_info.value.as_dict())


def test_display_text_canonicalizes_then_redacts_then_truncates_and_refuses_multiline():
    secret = _secret_token()
    raw_name = "gate-\x1b[31m" + secret + "\x1b[0m-" + ("tail" * 30)
    shown = team_gate.format_gate_label(raw_name, limit=48)
    assert len(shown) <= 48
    assert "\x1b" not in shown
    assert secret not in shown
    assert secret[:8] not in shown
    assert "[REDACTED" in shown

    decision = _decide(
        [_gate_receipt(gate=_gate_config(name=raw_name))],
        tree=TREE_A,
        command=LOCAL_CMD,
        gate=_gate_config(name=raw_name),
    )
    assert decision["reusable"] is True
    assert secret not in json.dumps(decision)
    assert decision["gate_name"] == team_gate.format_gate_label(raw_name)

    for bad_line in ("full\nsecond", "full\rsecond", "full\u2028second", "full\x00null"):
        with pytest.raises(team_gate.GateRefusal) as exc_info:
            team_gate.format_gate_label(bad_line)
        assert exc_info.value.code == "multiline_value"


@pytest.mark.parametrize("root_spelling", ["/work/trusted-store", "C:\\work\\trusted-store"])
def test_unsupported_platform_refuses_before_filesystem_access(monkeypatch, root_spelling):
    monkeypatch.setattr(team_gate, "descriptor_supported", lambda: False)
    with pytest.raises(team_gate.GateRefusal) as load_exc:
        team_gate.load_receipt(root_spelling, "receipts/r1.json")
    assert load_exc.value.code == "unsupported_platform"
    assert load_exc.value.exit_code == 1

    with pytest.raises(team_gate.GateRefusal) as decide_exc:
        team_gate.decide_reuse_files(
            root_spelling,
            ["receipts/r1.json"],
            tree=TREE_A,
            command=LOCAL_CMD,
            gate=_gate_config(),
        )
    assert decide_exc.value.code == "unsupported_platform"


def test_confined_reads_reject_symlinks_traversals_and_directories(tmp_path):
    root = make_store(tmp_path / "store")
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside.json"
    outside.write_bytes(json.dumps(_gate_receipt()).encode("utf-8"))

    (root / "receipts").mkdir(mode=0o700)
    leaf_link = root / "receipts" / "leaf.json"
    symlink_or_skip(outside, leaf_link)

    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir(mode=0o700)
    (outside_dir / "nested.json").write_bytes(json.dumps(_gate_receipt()).encode("utf-8"))
    parent_link = root / "linked-dir"
    symlink_or_skip(outside_dir, parent_link, target_is_directory=True)

    (root / "receipts" / "as_dir").mkdir(mode=0o700)

    for unsafe_rel in (
        "../outside.json",
        "/etc/passwd",
        "receipts\\leaf.json",
        "C:receipt.json",
        "receipts/leaf.json",
        "linked-dir/nested.json",
        "receipts/as_dir",
    ):
        with pytest.raises(team_gate.GateRefusal) as exc_info:
            team_gate.decide_reuse_files(
                root,
                [unsafe_rel],
                tree=TREE_A,
                command=LOCAL_CMD,
                gate=_gate_config(),
            )
        assert exc_info.value.code == "unsafe_path"
        assert "outside" not in str(exc_info.value)


def test_concurrent_evaluations_are_isolated_and_deterministic(tmp_path):
    root = make_store(tmp_path)
    xml_path, _, xml_owner = _stored_receipt(root, direct=True)
    direct = _gate_receipt()
    payload = json.dumps(direct).encode()
    (root / "direct.json").write_bytes(payload)
    owner = _owner_evidence([direct], [payload])

    def worker(slot: int):
        if slot % 4 == 0:
            res = team_gate.decide_reuse_files(root, ["direct.json"], **_REQUEST, **owner)
            assert res["reusable"] is True
            return ("pass", res["reason"])
        if slot % 4 == 1:
            res = _decide(
                [_gate_receipt(state="failed", exit_code=1, tests=False)],
                tree=TREE_A,
                command=LOCAL_CMD,
                gate=_gate_config(),
            )
            assert res["reusable"] is False
            return ("red", res["reason"])
        if slot % 4 == 2:
            res = team_gate.decide_reuse_files(root, [xml_path], **_REQUEST, **xml_owner)
            return ("xml", res["reason"])
        with pytest.raises(team_gate.GateRefusal) as exc_info:
            _decide([], tree="not-a-valid-oid", command=LOCAL_CMD, gate=_gate_config())
        return ("refused", exc_info.value.code)

    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(worker, range(24)))

    assert outcomes.count(("pass", "exact_tree_pass")) == 6
    assert outcomes.count(("red", "red_evidence")) == 6
    assert outcomes.count(("xml", "stale_incomplete")) == 6
    assert outcomes.count(("refused", "invalid_tree")) == 6


def test_resolved_team_profile_gate_and_review_policy_interoperate_directly():
    resolved = team_profile.resolve(
        preset="mixed",
        repo={
            "policy": {
                "review": {
                    "lenses": [
                        {"name": "arch.check", "host_pref": ["review"], "voting": False}
                    ]
                }
            }
        },
    )["profile"]
    [gate] = resolved["policy"]["gates"]
    review_policy = resolved["policy"]["review"]
    receipt = _gate_receipt(gate=gate)
    reviews = [
        {"role": "reviewer.correctness", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "reviewer.security", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "lens.extra", "verdict": "unavailable", "tree": TREE_A, "attempt": 1},
        {"role": "arch.check", "verdict": "unavailable", "tree": TREE_A, "attempt": 1},
    ]
    decision = _decide(
        [receipt],
        tree=TREE_A,
        command=LOCAL_CMD,
        gate=gate,
        reviews=reviews,
        review_policy=review_policy,
    )
    assert decision["reusable"] is True
    assert decision["decision"] == "reuse"
    assert decision["unavailable_reviews"] == ["arch.check", "lens.extra"]


def test_contradictory_attempt_and_timestamp_order_refuses():
    first = _gate_receipt(attempt=1, finished_at="2026-11-24T03:00:00Z")
    second = _gate_receipt(attempt=2, finished_at="2026-11-24T01:00:00Z")
    with pytest.raises(team_gate.GateRefusal) as exc_info:
        _decide([first, second], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert exc_info.value.code == "invalid_receipt"


@pytest.mark.parametrize("schema", ["gate", "job"])
def test_receipt_cannot_attest_its_own_provenance(schema):
    receipt = _gate_receipt() if schema == "gate" else _job_result_receipt()
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.decide_reuse([receipt], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


def test_junit_testcase_failure_cannot_be_hidden_by_omitting_a_count():
    xml = b'<testsuite tests="1"><testcase name="gate"><failure/></testcase></testsuite>'
    counts, problem = team_gate.junit_counts(xml)
    assert problem is not None or counts["failed"] == 1


def test_empty_path_list_checks_the_trusted_directory(tmp_path):
    root = make_store(tmp_path) / "absent"
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.decide_reuse_files(root, [], tree=TREE_A, command=LOCAL_CMD, gate=_gate_config())
    assert (error.value.code, error.value.exit_code) == ("unsafe_root", 1)


def test_bad_request_and_bad_recorded_gate_have_different_exit_codes():
    bad_gate = _gate_config(shards=[])
    with pytest.raises(team_gate.GateRefusal) as usage:
        team_gate.decide_reuse([], **{**_REQUEST, "gate": bad_gate})
    assert (usage.value.code, usage.value.exit_code) == ("invalid_shards", 2)
    receipt = _gate_receipt()
    owner = _owner_evidence([receipt])
    receipt["gate"] = bad_gate
    owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(receipt)
    with pytest.raises(team_gate.GateRefusal) as refused:
        team_gate.decide_reuse([receipt], **_REQUEST, **owner)
    assert (refused.value.code, refused.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("field", ["gate", "shard", "attempt", "tree", "command"])
def test_independent_admission_rejects_mismatched_completed_receipt(field):
    row = _gate_receipt()
    owner = _owner_evidence([row])
    replacements = {"gate": _gate_config(shards=["default", "unit"]), "shard": "unit",
                    "attempt": 2, "tree": TREE_B, "command": ["different-command"]}
    row[field] = replacements[field]
    owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(row)
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.decide_reuse([row], **_REQUEST, **owner)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("mark", ["verified", "settled", "process_stopped_confirmed", "provenance_unverified"])
def test_acceptance_needs_verified_provenance_and_settlement(mark):
    row = _gate_receipt()
    if mark not in ("verified", "settled"):
        row[mark] = mark == "provenance_unverified"
    owner = _owner_evidence([row])
    if mark in ("verified", "settled"):
        owner["completions"]["0"][mark] = False
    decision = team_gate.decide_reuse([row], **_REQUEST, **owner)
    assert (decision["reusable"], decision["incomplete_shards"]) == (False, ["default"])


@pytest.mark.parametrize("schema", ["gate", "gate-inline", "job"])
def test_result_digest_binds_exact_file_bytes(tmp_path, schema):
    root = make_store(tmp_path)
    if schema == "job":
        path, _row, owner = _stored_receipt(root)
    else:
        xml = "<!--" + "x" * 4500 + "-->" + _junit_xml().decode()
        row = _gate_receipt(junit_xml=xml if schema == "gate-inline" else None)
        path, payload = "gate.json", json.dumps(row).encode()
        (root / path).write_bytes(payload)
        owner = _owner_evidence([row], [payload])
    decision = team_gate.decide_reuse_files(root, [path], **_REQUEST, **owner)
    assert decision["reason"] == ("exact_tree_pass" if schema == "gate" else "stale_incomplete")
    receipt = root / path
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.decide_reuse_files(root, [path], **_REQUEST, **owner)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("newer", ["failed", "refused", "running", "partial", "drift", "missing", "undated"])
def test_same_source_retry_prevents_reuse_and_can_recover(newer):
    older = _gate_receipt(finished_at="2026-11-24T01:00:00Z")
    current = _job_result_receipt(attempt=2)
    admission_source = copy.deepcopy(current)
    if newer in ("failed", "partial", "drift"):
        current.update(state="failed", exit_code=-1)
        if newer == "partial":
            current["after"] = None
        if newer == "drift":
            current["after"]["dirty_content_sha256"] = "d" * 64
    elif newer in ("refused", "running", "undated"):
        current.update(state="refused" if newer == "refused" else "running", exit_code=None)
        current.update(steps=[], before=None, after=None, finished_at=None)
    if newer == "undated":
        older.pop("attempt")
        current.pop("attempt")
        admission_source.pop("attempt")
    owner = _owner_evidence([older, admission_source])
    owner["completions"]["1"].update(
        state=current["state"], finished_at=current["finished_at"],
        result_sha256=team_gate.evidence_digest(current),
    )
    receipts = [older, current]
    if newer == "missing":
        receipts.pop()
        owner["completions"].pop("1")
    if newer == "undated":
        with pytest.raises(team_gate.GateRefusal) as error:
            team_gate.decide_reuse(receipts, **_REQUEST, **owner)
        assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)
        return
    assert team_gate.decide_reuse(receipts, **_REQUEST, **owner)["reusable"] is False
    recovery = _gate_receipt(attempt=3, finished_at="2026-11-24T03:00:00Z")
    new_owner = _owner_evidence([recovery])
    for name in owner:
        owner[name]["2"] = new_owner[name]["0"]
    assert team_gate.decide_reuse([*receipts, recovery], **_REQUEST, **owner)["reusable"]


@pytest.mark.parametrize("direct", [False, True], ids=["producer", "direct"])
def test_shard_retry_skips_superseded_artifacts_and_refuses_missing_file(tmp_path, direct):
    root = make_store(tmp_path)
    gate = _gate_config(shards=["unit", "integration"])
    old, old_row, owner = _stored_receipt(root, shard="unit", folder="pilot/unit-old", gate=gate, direct=direct)
    other, _, other_owner = _stored_receipt(root, shard="integration", folder="pilot/integration", gate=gate, direct=direct)
    retry, _, retry_owner = _stored_receipt(root, shard="unit", attempt=2, folder="pilot/unit-next", gate=gate, direct=direct)
    for name in owner:
        owner[name].update(other=other_owner[name]["0"], retry=retry_owner[name]["0"])
    paths = [old, other, retry]
    request = {**_REQUEST, "gate": gate}
    Path(old_row["kept"][0]["copy"]).unlink()
    decision = team_gate.decide_reuse_files(root, paths, **request, **owner)
    assert decision["passed_shards"] == [] and decision["incomplete_shards"] == ["unit", "integration"]
    assert decision["superseded_pass_count"] == 0
    result = root / retry
    saved = result.read_bytes()
    result.unlink()
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.decide_reuse_files(root, paths, **request, **owner)
    assert (error.value.code, error.value.exit_code) == ("missing_receipt", 1)
    result.write_bytes(saved)
    restored = team_gate.decide_reuse_files(root, paths, **request, **owner)
    assert restored["reason"] == "stale_incomplete"


@pytest.mark.parametrize("problem", ["duplicate", "trailing", "relocated", "missing", "counts", "symlink"])
def test_producer_junit_checks_entire_list_location_and_counts(tmp_path, problem):
    root = make_store(tmp_path)
    _path, row, owner = _stored_receipt(root)
    kept = row["kept"][0]
    if problem == "duplicate":
        row["kept"].append(dict(kept))
    elif problem == "trailing":
        row["kept"].append({"path": "out.txt", "copy": "out.txt", "bytes": 1})
    elif problem == "relocated":
        other = root / "other.xml"
        other.write_bytes(Path(kept["copy"]).read_bytes())
        kept["copy"] = str(other)
    elif problem == "missing":
        row["kept"] = [{"path": "run/junit.xml", "error": "missing"}]
    elif problem == "counts":
        row["tests"].update(passed=2, skipped=0)
    else:
        path = Path(kept["copy"])
        other = root / "other.xml"
        path.rename(other)
        symlink_or_skip(other, path)
    owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(row)
    if problem == "missing":
        decision = team_gate.decide_reuse([row], root=root, **_REQUEST, **owner)
        assert (decision["reusable"], decision["reason"]) == (False, "missing_test_evidence")
    else:
        with pytest.raises(team_gate.GateRefusal) as error:
            team_gate.decide_reuse([row], root=root, **_REQUEST, **owner)
        expected = "unsafe_path" if problem in ("relocated", "symlink") else "invalid_receipt"
        assert (error.value.code, error.value.exit_code) == (expected, 1)


def test_review_retry_needs_completed_tree_bound_cross_family_vote():
    receipt = _gate_receipt()
    owner = _owner_evidence([receipt])
    policy = {"require_cross_family": True}
    request = {**_REQUEST, **owner, "review_policy": policy}
    assert team_gate.decide_reuse([receipt], **request)["decision"] == "hold"
    rows, bindings = _review_fixture([
        {"role": "reviewer.correctness", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "reviewer.security", "verdict": "accept", "tree": TREE_A, "attempt": 1},
        {"role": "lens.extra", "verdict": "reject", "tree": TREE_A, "attempt": 1},
    ])
    for family in (None, "review-family", "writer-family"):
        result = team_gate.decide_reuse(
            [receipt], reviews=rows, review_evidence=bindings, author_family=family, **request
        )
        assert result["decision"] == ("reuse" if family == "writer-family" else "hold")
    # A later admission with no settled result supersedes the earlier acceptance.
    bindings["next"] = {**bindings["0"], "attempt": 2}
    del bindings["next"]["result_sha256"]
    result = team_gate.decide_reuse(
        [receipt], reviews=rows, review_evidence=bindings, author_family="writer-family", **request
    )
    assert result["decision"] == "hold"
    rows[0]["reviewer"] = "different-reviewer"
    bindings["0"]["result_sha256"] = team_gate.evidence_digest(rows[0])
    del bindings["next"]
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.decide_reuse([receipt], reviews=rows, review_evidence=bindings, **request)
    assert (error.value.code, error.value.exit_code) == ("invalid_review", 1)


def test_review_display_and_unknown_order_refuse_to_advance():
    receipt = _gate_receipt()
    secret = _secret_token()
    decision = _decide([receipt], reviews=_votes(
        {"role": secret, "verdict": "unavailable", "tree": TREE_A, "attempt": 1},
    ), **_REQUEST)
    assert secret not in json.dumps(decision)
    assert decision["unavailable_reviews"] == [team_gate.format_gate_label(secret, limit=64)]
    reviews = [
        {"role": "reviewer.correctness", "verdict": "accept", "tree": TREE_A, "attempt": None,
         "finished_at": "2026-11-24T02:00:00Z"},
        {"role": "reviewer.correctness", "verdict": "reject", "tree": TREE_A, "attempt": None},
    ]
    with pytest.raises(team_gate.GateRefusal) as error:
        _decide([receipt], reviews=reviews, **_REQUEST)
    assert (error.value.code, error.value.exit_code) == ("invalid_review", 1)


@pytest.fixture(params=["memory", "files"])
def round1c_decide(request, tmp_path):
    def decide(rows, *, owner=None, **options):
        owner = _owner_evidence(rows) if owner is None else copy.deepcopy(owner)
        kwargs = {**_REQUEST, **owner, **options}
        if request.param == "memory":
            return team_gate.decide_reuse(rows, **kwargs)
        root = make_store(kwargs.pop("root", tmp_path))
        paths, wire_digests = [], {}
        for index, row in enumerate(rows):
            payload = json.dumps(row, ensure_ascii=False).encode("utf-8")
            path = f"round-{index}.json"
            (root / path).write_bytes(payload)
            paths.append(path)
            wire_digests[team_gate.evidence_digest(row)] = hashlib.sha256(payload).hexdigest()
        for done in kwargs["completions"].values():
            digest = done["result_sha256"]
            done["result_sha256"] = wire_digests.get(digest, digest)
        return team_gate.decide_reuse_files(root, paths, **kwargs)
    return decide


def _votes(*extra):
    return [{"role": role, "verdict": "accept", "tree": TREE_A, "attempt": 1}
            for role in ("reviewer.correctness", "reviewer.security")] + list(extra)


def _review_decision(decide, votes, *, change=None, **options):
    rows, bindings = _review_fixture(votes)
    if change is not None:
        change(rows, bindings)
    return decide([_gate_receipt(gate=options.get("gate"))], reviews=rows, review_evidence=bindings, **options)


@pytest.mark.parametrize("change", ["missing", "state", "identity", "verdict", "chronology"])
def test_round1c_validates_every_review_before_selection(round1c_decide, change):
    votes = _votes(
        {"role": "lens.extra", "verdict": "confirmed", "tree": TREE_B, "attempt": 1,
         "finished_at": "2026-11-24T02:00:00Z"},
        {"role": "lens.extra", "verdict": "accept", "tree": TREE_B, "attempt": 2,
         "finished_at": "2026-11-24T03:00:00Z"},
    )

    def corrupt(rows, bindings):
        if change == "missing":
            rows[2]["tree"] = bindings["2"]["tree"] = TREE_A
            bindings["2"]["result_sha256"] = team_gate.evidence_digest(rows.pop(2))
            return
        if change == "state":
            rows[2].pop("state")
        elif change == "identity":
            rows[2]["reviewer"] = "unadmitted"
        elif change == "verdict":
            rows[2]["verdict"] = "unknown"
        else:
            stamp = "2026-11-24T01:00:00Z"
            rows[3]["finished_at"] = bindings["3"]["finished_at"] = stamp
            bindings["3"]["result_sha256"] = team_gate.evidence_digest(rows[3])
        bindings["2"]["result_sha256"] = team_gate.evidence_digest(rows[2])

    with pytest.raises(team_gate.GateRefusal) as error:
        _review_decision(round1c_decide, votes, change=corrupt)
    assert (error.value.code, error.value.exit_code) == ("invalid_review", 1)


@pytest.mark.parametrize("provided", ["policy", "reviews", "evidence", "one-vote", "stale-votes"])
def test_round1c_review_inputs_require_both_current_votes(round1c_decide, provided):
    receipt = _gate_receipt()
    if provided in ("one-vote", "stale-votes"):
        votes = _votes()[:1] if provided == "one-vote" else [{**vote, "tree": TREE_B} for vote in _votes()]
        result = _review_decision(round1c_decide, votes)
    else:
        options = {"policy": {"review_policy": {}}, "reviews": {"reviews": []},
                   "evidence": {"review_evidence": {}}}
        result = round1c_decide([receipt], **options[provided])
    assert (result["decision"], result["reason"]) == ("hold", "review_unavailable")
    assert round1c_decide([receipt])["reusable"]


@pytest.mark.parametrize("role", ["lens.extra", "audit.advisory"])
@pytest.mark.parametrize("retry", ["pending", "running", "unverified", "unavailable", "skipped", "tie"])
def test_round1c_confirmed_advisory_block_survives_retry(round1c_decide, role, retry):
    policy = {"lenses": [{"name": "audit.advisory", "voting": False}]}
    first = {"role": role, "verdict": "confirmed", "tree": TREE_A, "attempt": 1}
    second = {**first, "attempt": 1 if retry == "tie" else 2,
              "verdict": retry if retry in ("unavailable", "skipped") else "accept"}
    if retry == "running":
        second["state"] = "running"
    votes = _votes(first, second)

    def partial(rows, bindings):
        if retry == "pending":
            rows.pop(3)
            bindings["3"].pop("result_sha256")
        elif retry == "unverified":
            bindings["3"]["verified"] = False

    result = _review_decision(round1c_decide, votes, change=partial, review_policy=policy)
    assert result["reason"] == "review_blocked"
    recovery = {**second, "attempt": 3, "state": "completed", "verdict": "reject"}
    assert _review_decision(round1c_decide, [*votes, recovery], change=partial, review_policy=policy)["reusable"]


@pytest.mark.parametrize("preset", ["pair", "mixed"])
def test_round1c_resolved_security_pin_and_cross_family_votes(round1c_decide, preset):
    resolved = team_profile.resolve(preset=preset, repo={"policy": {"review": {
        "lenses": [{"name": "audit.voting", "host_pref": ["review"], "voting": True, "pinned_family": True}]
    }}})["profile"]
    [gate] = resolved["policy"]["gates"]
    policy = resolved["policy"]["review"]
    settings = resolved["model_settings"]
    security = settings["roles"]["reviewer.security"]
    assert security["pinned_family"]
    security_kind = settings["hosts"][security["hosts"][0]]["kind"]
    pin = team_profile.PRESET_DATA["hosts"][security_kind]["family"]
    votes = _votes({"role": "audit.voting", "verdict": "accept", "tree": TREE_A, "attempt": 1})
    votes[0]["family"], votes[1]["family"], votes[2]["family"] = "claude", pin, "claude"
    options = {"gate": gate, "review_policy": policy, "author_family": pin}
    assert _review_decision(round1c_decide, votes, **options)["reason"] == "review_unavailable"
    options["security_family"] = pin
    assert _review_decision(round1c_decide, votes, **options)["reusable"]
    for index in (0, 2):
        same_family = [{**vote, "family": pin} if i == index else vote for i, vote in enumerate(votes)]
        assert _review_decision(round1c_decide, same_family, **options)["reason"] == "review_unavailable"
        rejection = {**same_family[index], "verdict": "reject"}
        assert _review_decision(round1c_decide, [*votes, rejection], **options)["reason"] == "review_blocked"
    wrong_pin = [votes[0], {**votes[1], "family": "claude"}, votes[2]]
    assert _review_decision(round1c_decide, wrong_pin, **options)["reason"] == "review_unavailable"
    forged = [votes[0], {**votes[1], "pinned_family": True}, votes[2]]
    del options["security_family"]
    assert _review_decision(round1c_decide, forged, **options)["reason"] == "review_unavailable"


@pytest.mark.parametrize("kind", ["gate", "job"])
@pytest.mark.parametrize("layout", [["default"], ["unit", "integration"]])
def test_round1c_binds_effective_ordered_layout(round1c_decide, kind, layout):
    receipt = _gate_receipt if kind == "gate" else _job_result_receipt
    rows = [receipt(shard=shard) for shard in layout]
    owner = _owner_evidence(rows)
    assert round1c_decide(rows, required_shards=layout)["reusable"] == (kind == "gate" and layout == ["default"])
    for row in owner["admissions"].values():
        row["shards"] = layout
    matched = round1c_decide(rows, owner=owner, required_shards=layout)
    assert matched["stale_count"] == 0
    assert matched["passed_shards" if kind == "gate" else "incomplete_shards"] == layout
    if len(layout) > 1:
        stale = round1c_decide(rows, owner=owner, required_shards=layout[::-1])
        assert (stale["reason"], stale["stale_count"]) == ("stale_config", 2)
    owner["admissions"]["0"]["gate"]["shards"] = ["different"]
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide(rows, owner=owner, required_shards=layout)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("kind", ["gate", "job"])
@pytest.mark.parametrize("disposition", ["stale", "superseded", "tied", "unverified"])
@pytest.mark.parametrize("field", ["tests", "after", "kept", "junit_xml"])
def test_round1c_validates_all_in_memory_receipt_evidence(round1c_decide, kind, disposition, field):
    receipt = _gate_receipt if kind == "gate" else _job_result_receipt
    bad = receipt(tree=TREE_B if disposition == "stale" else TREE_A)
    other = _gate_receipt(state="running", exit_code=None) if disposition == "tied" else receipt(attempt=2)
    rows = [bad, other]
    owner = _owner_evidence(rows)
    bad[field] = {"tests": {"total": "bad"}, "after": {"source_tree": TREE_A},
                  "kept": [{"path": "run/junit.xml"}], "junit_xml": "<broken"}[field]
    owner["completions"]["0"].update(
        verified=disposition != "unverified", result_sha256=team_gate.evidence_digest(bad),
    )
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide(rows, owner=owner)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("kind", ["gate", "job"])
@pytest.mark.parametrize("outcome", ["red", "incomplete", "competing"])
def test_round1c_tied_latest_receipts_settle_all_before_preference(round1c_decide, kind, outcome):
    receipt = _gate_receipt if kind == "gate" else _job_result_receipt
    current = receipt()
    other = receipt(finished_at="2026-11-24T02:00:01Z")
    if outcome == "red":
        other["tests"] = {"total": 1, "passed": 0, "failed": 1, "errors": 0, "skipped": 0}
    elif outcome == "incomplete":
        other["after"] = None
    for rows in ([current, other], [other, current]):
        if outcome == "competing" and kind == "gate":
            with pytest.raises(team_gate.GateRefusal) as error:
                round1c_decide(rows)
            assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)
        else:
            expected = "red_evidence" if outcome == "red" else "stale_incomplete"
            assert round1c_decide(rows)["reason"] == expected
            later = _gate_receipt(attempt=2, finished_at="2026-11-24T02:00:02Z")
            result = round1c_decide([*rows, later])
            assert (result["reusable"], result["superseded_pass_count"]) == (True, int(kind == "gate"))


@pytest.mark.parametrize("kind", ["gate", "job"])
@pytest.mark.parametrize("element", ["container", "nested", "nested-container", "leaf"])
def test_round1c_reconciles_all_junit_counters(round1c_decide, kind, element):
    receipt = _gate_receipt if kind == "gate" else _job_result_receipt
    counts = {"total": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}
    row = receipt(tests=counts)
    xml = ('<testsuites%s><testsuite%s><testsuites%s><testsuite%s><testcase/>'
           '</testsuite></testsuites></testsuite></testsuites>')
    attrs = tuple(' tests="2" failures="1"' if part == element else ' tests="1"'
                  for part in ("container", "nested", "nested-container", "leaf"))
    row["junit_xml"] = xml % attrs
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([row])
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)
    row["junit_xml"] = xml % (' tests="1" failures="0"', ' tests="1"', ' tests="1"', ' tests="1"')
    decision = round1c_decide([row])
    assert (decision["reason"], decision["tests"]) == ("stale_incomplete", None)
    assert team_gate.junit_counts(row["junit_xml"].encode()) == (counts, None)


@pytest.mark.parametrize("kind", ["gate", "job"])
@pytest.mark.parametrize("expects_tests", [True, False])
def test_round1c_declared_junit_error_prevents_summary_fallback(round1c_decide, kind, expects_tests):
    receipt = _gate_receipt if kind == "gate" else _job_result_receipt
    row = receipt()
    row["kept"] = [{"path": "junit.xml", "error": "missing"}]
    owner = _owner_evidence([row])
    owner["admissions"]["0"]["expects_tests"] = expects_tests
    assert round1c_decide([row], owner=owner)["reason"] == "missing_test_evidence"


def test_round1c_legacy_junit_checks_digest_and_rejects_alias_duplicates(tmp_path):
    root = make_store(tmp_path)
    row = _gate_receipt()
    owner = _owner_evidence([row])
    owner["admissions"]["0"]["artifact_dir"] = "kept"
    (root / "kept").mkdir()
    report = root / "kept" / "junit.xml"
    xml = _junit_xml()
    report.write_bytes(xml)
    row["kept"] = [{"path": "junit.xml", "copy": "kept/junit.xml",
                    "bytes": len(xml), "sha256": hashlib.sha256(xml).hexdigest()}]

    def decide():
        payload = json.dumps(row).encode()
        (root / "receipt.json").write_bytes(payload)
        owner["completions"]["0"]["result_sha256"] = hashlib.sha256(payload).hexdigest()
        return team_gate.decide_reuse_files(root, ["receipt.json"], **_REQUEST, **owner)

    assert decide()["reason"] == "stale_incomplete"
    report.write_bytes(xml.replace(b"gate", b"unit"))
    with pytest.raises(team_gate.GateRefusal) as corrupt:
        decide()
    assert (corrupt.value.code, corrupt.value.exit_code) == ("invalid_receipt", 1)
    report.write_bytes(xml)
    row["kept"].append({"path": "run/junit.xml", "error": "missing"})
    with pytest.raises(team_gate.GateRefusal) as duplicate:
        decide()
    assert (duplicate.value.code, duplicate.value.exit_code) == ("invalid_receipt", 1)


def test_round1c_raw_utf8_and_canonical_object_digest_keep_distinct_limits(tmp_path):
    root = make_store(tmp_path)
    row = _gate_receipt(junit_xml="<!--" + "é" * 50000 + "-->" + _junit_xml().decode())
    payload = json.dumps(row, ensure_ascii=False).encode("utf-8")
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert len(payload) < team_gate.MAX_RECEIPT_BYTES < len(canonical)
    (root / "receipt.json").write_bytes(payload)
    loaded = team_gate.load_receipt(root, "receipt.json")
    assert team_gate.evidence_digest(loaded) == hashlib.sha256(canonical).hexdigest()
    assert team_gate.evidence_digest(payload) == hashlib.sha256(payload).hexdigest()
    assert _decide([loaded], **_REQUEST)["reason"] == "stale_incomplete"
    too_wide = {**row, "junit_xml": "é" * (team_gate.MAX_RECEIPT_BYTES // 2 + 1)}
    with pytest.raises(team_gate.GateRefusal) as error:
        team_gate.evidence_digest(too_wide)
    assert (error.value.code, error.value.exit_code) == ("limit_exceeded", 1)


@pytest.mark.parametrize("value,code", [(None, "invalid_receipt"),
                                       ([None] * (team_gate.MAX_RECEIPTS + 1), "limit_exceeded")])
def test_round1c_both_apis_classify_bad_collections_as_usage(value, code):
    for invoke in (team_gate.decide_reuse, lambda rows, **kwargs: team_gate.decide_reuse_files(None, rows, **kwargs)):
        with pytest.raises(team_gate.GateRefusal) as error:
            invoke(value, **_REQUEST)
        assert (error.value.code, error.value.exit_code) == (code, 2)


@pytest.mark.parametrize("family,code", [("", "invalid_review"), (7, "invalid_review"),
                                         ("a\nb", "multiline_value")])
def test_round1c_both_apis_classify_bad_author_family_as_usage(round1c_decide, family, code):
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([_gate_receipt()], author_family=family)
    assert (error.value.code, error.value.exit_code) == (code, 2)


def test_round1c_missing_declared_result_cannot_reuse_an_older_pass(round1c_decide):
    older, later = _gate_receipt(), _gate_receipt(attempt=2)
    owner = _owner_evidence([older, later])
    decision = round1c_decide([older], owner=owner)
    assert (decision["reason"], decision["superseded_pass_count"]) == ("stale_incomplete", 1)
    assert round1c_decide([older, later], owner=owner)["reusable"]


@pytest.mark.parametrize("kind", ["gate", "job"])
def test_round1c_malformed_kept_junit_refuses_despite_tied_failed_attempt(round1c_decide, tmp_path, kind):
    root = make_store(tmp_path)
    receipt = _gate_receipt if kind == "gate" else _job_result_receipt
    current, failed = receipt(), _gate_receipt(state="failed", exit_code=1)
    report = root / "kept" / "run" / "junit.xml"
    report.parent.mkdir(parents=True)
    payload = b"<malformed"
    report.write_bytes(payload)
    current["kept"] = [{"path": "run/junit.xml", "copy": str(report), "bytes": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest()}]
    for rows in ([current, failed], [failed, current]):
        owner = _owner_evidence(rows)
        owner["admissions"][str(rows.index(current))]["artifact_dir"] = "kept"
        with pytest.raises(team_gate.GateRefusal) as error:
            round1c_decide(rows, owner=owner, root=root)
        assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("field", ["recipes_sha256", "source_export", "host_plan", "failed_launch", "resolved_by_root"])
def test_round1c_validates_producer_provenance_even_on_refused_retry(round1c_decide, field):
    older = _gate_receipt()
    later = _job_result_receipt(attempt=2, state="failed", exit_code=1, tests=False)
    owner = _owner_evidence([older, later])
    later.update(state="refused", exit_code=None, before=None, after=None, steps=[])
    done = owner["completions"]["1"]
    done.update(state="refused", result_sha256=team_gate.evidence_digest(later))
    assert round1c_decide([older, later], owner=owner)["reason"] == "red_evidence"
    later[field] = {"recipes_sha256": "bad-digest", "source_export": {"tree": TREE_A},
                    "host_plan": False, "failed_launch": {"step": 0}, "resolved_by_root": True}[field]
    done["result_sha256"] = team_gate.evidence_digest(later)
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([older, later], owner=owner)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("kind", ["gate", "job"])
def test_round1d_subsecond_retry_order_and_exact_stamp_binding(round1c_decide, kind):
    receipt = _gate_receipt if kind == "gate" else _job_result_receipt
    first = receipt(attempt=None, finished_at="2026-11-24T02:00:01.000001Z")
    failed = receipt(attempt=None, finished_at="2026-11-24T02:00:01.000002Z", state="failed", exit_code=1)
    recovery = _gate_receipt(attempt=None, finished_at="2026-11-24T02:00:01.1Z")
    assert round1c_decide([failed, first])["reason"] == "red_evidence"
    assert round1c_decide([recovery, first, failed])["reusable"]
    owner = _owner_evidence([recovery])
    owner["completions"]["0"]["finished_at"] = "2026-11-24T02:00:01.100000Z"
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([recovery], owner=owner)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


def test_round1d_explicit_retry_cannot_reverse_subsecond_order(round1c_decide):
    first = _gate_receipt(attempt=1, finished_at="2026-11-24T02:00:01.000002Z")
    second = _gate_receipt(attempt=2, finished_at="2026-11-24T02:00:01.000001Z")
    assert round1c_decide([first])["reusable"]
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([first, second])
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


def test_round1d_subsecond_advisory_retry_must_be_demonstrably_later(round1c_decide):
    confirmed = {"role": "lens.extra", "tree": TREE_A, "attempt": None, "verdict": "confirmed",
                 "finished_at": "2026-11-24T02:00:01.1Z"}
    tied = {**confirmed, "verdict": "accept", "finished_at": "2026-11-24T02:00:01.100000Z"}
    later = {**tied, "finished_at": "2026-11-24T02:00:01.100001Z"}
    assert _review_decision(round1c_decide, _votes(confirmed, tied))["reason"] == "review_blocked"
    assert _review_decision(round1c_decide, _votes(later, confirmed, tied))["reusable"]


@pytest.mark.parametrize("stamp", ["2026-11-24t02:00:01z", "2026-11-24T02:00:01.1234567Z",
                                  "2026-02-29T02:00:01.123456Z", "2026-11-24T02:00:01+00:00"],
                         ids=["lowercase", "precision", "calendar", "offset"])
def test_round1d_invalid_utc_stamps_refuse_for_receipts_and_reviews(round1c_decide, stamp):
    row = _gate_receipt(finished_at=stamp)
    with pytest.raises(team_gate.GateRefusal) as receipt:
        round1c_decide([row])
    assert (receipt.value.code, receipt.value.exit_code) == ("invalid_receipt", 1)
    votes = _votes()
    votes[1]["finished_at"] = stamp
    with pytest.raises(team_gate.GateRefusal) as review:
        _review_decision(round1c_decide, votes)
    assert (review.value.code, review.value.exit_code) == ("invalid_review", 1)


@pytest.mark.parametrize("kind", ["gate", "job"])
def test_round1d_equal_receipt_content_requires_complete_multiplicity_and_binding(round1c_decide, kind):
    row = _gate_receipt() if kind == "gate" else _job_result_receipt()
    owner = _owner_evidence([row, row])
    del row["attempt"]
    for index, done in owner["completions"].items():
        done["result_sha256"] = team_gate.evidence_digest(row)
        owner["admissions"][index]["attempt"] = int(index) + 1
    rows = [row, copy.deepcopy(row)]
    result = round1c_decide(rows[::-1], owner=owner)
    assert (result["reusable"], result["superseded_pass_count"]) == (kind == "gate", int(kind == "gate"))
    if kind == "job":
        assert result["reason"] == "stale_incomplete"
    assert round1c_decide([], owner=owner)["reason"] == "stale_incomplete"
    for bad in ([row], [row, row, row]):
        with pytest.raises(team_gate.GateRefusal) as error:
            round1c_decide(bad, owner=owner)
        assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)
    owner["admissions"]["1"]["attempt"] = 1
    if kind == "gate":
        with pytest.raises(team_gate.GateRefusal) as tied:
            round1c_decide(rows, owner=owner)
        assert (tied.value.code, tied.value.exit_code) == ("invalid_receipt", 1)
    else:
        assert round1c_decide(rows, owner=owner)["reason"] == "stale_incomplete"
    owner["admissions"]["1"]["attempt"] = 2
    owner["admissions"]["1"]["before"]["source_tree"] = TREE_B
    with pytest.raises(team_gate.GateRefusal) as wrong_tree:
        round1c_decide(rows, owner=owner)
    assert (wrong_tree.value.code, wrong_tree.value.exit_code) == ("invalid_receipt", 1)


def test_round1d_equal_job_content_can_bind_two_independent_shards(round1c_decide):
    gate = _gate_config(shards=["unit", "integration"])
    row = _job_result_receipt(gate=gate, shard="unit")
    owner = _owner_evidence([row, row])
    for key in ("gate", "shard", "attempt"):
        del row[key]
    owner["admissions"]["1"]["shard"] = "integration"
    for done in owner["completions"].values():
        done["result_sha256"] = team_gate.evidence_digest(row)
    result = round1c_decide([row, row], owner=owner, gate=gate)
    assert (result["reason"], result["stale_count"]) == ("stale_incomplete", 0)
    assert result["incomplete_shards"] == ["unit", "integration"] and result["passed_shards"] == []


def test_round1d_review_replays_cannot_create_a_distinct_vote(round1c_decide):
    correct, security = _votes()
    assert _review_decision(round1c_decide, [correct, correct])["reason"] == "review_unavailable"
    assert _review_decision(round1c_decide, [security, correct, correct])["reusable"]

    def wrong_role(rows, bindings):
        bindings["2"]["role"] = "lens.extra"

    def missing(rows, bindings):
        rows.pop()

    def excess(rows, bindings):
        rows.append(rows[-1])

    def unverified(rows, bindings):
        bindings["1"]["verified"] = False

    assert _review_decision(round1c_decide, [security, correct, correct], change=unverified)["reusable"]
    for corrupt in (wrong_role, missing, excess):
        with pytest.raises(team_gate.GateRefusal) as error:
            _review_decision(round1c_decide, [security, correct, correct], change=corrupt)
        assert (error.value.code, error.value.exit_code) == ("invalid_review", 1)


@pytest.mark.parametrize("layout", ["tied", "sharded"])
@pytest.mark.parametrize("state,status", [("failed", 1), ("refused", None), ("timed_out", 124), ("cancelled", 130)])
def test_round1d_verified_failure_remains_red_without_payload(round1c_decide, layout, state, status):
    shards = ["default", "other"] if layout == "sharded" else ["default"]
    gate = _gate_config(shards=shards)
    passing = _gate_receipt(gate=gate)
    failing = _job_result_receipt(gate=gate, shard=shards[-1], state=state, exit_code=status, tests=False)
    owner = _owner_evidence([passing, failing])
    decision = round1c_decide([passing], owner=owner, gate=gate)
    assert (decision["reason"], decision["red_shards"]) == ("red_evidence", [shards[-1]])
    owner["completions"]["1"]["verified"] = False
    assert round1c_decide([passing], owner=owner, gate=gate)["incomplete_shards"] == [shards[-1]]
    passing["tests"]["passed"] = 0
    owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(passing)
    owner["completions"]["1"]["verified"] = True
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([passing], owner=owner, gate=gate)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


def test_round1d_expanded_label_remains_redacted_and_bounded(round1c_decide):
    name = "\x1b[0m" + "://a:b@" * 584
    gate = _gate_config(name=name)
    row = _gate_receipt(gate=gate)
    expected = team_gate.format_gate_label(name)
    decision = round1c_decide([row], gate=gate)
    assert (decision["reusable"], decision["gate_name"]) == (True, expected)
    assert len(expected) <= 128 and "a:b@" not in expected and "\x1b" not in expected
    wide = team_gate.format_gate_label(name, limit=team_gate.MAX_STRING)
    assert len(name) < len(wide) <= team_gate.MAX_STRING and "a:b@" not in wide


@pytest.mark.parametrize("where", ["request", "receipt", "review"])
def test_round1d_label_refusals_are_translated_by_context(round1c_decide, monkeypatch, where):
    original = team_gate.redact_display_secrets

    def refuses(text, *, limit):
        if text == "reject-display":
            raise RedactionRefusal("invalid")
        return original(text, limit=limit)

    monkeypatch.setattr(team_gate, "redact_display_secrets", refuses)
    row = _gate_receipt()
    owner = _owner_evidence([row])
    options = {}
    if where == "request":
        options["gate"] = _gate_config(name="reject-display")
    elif where == "receipt":
        row["gate"]["name"] = "reject-display"
        owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(row)
    else:
        votes = _votes({"role": "reject-display", "tree": TREE_A, "attempt": 1, "verdict": "unavailable"})
        options["reviews"], options["review_evidence"] = _review_fixture(votes)
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([row], owner=owner, **options)
    expected = {"request": ("invalid_gate_config", 2), "receipt": ("invalid_receipt", 1),
                "review": ("invalid_review", 1)}
    assert (error.value.code, error.value.exit_code) == expected[where]
    assert "reject-display" not in str(error.value)


@pytest.mark.parametrize("problem", ["null-plan", "orphan-digest", "missing-field", "extra-plan", "multiline-plan",
                                    "unknown-derivation", "partial-complete", "null-export", "extra-export"])
def test_round1d_provenance_groups_are_closed_and_presence_based(round1c_decide, problem):
    derivation = {"derived_by": "runner", "dirty_content_sha256": team_gate.EMPTY_STATUS,
                  "host_plan": {"path": "/work/host-plan.json", "sha256": "f" * 64, "team": "review"},
                  "expected_tree": None, "changed_paths": None}
    export = {"commit": COMMIT_A, "tree": TREE_A, "entries": 7, "bytes": 900, "removed": True}
    failed = _job_result_receipt(state="failed", exit_code=1)
    failed.update(derivation, source_export=export)
    assert round1c_decide([failed])["reason"] == "red_evidence"
    row = _job_result_receipt()
    if problem == "null-plan":
        row["host_plan"] = None
    elif problem == "orphan-digest":
        row["dirty_content_sha256"] = team_gate.EMPTY_STATUS
    elif problem == "missing-field":
        row.update(derivation)
        row.pop("expected_tree")
    elif problem == "extra-plan":
        row.update(derivation, host_plan={**derivation["host_plan"], "unknown": True})
    elif problem == "multiline-plan":
        row.update(derivation, host_plan={**derivation["host_plan"], "team": "one\ntwo"})
    elif problem == "unknown-derivation":
        row.update(derivation, derived_paths=[])
    elif problem == "partial-complete":
        row.update(derivation)
    else:
        row["source_export"] = None if problem == "null-export" else {**export, "unknown": True}
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([row])
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


def test_round1e_producer_argv_and_digest_do_not_prove_the_requested_launch(round1c_decide):
    for digest in ("a" * 64, "b" * 64):
        producer = _job_result_receipt()
        producer.update(recipe="full-suite", recipes_sha256=digest)
        decision = round1c_decide([producer])
        assert (decision["decision"], decision["reason"]) == ("run", "stale_incomplete")
        assert decision["passed_shards"] == [] and decision["incomplete_shards"] == ["default"]
        assert decision["tests"] is None

    direct = _gate_receipt(tests=producer["tests"])
    assert round1c_decide([direct])["reason"] == "exact_tree_pass"
    producer["tests"].update(passed=3, failed=1)
    adverse = round1c_decide([producer])
    assert (adverse["reason"], adverse["red_shards"], adverse["tests"]["failed"]) == ("red_evidence", ["default"], 1)


def test_round1e_shard_expansions_need_exact_request_argv(round1c_decide):
    gate = _gate_config(shards=["unit", "integration"])
    unit = (*LOCAL_CMD, "--junitxml", "/jobs/unit/scratch/run/junit.xml")
    integration = (*LOCAL_CMD, "--junitxml", "/jobs/integration/scratch/run/junit.xml")
    template = (*LOCAL_CMD, "--junitxml", "$scratch/junit.xml")
    producer = [_job_result_receipt(gate=gate, shard=shard, command=command)
                for shard, command in zip(gate["shards"], (unit, integration))]
    incompatible = round1c_decide(producer, gate=gate, command=template)
    assert (incompatible["reason"], incompatible["stale_count"]) == ("stale_command", 2)
    partial = round1c_decide(producer, gate=gate, command=unit)
    assert (partial["reason"], partial["stale_count"], partial["passed_shards"]) == ("stale_incomplete", 1, [])

    direct = [_gate_receipt(gate=gate, shard=shard, command=command)
              for shard, command in zip(gate["shards"], (unit, integration))]
    partial = round1c_decide(direct, gate=gate, command=unit)
    assert (partial["reason"], partial["stale_count"], partial["passed_shards"]) == ("partial_evidence", 1, ["unit"])
    direct[1] = _gate_receipt(gate=gate, shard="integration", command=unit)
    assert round1c_decide(direct, gate=gate, command=unit)["passed_shards"] == ["unit", "integration"]


@pytest.mark.parametrize("storage", ["inline", "kept"])
@pytest.mark.parametrize("ambiguous", [
    '<testcase><failure xmlns="urn:junit"/></testcase>',
    '<testcase><unknown/></testcase>',
    '<testcase><system-out>unclear</system-out></testcase>',
    '<testcase/><properties xmlns="urn:junit"/>',
], ids=["qualified-outcome", "unknown-case-child", "case-metadata", "qualified-suite-metadata"])
def test_round1e_ambiguous_xml_cannot_supply_pass_credit(round1c_decide, tmp_path, storage, ambiguous):
    def decide(fragment):
        xml = f'<testsuite tests="1">{fragment}</testsuite>'
        row = _gate_receipt(tests=False)
        owner = _owner_evidence([row])
        options = {}
        if storage == "inline":
            row["junit_xml"] = xml
        else:
            root = make_store(tmp_path)
            report = root / "evidence" / "junit.xml"
            report.parent.mkdir(exist_ok=True)
            raw = xml.encode()
            report.write_bytes(raw)
            row["kept"] = [{"path": "junit.xml", "copy": "evidence/junit.xml",
                            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}]
            owner["admissions"]["0"]["artifact_dir"] = "evidence"
            options["root"] = root
        owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(row)
        return round1c_decide([row], owner=owner, **options)

    with pytest.raises(team_gate.GateRefusal) as error:
        decide(ambiguous)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)
    failed = decide("<testcase><failure/></testcase>")
    assert (failed["reason"], failed["red_shards"], failed["tests"]) == ("red_evidence", ["default"], None)
    assert decide("<testcase/>")["reason"] == "stale_incomplete"


@pytest.mark.parametrize("origin", ["omitted", "indeterminate", "producer", "direct"])
def test_round1f_only_owner_admitted_direct_origin_can_reuse(round1c_decide, origin):
    row = _gate_receipt()
    owner = _owner_evidence([row])
    admission = owner["admissions"]["0"]
    admission.pop("origin", None)
    if origin != "omitted":
        admission["origin"] = None if origin == "indeterminate" else origin
    if origin == "producer":
        with pytest.raises(team_gate.GateRefusal) as error:
            round1c_decide([row], owner=owner)
        assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)
        return
    decision = round1c_decide([row], owner=owner)
    expected = "exact_tree_pass" if origin == "direct" else "stale_incomplete"
    assert decision["reason"] == expected
    assert decision["passed_shards"] == (["default"] if origin == "direct" else [])
    if origin != "direct":
        assert decision["next_action"].startswith("Run the configured local gate")


@pytest.mark.parametrize("origin", ["omitted", "producer", "direct"])
def test_round1f_job_bound_admission_refuses_direct_spelling(round1c_decide, origin):
    job = _job_result_receipt()
    owner = _owner_evidence([job])
    admission = owner["admissions"]["0"]
    admission.pop("origin", None)
    if origin != "omitted":
        admission["origin"] = origin
    impostor = _gate_receipt()
    owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(impostor)
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([impostor], owner=owner)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)
    if origin != "direct":
        owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(job)
        result = round1c_decide([job], owner=owner)
        assert result["reason"] == "stale_incomplete" and result["next_action"].startswith("Run")


@pytest.mark.parametrize("declaration", ["inline", "null-inline", "legacy-kept", "producer-kept"])
def test_round1f_xml_cannot_authorize_pass_or_superseded_credit(round1c_decide, tmp_path, declaration):
    older = _gate_receipt(attempt=1)
    recovery = _gate_receipt(attempt=2, finished_at="2026-11-24T02:01:00Z")
    rows = [older, recovery]
    owner = _owner_evidence(rows)
    options = {}
    raw = _junit_xml()
    if declaration in ("inline", "null-inline"):
        older["junit_xml"] = raw.decode() if declaration == "inline" else None
    else:
        name = "junit.xml" if declaration == "legacy-kept" else "run/junit.xml"
        root = make_store(tmp_path)
        report = root / "evidence" / name
        report.parent.mkdir(parents=True)
        report.write_bytes(raw)
        older["kept"] = [{"path": name, "copy": "evidence/" + name,
                          "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]
        owner["admissions"]["0"]["artifact_dir"] = "evidence"
        options["root"] = root
    owner["completions"]["0"]["result_sha256"] = team_gate.evidence_digest(older)
    old_owner = {name: {"0": entries["0"]} for name, entries in owner.items()}
    decision = round1c_decide([older], owner=old_owner, **options)
    assert (decision["reason"], decision["tests"], decision["passed_shards"]) == ("stale_incomplete", None, [])
    assert decision["next_action"].startswith("Run")
    result = round1c_decide(rows, owner=owner, **options)
    assert (result["reason"], result["superseded_pass_count"]) == ("exact_tree_pass", 0)


@pytest.mark.parametrize("state", ["completed", "failed", "running", "settled-running", "unverified", "admitted"])
def test_round1f_recovery_advice_uses_owner_attempt_state(round1c_decide, state):
    older = _gate_receipt(attempt=1)
    done = _gate_receipt(attempt=2, finished_at="2026-11-24T02:01:00Z")
    owner = _owner_evidence([older, done])
    owner["admissions"]["0"].pop("origin", None)
    current = owner["completions"]["1"]
    if state == "admitted":
        del owner["completions"]["1"]
    elif state == "unverified":
        current["verified"] = False
    else:
        current["state"] = "running" if state == "settled-running" else state
        current["settled"] = state != "running"
    decision = round1c_decide([older], owner=owner)
    if state == "failed":
        assert (decision["reason"], decision["red_shards"]) == ("red_evidence", ["default"])
    else:
        assert (decision["reason"], decision["incomplete_shards"]) == ("stale_incomplete", ["default"])
        assert decision["next_action"].startswith("Wait" if state in ("running", "admitted") else "Run")
    assert decision["superseded_pass_count"] == 0
    if state == "completed":
        recovery = round1c_decide([older, done], owner=owner)
        assert (recovery["reason"], recovery["superseded_pass_count"]) == ("exact_tree_pass", 0)


def test_round1h_mixed_pending_and_settled_shards_wait_for_settlement(round1c_decide):
    gate = _gate_config(shards=["unit", "integration", "docs"])
    passed = _gate_receipt(shard="unit", gate=gate)
    waiting = _gate_receipt(shard="integration", gate=gate, state="running", exit_code=None)
    old = _gate_receipt(shard="docs", gate=gate)
    owner = _owner_evidence([passed, waiting, old])
    owner["completions"]["1"]["settled"] = False
    owner["admissions"]["2"].pop("origin", None)
    result = round1c_decide([passed, waiting, old], owner=owner, gate=gate)
    assert (result["reason"], result["incomplete_shards"]) == ("partial_evidence", ["integration", "docs"])
    assert result["next_action"] == "Wait for all outstanding gate attempts to settle before launching any gate run."


@pytest.mark.parametrize("report", [
    '<testsuite tests="1"><test-result outcome="failed"/></testsuite>',
    '<testsuite tests="1"><testcase status="notrun" result="suppressed"/></testsuite>',
], ids=["suite-result", "case-attributes"])
def test_round1f_unsupported_xml_cannot_reuse_with_matching_summary(round1c_decide, report):
    row = _gate_receipt(tests={"total": 1, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}, junit_xml=report)
    result = round1c_decide([row])
    assert (result["reason"], result["passed_shards"], result["tests"]) == ("stale_incomplete", [], None)
    assert result["next_action"].startswith("Run")


def test_round1f_missing_counts_and_optional_counts_keep_their_gate_contract(round1c_decide):
    row = _gate_receipt(tests=False)
    owner = _owner_evidence([row])
    missing = round1c_decide([row], owner=owner)
    assert missing["reason"] == "missing_test_evidence" and missing["next_action"].startswith("Run")
    owner["admissions"]["0"]["expects_tests"] = False
    optional = round1c_decide([row], owner=owner)
    assert (optional["reason"], optional["tests"]) == ("exact_tree_pass", None)


@pytest.mark.parametrize("kind", ["direct", "producer"])
@pytest.mark.parametrize("storage", ["inline", "junit.xml", "run/junit.xml"])
@pytest.mark.parametrize("outcome", ["failure", "mixed", "error", "summary-only", "summary-fallback", "summary-sibling", "zero-pass"])
def test_round1g_xml_is_excluded_from_gate_totals(round1c_decide, tmp_path, kind, storage, outcome):
    gate = _gate_config(shards=["plain", "report"])
    plain = _gate_receipt(shard="plain", gate=gate)
    receipt = _gate_receipt if kind == "direct" else _job_result_receipt
    red_case = "<testcase><failure/></testcase>"
    cases = {
        "failure": red_case + "<testcase/>",
        "mixed": red_case + '<testcase status="notrun" result="suppressed"/>',
        "error": "<testcase><error/></testcase><testcase/>",
        "summary-only": "",
        "summary-fallback": '<test-result outcome="failed"/>',
        "summary-sibling": '<testsuite tests="1" failures="1"/><testsuite><testcase status="notrun"/></testsuite>',
        "zero-pass": "",
    }
    counts = {"total": 2, "passed": 1, "failed": 1, "errors": 0, "skipped": 0}
    if outcome == "error":
        counts.update(failed=0, errors=1)
    if outcome == "zero-pass":
        counts.update(passed=0, failed=0, skipped=2)
    row = receipt(shard="report", gate=gate, tests=counts)
    tag = "testsuites" if outcome == "summary-sibling" else "testsuite"
    attrs = f'tests="2" failures="{counts["failed"]}" errors="{counts["errors"]}" skipped="{counts["skipped"]}"'
    raw = f'<{tag} {attrs}>{cases[outcome]}</{tag}>'.encode()
    assert team_gate.junit_counts(raw) == (counts, None)
    options = {}
    if storage == "inline":
        row["junit_xml"] = raw.decode()
    else:
        root = make_store(tmp_path)
        path = root / "report" / storage
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        row["kept"] = [{"path": storage, "copy": "report/" + storage,
                        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]
        options["root"] = root
    recovery = _gate_receipt(shard="report", gate=gate, attempt=2, finished_at="2026-11-24T02:01:00Z")
    rows = [plain, row, recovery]
    owner = _owner_evidence(rows)
    if storage != "inline":
        owner["admissions"]["1"]["artifact_dir"] = "report"
    current = {name: {key: values[key] for key in ("0", "1")} for name, values in owner.items()}
    decision = round1c_decide(rows[:2], gate=gate, owner=current, **options)
    if outcome in ("summary-only", "summary-fallback", "summary-sibling", "zero-pass"):
        assert (decision["reason"], decision["red_shards"]) == ("partial_evidence", [])
    else:
        assert (decision["reason"], decision["red_shards"]) == ("red_evidence", ["report"])
    assert (decision["passed_shards"], decision["tests"]) == (["plain"], None)
    if storage != "inline":
        path.unlink()
    owner["completions"]["1"]["settled"] = False
    settled = round1c_decide(rows, gate=gate, owner=owner, **options)
    assert (settled["reason"], settled["superseded_pass_count"]) == ("exact_tree_pass", 0)
    assert settled["tests"] == {"total": 10, "passed": 10, "failed": 0, "errors": 0, "skipped": 0}


@pytest.mark.parametrize("kind", ["direct", "producer"])
@pytest.mark.parametrize("state", ["completed", "failed"])
def test_round1g_waits_for_settlement_after_command_exit(round1c_decide, kind, state):
    receipt = _gate_receipt if kind == "direct" else _job_result_receipt
    row = receipt(state=state, exit_code=0 if state == "completed" else 1)
    row["process_stopped_confirmed"] = False
    owner = _owner_evidence([row])
    owner["completions"]["0"]["settled"] = False
    outstanding = round1c_decide([row], owner=owner)
    reason = "stale_incomplete" if state == "completed" else "red_evidence"
    assert (outstanding["reason"], outstanding["next_action"].startswith("Wait")) == (reason, True)
    owner["completions"]["0"]["settled"] = True
    settled = round1c_decide([row], owner=owner)
    assert settled["reason"] == reason
    assert settled["next_action"].startswith("Run" if state == "completed" else "Fix")
    recovery = _gate_receipt(attempt=2, finished_at="2026-11-24T02:01:00Z")
    assert round1c_decide([row, recovery])["reason"] == "exact_tree_pass"


def test_round1h_tied_outstanding_attempt_blocks_launch_and_keeps_fix_advice(round1c_decide):
    gate = _gate_config(shards=["busy", "ready", "passed"])
    running = _gate_receipt(gate=gate, shard="busy")
    failed = _gate_receipt(gate=gate, shard="busy", state="failed", exit_code=1)
    passed = _gate_receipt(gate=gate, shard="passed")
    rows = [running, failed, passed]
    owner = _owner_evidence(rows)
    owner["completions"]["0"]["settled"] = False
    decision = round1c_decide(rows, gate=gate, owner=owner)
    assert (decision["reason"], decision["red_shards"]) == ("red_evidence", ["busy"])
    assert decision["next_action"] == (
        "Wait for all outstanding gate attempts to settle before launching any gate run. Fix the failing gate run."
    )
    owner["completions"]["0"]["settled"] = True
    settled = round1c_decide(rows, gate=gate, owner=owner)
    assert (settled["reason"], settled["red_shards"]) == ("red_evidence", ["busy"])
    assert settled["next_action"].startswith("Fix the failing gate run.")
    assert "Wait" not in settled["next_action"]


def test_round1h_tied_xml_counters_cannot_create_or_discard_red(round1c_decide):
    gate = _gate_config(shards=["tied", "plain"])
    passed = _gate_receipt(gate=gate, shard="plain")
    failed = _gate_receipt(gate=gate, shard="tied", tests={"total": 1, "passed": 0, "failed": 1,
                                                         "errors": 0, "skipped": 0})
    xml = _gate_receipt(gate=gate, shard="tied", tests=False, junit_xml='<testsuite tests="1" failures="1"/>')
    result = round1c_decide([passed, failed, xml], gate=gate)
    assert (result["reason"], result["red_shards"], result["tests"]) == ("red_evidence", ["tied"], None)
    clean = _gate_receipt(gate=gate, shard="tied")
    result = round1c_decide([passed, clean, xml], gate=gate)
    assert (result["reason"], result["red_shards"], result["tests"]) == ("partial_evidence", [], None)
    xml["junit_xml"] = '<testsuite tests="1"><testcase><unknown/></testcase></testsuite>'
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([passed, failed, xml], gate=gate)
    assert (error.value.code, error.value.exit_code) == ("invalid_receipt", 1)


@pytest.mark.parametrize("declaration", ["null-inline", "kept-error"])
def test_round1g_unavailable_xml_does_not_publish_summary_fallback(round1c_decide, declaration):
    gate = _gate_config(shards=["plain", "report"])
    plain = _gate_receipt(shard="plain", gate=gate)
    claims = {"total": 1, "passed": 0, "failed": 1, "errors": 0, "skipped": 0}
    xml = _gate_receipt(shard="report", gate=gate, tests=claims)
    if declaration == "null-inline":
        xml["junit_xml"] = None
    else:
        xml["kept"] = [{"path": "run/junit.xml", "error": "missing"}]
    decision = round1c_decide([plain, xml], gate=gate)
    assert (decision["reason"], decision["red_shards"], decision["tests"]) == ("partial_evidence", [], None)
    plain["tests"] = claims
    red = round1c_decide([plain, xml], gate=gate)
    assert (red["reason"], red["red_shards"], red["tests"]) == ("red_evidence", ["plain"], None)


def _assert_round1i_refusal(error, code):
    assert error.as_dict() == {
        "schema": team_gate.GATE_SCHEMA, "status": "refused", "reusable": False, "decision": "refused",
        "code": code, "reason": code, "message": team_gate.REFUSALS[code], "exit_code": 1,
        "next_action": team_gate.NEXT_ACTIONS[code] + " Re-evaluate after repair before launching any gate run.",
    }
    assert str(error) == team_gate.REFUSALS[code]


@pytest.mark.parametrize("kind", ["direct", "producer"])
@pytest.mark.parametrize("problem", ["missing", "malformed"])
@pytest.mark.parametrize("red_source", ["execution", "summary"])
def test_round1i_kept_refusal_repairs_and_requires_re_evaluation(round1c_decide, tmp_path, problem, kind, red_source):
    root = make_store(tmp_path)
    gate = _gate_config(shards=["unit", "integration"])
    raw = b"<bad"
    report = root / "report" / "junit.xml"
    report.parent.mkdir()
    if problem == "malformed":
        report.write_bytes(raw)
    receipt = _gate_receipt if kind == "direct" else _job_result_receipt
    row = receipt(tests=False, gate=gate, shard="integration")
    row["kept"] = [{"path": "junit.xml", "copy": "report/junit.xml",
                    "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]
    claims = {"total": 1, "passed": 0, "failed": 1, "errors": 0, "skipped": 0}
    failed = (receipt(gate=gate, shard="unit", state="failed", exit_code=1) if red_source == "execution"
              else receipt(gate=gate, shard="unit", tests=claims))
    assert round1c_decide([failed], gate=gate)["red_shards"] == ["unit"]
    rows = [failed, row]
    owner = _owner_evidence(rows)
    owner["admissions"]["1"]["artifact_dir"] = "report"
    code = "missing_receipt" if problem == "missing" else "invalid_receipt"
    for settled in (False, True):
        owner["completions"]["1"]["settled"] = settled
        with pytest.raises(team_gate.GateRefusal) as error:
            round1c_decide(rows, owner=owner, root=root, gate=gate)
        _assert_round1i_refusal(error.value, code)


@pytest.mark.parametrize("input_kind", ["memory", "file", "missing-file"])
@pytest.mark.parametrize("owner_state", [
    "outstanding", "settled", "invalid", "bad-order", "absent", "explicit-empty", "pending", "tied", "stale", "superseded",
])
def test_round1i_early_refusal_keeps_precedence_and_uses_only_code(tmp_path, input_kind, owner_state):
    row = _gate_receipt()
    bad_json = b'{"untrusted-value":'
    owner = _owner_evidence([row])
    owner["completions"]["0"].update(
        result_sha256=hashlib.sha256(bad_json).hexdigest(), settled=owner_state == "settled",
    )
    if owner_state == "invalid":
        owner["completions"]["0"]["settled"] = "untrusted-value"
    if owner_state == "bad-order":
        owner["admissions"]["older"] = {**owner["admissions"]["0"], "attempt": None}
    if owner_state == "stale":
        owner["admissions"]["0"]["before"] = _clean_witness(TREE_B)
    if owner_state == "superseded":
        owner["admissions"]["older"] = dict(owner["admissions"]["0"])
        owner["admissions"]["0"]["attempt"] = 2
        owner["completions"]["0"]["settled"] = True
    if owner_state == "tied":
        owner["admissions"]["next"] = dict(owner["admissions"]["0"])
        owner["completions"]["0"]["settled"] = True
    if owner_state == "pending":
        owner["completions"].clear()
    if owner_state == "absent":
        owner = {}
    if owner_state == "explicit-empty":
        owner = {"admissions": {}, "completions": {}}
    kwargs = {**_REQUEST, **owner}
    code = "missing_receipt" if input_kind == "missing-file" else "invalid_json"
    if input_kind != "memory":
        root = make_store(tmp_path)
        if input_kind == "file":
            (root / "malformed.json").write_bytes(bad_json)
    with pytest.raises(team_gate.GateRefusal) as error:
        if input_kind == "memory":
            team_gate.decide_reuse([bad_json], **kwargs)
        else:
            team_gate.decide_reuse_files(root, ["malformed.json"], **kwargs)
    expected_code = "invalid_receipt" if input_kind != "missing-file" and owner_state == "invalid" else code
    _assert_round1i_refusal(error.value, expected_code)
    assert "untrusted-value" not in str(error.value.as_dict())


@pytest.mark.parametrize("kind", ["direct", "producer"])
@pytest.mark.parametrize("problem", ["ordering", "review"])
@pytest.mark.parametrize("red_source", ["drift", "xml"])
def test_round1i_refusal_requires_re_evaluation_before_direct_reuse(round1c_decide, kind, problem, red_source):
    gate = _gate_config(shards=["unit", "integration"])
    receipt = _gate_receipt if kind == "direct" else _job_result_receipt
    red = receipt(gate=gate, shard="unit", tests=False)
    if red_source == "drift":
        red["after"] = _clean_witness(TREE_B)
    else:
        red["junit_xml"] = '<testsuite tests="1"><testcase><error/></testcase></testsuite>'
    control = round1c_decide([red], gate=gate)
    assert control["red_shards"] == ["unit"] and control["next_action"].startswith("Fix")

    other = _gate_receipt(gate=gate, shard="integration", tests=False)
    rows = [red, other]
    owner = _owner_evidence(rows)
    owner["admissions"]["unorderable"] = {**owner["admissions"]["1"], "attempt": None}
    options = {"reviews": []} if problem == "review" else {}
    if problem == "review":
        options["review_evidence"] = {"invalid": {}}
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide(rows, owner=owner, gate=gate, **options)
    _assert_round1i_refusal(error.value, "invalid_review" if problem == "review" else "invalid_receipt")

    fresh = [_gate_receipt(gate=gate, shard=shard, attempt=2, finished_at="2026-11-24T02:01:00Z")
             for shard in ("unit", "integration")]
    reviews, review_evidence = _review_fixture(_votes())
    repaired = round1c_decide([*rows, *fresh], gate=gate, reviews=reviews, review_evidence=review_evidence)
    assert (repaired["reason"], repaired["passed_shards"], repaired["red_shards"]) == (
        "exact_tree_pass", ["unit", "integration"], [],
    )


def test_round1i_usage_refusal_preserves_original_repair(round1c_decide):
    with pytest.raises(team_gate.GateRefusal) as error:
        round1c_decide([], tree="untrusted-value")
    assert (error.value.code, error.value.exit_code) == ("invalid_tree", 2)
    assert error.value.next_action == team_gate.NEXT_ACTIONS["invalid_tree"]


@pytest.mark.parametrize("api", ["memory", "files"])
def test_round1h_gate_without_owner_state_verifies_before_launch(tmp_path, api):
    decide, args = team_gate.decide_reuse, ([],)
    if api == "files":
        decide, args = team_gate.decide_reuse_files, (make_store(tmp_path), [])
    unknown = decide(*args, **_REQUEST)
    known_empty = decide(*args, **_REQUEST, admissions={})
    assert unknown["reason"] == known_empty["reason"] == "missing_evidence"
    assert unknown["next_action"].startswith("Verify owner attempt state")
    assert known_empty["next_action"].startswith("Run")
