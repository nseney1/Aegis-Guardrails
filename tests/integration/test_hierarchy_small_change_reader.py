"""Read-only declaration classification through the lifecycle CLI."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.integration.test_hierarchy_lifecycle import Ledger, raw_request, request as lifecycle_request


TOOL = Path(__file__).resolve().parents[2] / "tools" / "hierarchy_lifecycle.py"


SCOPE = str(Path("/fixture/engine/tests").absolute())
OTHER_SCOPE = str(Path("/fixture/other").absolute())


def request(**changes):
    return lifecycle_request(**{"paths": [SCOPE], **changes})


def proposal():
    raw = raw_request(request())
    return {"schema": "aegis.small-change-plan/v1", "request": raw,
            "plan": {"request_sha256": raw["sha256"], "projects": ["engine"],
                     "writing_lanes": [{"lane": "fix", "writer": "writer-1"}],
                     "path_scopes": [[SCOPE]], "checks": ["focused-tests"],
                     "reviewer": "reviewer-1", "shared_interface_change": False,
                     "migration": False, "governance_change": False, "budget_expansion": False,
                     "scope_certain": True}}


def inspect(tmp_path, value, *, expect=0, root=None):
    path = tmp_path / "inspection.json"
    path.write_text(json.dumps(value))
    args = [] if root is None else ["--root", str(root)]
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), *args,
                           "inspect-request", "--file", str(path)],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == expect, proc.stdout + proc.stderr
    assert not proc.stderr, proc.stderr
    return json.loads(proc.stdout)


def test_single_declared_scope_is_eligible_without_granting_authority(tmp_path):
    value = proposal()
    result = inspect(tmp_path, value)
    assert result == {"schema": "aegis.request-inspection/v1", "request_id": "engine-partial",
                      "request_sha256": value["request"]["sha256"], "request_schema": "aegis.lifecycle-request/v1",
                      "classification": "declared_eligible", "escalation_reasons": [],
                      "approval": "not_evaluated", "checks_admission": "not_evaluated",
                      "reviewer_independence": "declared_distinct", "reviewer_authenticated": False,
                      "execution_enabled": False}


@pytest.mark.parametrize("field,value,reason", [
    ("projects", ["engine", "other"], "project_count"),
    ("projects", [], "project_count"),
    ("writing_lanes", [], "writing_lane_count"),
    ("writing_lanes", [{"lane": "fix", "writer": "writer-1"},
                       {"lane": "other", "writer": "writer-2"}], "writing_lane_count"),
    ("path_scopes", [], "path_scope_count"),
    ("path_scopes", [[SCOPE], [OTHER_SCOPE]], "path_scope_count"),
    ("path_scopes", [[OTHER_SCOPE]], "path_scope_mismatch"),
    ("checks", [], "checks_missing"),
    ("reviewer", "writer-1", "writer_reviewer_conflict"),
    ("shared_interface_change", True, "shared_interface_change"),
    ("migration", True, "migration"),
    ("governance_change", True, "governance_change"),
    ("budget_expansion", True, "budget_expansion"),
    ("scope_certain", False, "uncertain_scope"),
])
def test_each_escalation_is_not_an_approval(tmp_path, field, value, reason):
    body = proposal()
    body["plan"][field] = value
    result = inspect(tmp_path, body)
    assert result["classification"] == "full_planning_required"
    assert reason in result["escalation_reasons"]
    assert result["approval"] == result["checks_admission"] == "not_evaluated"
    assert result["reviewer_authenticated"] is result["execution_enabled"] is False


def test_all_escalations_are_reported_in_stable_order(tmp_path):
    body = proposal()
    body["plan"].update(shared_interface_change=True, migration=True, governance_change=True,
                        budget_expansion=True, scope_certain=False, checks=[])
    result = inspect(tmp_path, body)
    assert result["escalation_reasons"] == ["checks_missing", "shared_interface_change", "migration",
                                            "governance_change", "budget_expansion", "uncertain_scope"]


@pytest.mark.parametrize("field", ["shared_interface_change", "migration", "governance_change",
                                  "budget_expansion", "scope_certain"])
@pytest.mark.parametrize("invalid", [None, 0, 1, "false", [], {}])
def test_risk_declarations_require_real_booleans(tmp_path, field, invalid):
    body = proposal()
    body["plan"][field] = invalid
    assert inspect(tmp_path, body, expect=2)["error"] == "invalid plan " + field


@pytest.mark.parametrize("location", ["envelope", "plan", "lane", "request"])
def test_unknown_fields_refuse(tmp_path, location):
    body = proposal()
    target = {"envelope": body, "plan": body["plan"], "lane": body["plan"]["writing_lanes"][0]}
    if location == "request":
        value = json.loads(body["request"]["raw"])
        value["unknown"] = True
        body["request"] = raw_request(value)
        body["plan"]["request_sha256"] = body["request"]["sha256"]
    else:
        target[location]["unknown"] = True
    assert inspect(tmp_path, body, expect=2)["error"] == "unexpected fields: unknown"


@pytest.mark.parametrize("field", list(proposal()["plan"]))
def test_missing_declarations_refuse(tmp_path, field):
    body = proposal()
    del body["plan"][field]
    assert inspect(tmp_path, body, expect=2)["error"] == "missing fields: " + field


@pytest.mark.parametrize("field,value,error", [
    ("projects", "engine", "invalid plan projects"),
    ("projects", ["engine", "engine"], "duplicate plan projects"),
    ("writing_lanes", [{"lane": "fix", "writer": "writer-1"}] * 2, "duplicate plan lane"),
    ("writing_lanes", [{"lane": "fix", "writer": "writer-1"},
                       {"lane": "other", "writer": "writer-1"}], "duplicate plan writer"),
    ("path_scopes", [[SCOPE] * 2], "duplicate plan path"),
    ("path_scopes", [[]], "invalid plan path scope"),
    ("checks", ["focused-tests"] * 2, "duplicate plan checks"),
    ("reviewer", {}, "invalid plan reviewer"),
])
def test_malformed_and_conflicting_declarations_refuse(tmp_path, field, value, error):
    body = proposal()
    body["plan"][field] = value
    assert inspect(tmp_path, body, expect=2)["error"] == error


def test_hash_binding_uses_exact_raw_bytes_not_json_equivalence(tmp_path):
    body = proposal()
    body["request"]["raw"] += " "
    assert inspect(tmp_path, body, expect=2)["error"] == "raw request sha256 mismatch"
    body["request"]["sha256"] = hashlib.sha256(body["request"]["raw"].encode()).hexdigest()
    assert inspect(tmp_path, body, expect=2)["error"] == "plan request sha256 mismatch"


def test_historical_v1_raw_request_is_readable_but_has_no_plan(tmp_path):
    result = inspect(tmp_path, raw_request(request()))
    assert result["classification"] == "full_planning_required"
    assert result["escalation_reasons"] == ["plan_missing"]
    assert result["reviewer_independence"] == "not_declared"


def test_unsupported_schemas_refuse_instead_of_granting_eligibility(tmp_path):
    body = proposal()
    body["schema"] = "aegis.small-change-plan/v2"
    assert inspect(tmp_path, body, expect=2)["error"] == "unsupported small-change plan schema"
    body = raw_request(request(schema="aegis.lifecycle-request/v2"))
    assert inspect(tmp_path, body, expect=2)["error"] == "unsupported request schema"


def test_inspection_does_not_create_a_journal_or_read_a_corrupt_one(tmp_path):
    root = tmp_path / "journal"
    inspect(tmp_path, proposal(), root=root)
    assert not root.exists()
    root.mkdir()
    (root / "policy.json").write_bytes(b"broken")
    inspect(tmp_path, proposal(), root=root)
    assert {p.name: p.read_bytes() for p in root.iterdir()} == {"policy.json": b"broken"}


@pytest.mark.skipif(os.name != "posix", reason="lifecycle mutation requires POSIX directory fsync")
def test_inspection_preserves_existing_v1_history_and_refuses_plan_publication(tmp_path):
    ledger = Ledger(tmp_path)
    value = ledger.ready()
    before = ledger.files()
    inspect(tmp_path, proposal(), root=ledger.path)
    assert ledger.files() == before
    assert ledger.status()["requests"][value["id"]]["raw"] == raw_request(value)
    result = ledger.event("publish", request=proposal(), expect=2)
    assert result["error"] == "missing fields: raw, sha256"
    assert ledger.files() == before


@pytest.mark.parametrize("raw", [b'{"raw":0,"raw":1}', b'{', b'\xff'])
def test_malformed_input_is_a_structured_hold(tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "inspect-request", "--file", str(path)],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["error"] == "malformed JSON"
    assert not proc.stderr


def test_missing_input_is_a_structured_hold(tmp_path):
    path = tmp_path / "missing.json"
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "inspect-request", "--file", str(path)],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["execution_enabled"] is False
    with pytest.raises(FileNotFoundError) as missing:
        path.stat()
    assert json.loads(proc.stdout)["error"] == str(missing.value)
    assert not proc.stderr
