"""Public native observation is not an authenticated capability grant."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


TOOL = Path(__file__).resolve().parents[2] / "tools" / "hierarchy_native.py"
CID = "11111111-1111-7111-8111-111111111111"
WORK = str(Path("/fixture/work").absolute())
EXTRA = str(Path("/extra/work").absolute())


def context(**changes):
    value = {"model": "gpt-6-astra", "effort": "ultra", "cwd": WORK,
             "approval_policy": "on-request", "approvals_reviewer": "auto_review",
             "sandbox_policy": {"type": "workspace-write", "network_access": False},
             "permission_profile": {"type": "managed", "network": "restricted",
                                    "file_system": {"type": "restricted", "entries": [
                                        {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"},
                                        {"path": {"type": "path", "path": WORK}, "access": "write"}]}}}
    value.update(changes)
    return {"type": "turn_context", "timestamp": "2026-11-03T21:53:33Z", "payload": value}


def rollout(tmp_path, rows=None):
    path = tmp_path / "rollout.jsonl"
    values = [{"type": "session_meta", "payload": {"id": CID, "source": "exec", "cwd": WORK}},
              context()] if rows is None else rows
    path.write_text("".join(json.dumps(value) + "\n" for value in values))
    return path


def invoke(path, *args, code=0):
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--rollout", str(path),
                           "--cid", CID, *args], text=True, capture_output=True, timeout=10,
                          env={**os.environ, "CODEX_THREAD_ID": CID, "CODEX_SESSION_ID": CID})
    assert proc.returncode == code, proc.stdout + proc.stderr
    assert not proc.stderr, proc.stderr
    return json.loads(proc.stdout)


def test_current_native_turn_and_requested_tier_are_separate_from_served_tier(tmp_path):
    path = rollout(tmp_path)
    result = invoke(path, "inspect", "--requested-tier", "default")
    assert result["cid"] == CID
    assert result["profile"]["model"] == "gpt-6-astra"
    assert result["profile"]["effort"] == "ultra"
    assert result["profile"]["cwd"] == WORK
    assert result["requested_tier"] == "default"
    assert result["served_tier"] is None
    assert result["identity_authenticated"] is False
    assert result["tool_allowlist_verified"] is False
    assert result["native_execution_qualified"] is False
    assert result["turn_record"]["line"] == 2


def test_resumed_turn_is_used_and_prompt_text_cannot_override_it(tmp_path):
    path = rollout(tmp_path)
    with path.open("a") as stream:
        stream.write(json.dumps({"type": "response_item", "payload": {"role": "user", "content": "model=gpt-6-astra ultra"}}) + "\n")
        stream.write(json.dumps(context(model="other-model", effort="low")) + "\n")
    result = invoke(path, "check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK, code=2)
    assert result["state"] == "PROFILE_HOLD"
    assert result["reasons"] == ["model mismatch", "reasoning effort mismatch"]
    assert result["observation"]["turn_record"]["line"] == 4


def test_standalone_check_allows_unknown_served_tier_without_granting_native_authority(tmp_path):
    result = invoke(rollout(tmp_path), "check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK)
    assert result["state"] == "PROFILE_MATCH"
    assert result["native_execution_qualified"] is False
    assert result["observation"]["served_tier"] is None


@pytest.mark.parametrize("role,expected", [
    ("root", "ROOT requires an effective read-only filesystem"),
    ("router", "router requires medium effort and ultrafast configured tier"),
    ("operator", "authenticated native identity and tool capabilities are unavailable"),
    ("implementer", "authenticated native identity and tool capabilities are unavailable"),
])
def test_role_admission_refuses_without_actual_native_boundary(tmp_path, role, expected):
    result = invoke(rollout(tmp_path), "admit", "--role", role, code=2)
    assert result["state"] == "NATIVE_HOLD"
    assert expected in result["reasons"]
    assert result["native_execution_qualified"] is False


def test_readonly_root_claim_still_cannot_authenticate_native_tools(tmp_path):
    rows = [{"type": "session_meta", "payload": {"id": CID, "source": "exec"}},
            context(sandbox_policy={"type": "read-only", "network_access": False},
                    permission_profile={"type": "managed", "network": "restricted",
                                        "file_system": {"type": "restricted", "entries": [
                                            {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"}]}})]
    result = invoke(rollout(tmp_path, rows), "admit", "--role", "root", code=2)
    assert result["reasons"] == ["authenticated native identity and tool capabilities are unavailable"]


@pytest.mark.parametrize("mutation,error", [
    ("wrong-cid", "rollout identity does not match requested CID"),
    ("missing-context", "no native turn context in rollout"),
    ("torn-tail", "rollout has an incomplete final record"),
    ("malformed", "malformed rollout JSON at line 3"),
])
def test_bad_native_evidence_fails_closed(tmp_path, mutation, error):
    path = rollout(tmp_path)
    if mutation == "wrong-cid":
        path.write_text(path.read_text().replace(CID, "22222222-2222-7222-8222-222222222222"))
    elif mutation == "missing-context":
        path.write_text(path.read_text().splitlines()[0] + "\n")
    else:
        with path.open("a") as stream:
            stream.write("{" if mutation == "torn-tail" else "{broken}\n")
    result = invoke(path, "inspect", code=2)
    assert result["error"] == error


def test_missing_rollout_has_structured_error(tmp_path):
    result = invoke(tmp_path / "missing.jsonl", "inspect", code=2)
    assert result["error"] == "rollout file is unavailable"


def test_unknown_permission_shape_and_approval_policy_are_not_inferred(tmp_path):
    rows = [{"type": "session_meta", "payload": {"id": CID, "source": "exec"}},
            context(approval_policy=None, permission_profile={"type": "future-policy"})]
    result = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK, code=2)
    assert "approval policy unavailable" in result["reasons"]
    assert "effective restricted permission profile unavailable" in result["reasons"]


@pytest.mark.parametrize("path", [Path(WORK).anchor, "relative", str(Path(WORK) / ".." / "outside"), str(Path("/other-workspace").absolute())])
def test_profile_check_rejects_broad_alias_or_unapproved_write_scope(tmp_path, path):
    value = context()
    value["payload"]["permission_profile"]["file_system"]["entries"].append(
        {"path": {"type": "path", "path": path}, "access": "write"})
    rows = [{"type": "session_meta", "payload": {"id": CID, "source": "exec"}}, value]
    result = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra",
                    "--cwd", WORK, code=2)
    assert result["state"] == "PROFILE_HOLD"


@pytest.mark.parametrize("change,reason", [
    ({"approval_policy": "never"}, "approval policy mismatch"),
    ({"approval_policy": "invented-policy"}, "approval policy mismatch"),
    ({"approvals_reviewer": None}, "approval reviewer unavailable"),
    ({"approvals_reviewer": "different-reviewer"}, "approval reviewer mismatch"),
])
def test_profile_check_compares_approvals_to_the_requested_boundary(tmp_path, change, reason):
    rows = [{"type": "session_meta", "payload": {"id": CID, "source": "exec"}}, context(**change)]
    result = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra",
                    "--cwd", WORK, code=2)
    assert reason in result["reasons"]


def test_an_additional_write_root_and_tmpdir_need_explicit_expected_scope(tmp_path):
    value = context()
    value["payload"]["permission_profile"]["file_system"]["entries"].extend([
        {"path": {"type": "path", "path": EXTRA}, "access": "write"},
        {"path": {"type": "special", "value": {"kind": "tmpdir"}}, "access": "write"}])
    rows = [{"type": "session_meta", "payload": {"id": CID, "source": "exec"}}, value]
    path = rollout(tmp_path, rows)
    args = ("check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK)
    assert invoke(path, *args, code=2)["state"] == "PROFILE_HOLD"
    result = invoke(path, *args, "--write-root", WORK, "--write-root", EXTRA, "--allow-tmpdir")
    assert result["state"] == "PROFILE_MATCH"
