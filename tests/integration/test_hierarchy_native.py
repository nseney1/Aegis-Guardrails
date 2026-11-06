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


def run_tool(path, *args):
    # The reader runs no tool, so its PATH is an empty fake-bin dir and HOME a disposable folder: a stray
    # lookup of codex or ~/.codex would find nothing real.
    base = Path(path).parent
    (base / "fake-bin").mkdir(exist_ok=True)
    (base / "home").mkdir(exist_ok=True)
    env = {"PATH": str(base / "fake-bin"), "HOME": str(base / "home"), "CODEX_THREAD_ID": CID,
           "CODEX_SESSION_ID": CID, "LANG": os.environ.get("LANG", "C.UTF-8")}
    return subprocess.run([sys.executable, "-I", "-B", str(TOOL), "--rollout", str(path),
                           "--cid", CID, *args], text=True, capture_output=True, timeout=5, env=env)


def invoke(path, *args, code=0):
    proc = run_tool(path, *args)
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


@pytest.mark.parametrize("new_context", [None, "old-turn"])
def test_new_turn_cannot_reuse_previous_turn_profile(tmp_path, new_context):
    path = rollout(tmp_path)
    with path.open("a") as stream:
        stream.write(json.dumps({"type": "event_msg", "payload": {"type": "task_started",
            "turn_id": "new-turn"}}) + "\n")
        if new_context:
            value = context()
            value["payload"]["turn_id"] = new_context
            stream.write(json.dumps(value) + "\n")
    result = invoke(path, "check", "--model", "gpt-6-astra", "--effort", "ultra",
                    "--cwd", WORK, code=2)
    assert result["error"] == "latest started turn has no matching native context"


def test_matching_new_turn_context_replaces_previous_profile(tmp_path):
    path = rollout(tmp_path)
    value = context(effort="medium", turn_id="new-turn")
    with path.open("a") as stream:
        stream.write(json.dumps({"type": "event_msg", "payload": {"type": "task_started",
            "turn_id": "new-turn"}}) + "\n")
        stream.write(json.dumps(value) + "\n")
    result = invoke(path, "check", "--model", "gpt-6-astra", "--effort", "ultra",
                    "--cwd", WORK, code=2)
    assert result["state"] == "PROFILE_HOLD"
    assert result["reasons"] == ["reasoning effort mismatch"]
    assert result["observation"]["turn_record"]["line"] == 4


# Real rollout shapes (Codex 0.165/0.166, per evidence/30-item7-understand.json): the served tier is only in
# event_msg/thread_settings_applied, and a default workspace-write profile carries slash_tmp and tmpdir writes,
# read carve-outs for <ws>/.git and the like, and entries with missing_path_behavior.
REGISTRY = Path(__file__).resolve().parents[2] / "tools" / "hierarchy_templates" / "role-registry.json"


def started(turn):
    return {"type": "event_msg", "payload": {"type": "task_started", "turn_id": turn, "root_turn_id": turn}}


def completed(turn):
    return {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": turn}}


def settings(tier, turn=None, **changes):
    value = {"model": "gpt-6-astra", "service_tier": tier, "approval_policy": "never",
             "approvals_reviewer": "user", **changes}
    payload = {"type": "thread_settings_applied", "thread_settings": value}
    if turn is not None:
        payload["turn_id"] = turn
    return {"type": "event_msg", "timestamp": "2026-11-03T21:53:30Z", "payload": payload}


def real_profile(*extra):
    return {"type": "managed", "network": "restricted", "file_system": {"type": "restricted", "entries": [
        {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"},
        {"path": {"type": "path", "path": WORK}, "access": "write"},
        {"path": {"type": "special", "value": {"kind": "slash_tmp"}}, "access": "write"},
        {"path": {"type": "special", "value": {"kind": "tmpdir"}}, "access": "write"},
        {"path": {"type": "path", "path": WORK + "/.git"}, "access": "read", "missing_path_behavior": "skip"},
        {"path": {"type": "path", "path": WORK + "/.codex"}, "access": "read", "missing_path_behavior": "skip"},
        *extra]}}


def turn(turn_id, **changes):
    return context(turn_id=turn_id, **changes)


META = {"type": "session_meta", "payload": {"id": CID, "source": "exec", "cwd": WORK, "cli_version": "0.166.0"}}


def test_served_tier_comes_from_thread_settings_applied_for_the_current_turn(tmp_path):
    rows = [META, settings("flex"), started("t1"), turn("t1")]
    result = invoke(rollout(tmp_path, rows), "inspect", "--requested-tier", "flex")
    assert result["served_tier"] == "flex"
    assert result["served_tier_source"] == "thread_settings_applied"
    assert result["settings_record"]["line"] == 2
    assert result["applied_settings"]["approval_policy"] == "never"
    assert result["profile"]["model"] == "gpt-6-astra"


def test_settings_applied_inside_the_current_turn_are_read(tmp_path):
    rows = [META, started("t1"), settings("ultrafast"), turn("t1")]
    assert invoke(rollout(tmp_path, rows), "inspect")["served_tier"] == "ultrafast"


@pytest.mark.parametrize("rows", [
    [META, settings("flex"), started("t1"), turn("t1"), completed("t1"), started("t2"), turn("t2")],
    [META, started("t1"), settings("flex"), turn("t1"), completed("t1"), started("t2"), turn("t2")],
    [META, settings("flex", turn="t1"), started("t2"), turn("t2")],
    [META, started("t2"), settings("flex", turn="t1"), turn("t2")],
])
def test_an_earlier_turns_settings_never_report_the_current_served_tier(tmp_path, rows):
    result = invoke(rollout(tmp_path, rows), "inspect")
    assert result["served_tier"] is None
    assert result["served_tier_source"] is None
    assert "settings_record" not in result


def test_settings_applied_between_turns_belong_to_the_next_turn(tmp_path):
    rows = [META, settings("default"), started("t1"), turn("t1"), completed("t1"),
            settings("ultrafast"), started("t2"), turn("t2")]
    result = invoke(rollout(tmp_path, rows), "inspect")
    assert result["served_tier"] == "ultrafast"
    assert result["settings_record"]["line"] == 6


def test_malformed_thread_settings_fail_closed(tmp_path):
    bad = {"type": "event_msg", "payload": {"type": "thread_settings_applied", "thread_settings": "fast"}}
    result = invoke(rollout(tmp_path, [META, bad, started("t1"), turn("t1")]), "inspect", code=2)
    assert result["error"] == "thread settings at line 2 must be an object"


def test_inspect_reports_the_observed_real_profile_structurally(tmp_path):
    rows = [META, started("t1"), turn("t1", permission_profile=real_profile())]
    observed = invoke(rollout(tmp_path, rows), "inspect")["observed_permissions"]
    assert observed["supported"] is True
    assert observed["network"] == "restricted"
    assert observed["entries"] == [
        {"kind": "special", "path_or_special": "root", "access": "read", "missing_path_behavior": None},
        {"kind": "path", "path_or_special": WORK, "access": "write", "missing_path_behavior": None},
        {"kind": "special", "path_or_special": "slash_tmp", "access": "write", "missing_path_behavior": None},
        {"kind": "special", "path_or_special": "tmpdir", "access": "write", "missing_path_behavior": None},
        {"kind": "path", "path_or_special": WORK + "/.git", "access": "read", "missing_path_behavior": "skip"},
        {"kind": "path", "path_or_special": WORK + "/.codex", "access": "read", "missing_path_behavior": "skip"}]


def test_inspect_reports_an_unsupported_profile_without_guessing(tmp_path):
    rows = [META, context(permission_profile={"type": "future-policy"})]
    observed = invoke(rollout(tmp_path, rows), "inspect")["observed_permissions"]
    assert observed == {"supported": False, "network": None, "entries": [],
                        "reasons": ["permission profile is not a managed restricted profile"]}


def test_check_refuses_unrequested_special_writes_and_names_each(tmp_path):
    rows = [META, started("t1"), turn("t1", permission_profile=real_profile())]
    path = rollout(tmp_path, rows)
    args = ("check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK)
    result = invoke(path, *args, code=2)
    assert result["reasons"] == ["special write access was not requested: slash_tmp",
                                 "special write access was not requested: tmpdir"]
    result = invoke(path, *args, "--allow-special-write", "tmpdir", code=2)
    assert result["reasons"] == ["special write access was not requested: slash_tmp"]
    result = invoke(path, *args, "--allow-special-write", "tmpdir", "--allow-special-write", "slash_tmp")
    assert result["state"] == "PROFILE_MATCH"
    result = invoke(path, *args, "--allow-tmpdir", "--allow-special-write", "slash_tmp")
    assert result["state"] == "PROFILE_MATCH"


def test_check_still_refuses_an_unexpected_path_write_in_a_real_profile(tmp_path):
    extra = {"path": {"type": "path", "path": WORK + "/.git"}, "access": "write", "missing_path_behavior": "skip"}
    rows = [META, started("t1"), turn("t1", permission_profile=real_profile(extra))]
    result = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra",
                    "--cwd", "/other-workspace", "--allow-special-write", "tmpdir",
                    "--allow-special-write", "slash_tmp", code=2)
    assert "write root is outside requested scope: " + WORK in result["reasons"]
    assert "write root is outside requested scope: " + WORK + "/.git" in result["reasons"]


def test_root_write_can_never_be_allowed(tmp_path):
    extra = {"path": {"type": "special", "value": {"kind": "root"}}, "access": "write"}
    rows = [META, started("t1"), turn("t1", permission_profile=real_profile(extra))]
    path = rollout(tmp_path, rows)
    args = ("check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK)
    result = invoke(path, *args, "--allow-special-write", "tmpdir", "--allow-special-write", "slash_tmp", code=2)
    assert result["reasons"] == ["special write access was not requested: root"]
    result = invoke(path, *args, "--allow-special-write", "root", code=2)
    assert result["error"] == "root write access cannot be allowed"


@pytest.mark.parametrize("entry,reason", [
    ({"path": {"type": "path", "path": WORK}, "access": "execute"}, "unsupported access at entry 7"),
    ({"path": {"type": "path", "path": WORK}, "access": "read", "missing_path_behavior": 3},
     "unsupported missing_path_behavior at entry 7"),
    ({"path": {"type": "special", "value": {}}, "access": "read"}, "unsupported special path at entry 7"),
    ({"path": "loose", "access": "read"}, "unsupported path at entry 7"),
])
def test_malformed_profile_entries_are_reported_and_held(tmp_path, entry, reason):
    rows = [META, started("t1"), turn("t1", permission_profile=real_profile(entry))]
    path = rollout(tmp_path, rows)
    observed = invoke(path, "inspect")["observed_permissions"]
    assert observed["supported"] is False and observed["reasons"] == [reason]
    result = invoke(path, "check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK,
                    "--allow-tmpdir", "--allow-special-write", "slash_tmp", code=2)
    assert result["reasons"] == ["effective restricted permission profile unavailable"]


@pytest.mark.parametrize("reviewer,code,reasons", [
    (None, 0, []),
    ("user", 2, ["approval reviewer mismatch"]),
])
def test_provisioned_never_policy_with_no_reviewer_can_be_expected(tmp_path, reviewer, code, reasons):
    rows = [META, started("t1"), turn("t1", approval_policy="never", approvals_reviewer=reviewer)]
    result = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra",
                    "--cwd", WORK, "--approval-policy", "never", "--approvals-reviewer", "none", code=code)
    assert result["reasons"] == reasons


def codex_roles():
    roles = json.loads(REGISTRY.read_text())["roles"]
    return sorted(name for name, entry in roles.items() if entry["endpoint"] is not None)


def test_registry_lists_the_codex_roles_this_reader_must_know():
    assert codex_roles() == ["decider", "front-door", "implementer", "integrator", "orchestrator",
                             "reviewer", "root", "router"]


@pytest.mark.parametrize("role", codex_roles())
def test_every_registry_codex_role_is_assessed_and_held(tmp_path, role):
    rows = [META, started("t1"), turn("t1", effort="medium")]
    result = invoke(rollout(tmp_path, rows), "admit", "--role", role, "--requested-tier", "ultrafast", code=2)
    assert result["state"] == "NATIVE_HOLD"
    assert result["role"] == role
    assert result["reasons"][-1] == "authenticated native identity and tool capabilities are unavailable"


def test_a_role_without_a_codex_endpoint_is_refused(tmp_path):
    proc = run_tool(rollout(tmp_path), "admit", "--role", "owner")
    assert proc.returncode == 2
    assert "invalid choice: 'owner'" in proc.stderr


def test_root_with_real_workspace_profile_is_not_read_only(tmp_path):
    rows = [META, started("t1"), turn("t1", permission_profile=real_profile())]
    result = invoke(rollout(tmp_path, rows), "admit", "--role", "root", code=2)
    assert "ROOT requires an effective read-only filesystem" in result["reasons"]


def exec_end(turn_id, call, command, code, output, **extra):
    payload = {"type": "exec_command_end", "call_id": call, "command": command, "cwd": WORK,
               "exit_code": code, "aggregated_output": output, "stdout": output, "stderr": "", **extra}
    if turn_id is not None:
        payload["turn_id"] = turn_id
    return {"type": "event_msg", "timestamp": "2026-11-03T21:54:00Z", "payload": payload}


def patch_end(turn_id, call, success, changes, stderr=""):
    payload = {"type": "patch_apply_end", "call_id": call, "success": success, "changes": changes,
               "stdout": "", "stderr": stderr}
    if turn_id is not None:
        payload["turn_id"] = turn_id
    return {"type": "event_msg", "payload": payload}


def item(command, code, output, status="completed"):
    return {"type": "item.completed", "item": {"id": "item_1", "type": "command_execution", "command": command,
                                              "aggregated_output": output, "exit_code": code, "status": status}}


ATTEMPT = ["/bin/bash", "-lc", "python3 .aegis-probe/attempt.py n0nce"]
EROFS = "OSError(30, 'Read-only file system')"


def exec_rows():
    return [META, started("t1"), turn("t1"),
            exec_end("t1", "c1", ATTEMPT, 0, "ok"),
            completed("t1"), started("t2"), turn("t2"),
            exec_end(None, "c2", ATTEMPT, 1, EROFS),
            patch_end("t2", "p1", False, {WORK + "/../outside/n0nce": {"add": {"content": "n0nce"}}},
                      "patch rejected: writing outside of the project; rejected by user approval settings"),
            item("python3 .aegis-probe/attempt.py n0nce", None, "", status="in_progress"),
            {"type": "response_item", "payload": {"role": "assistant", "content": "exit_code 1 EROFS"}}]


def test_events_lists_the_current_turns_executions_and_patches(tmp_path):
    result = invoke(rollout(tmp_path, exec_rows()), "events")
    assert result["schema"] == "aegis.native-exec-events/v1"
    assert result["turn_scope"] == "current" and result["current_turn_id"] == "t2"
    executions = result["command_executions"]
    assert [(e["turn_id"], e["call_id"], e["exit_code"], e["line"]) for e in executions] == [
        ("t2", "c2", 1, 8), ("t2", "item_1", None, 10)]
    assert executions[0]["command"] == ATTEMPT
    assert executions[0]["command_text"] == "/bin/bash -lc 'python3 .aegis-probe/attempt.py n0nce'"
    assert executions[0]["aggregated_output"] == EROFS
    assert executions[0]["source"] == "exec_command_end"
    assert executions[1]["status"] == "in_progress" and executions[1]["source"] == "item.completed"
    assert len(executions[0]["sha256"]) == 64
    patches = result["patch_applies"]
    assert len(patches) == 1
    assert patches[0]["turn_id"] == "t2" and patches[0]["success"] is False
    assert patches[0]["paths"] == [WORK + "/../outside/n0nce"]
    assert patches[0]["stderr"].startswith("patch rejected")
    assert result["native_execution_qualified"] is False


def test_events_read_file_change_items_as_patch_attempts(tmp_path):
    change = {"type": "item.completed", "item": {"id": "item_2", "type": "file_change", "status": "failed",
                                                 "changes": [{"path": WORK + "/n0nce", "kind": "add"}]}}
    patches = invoke(rollout(tmp_path, [META, started("t1"), turn("t1"), change]), "events")["patch_applies"]
    assert [(p["turn_id"], p["call_id"], p["success"], p["paths"], p["source"]) for p in patches] == [
        ("t1", "item_2", False, [WORK + "/n0nce"], "item.completed")]


def test_events_for_all_turns_keeps_turn_attribution(tmp_path):
    result = invoke(rollout(tmp_path, exec_rows()), "events", "--turn", "all")
    assert result["turn_scope"] == "all"
    assert [(e["turn_id"], e["exit_code"]) for e in result["command_executions"]] == [
        ("t1", 0), ("t2", 1), ("t2", None)]


def test_events_after_a_new_turn_start_do_not_reuse_old_executions(tmp_path):
    rows = exec_rows() + [started("t3")]
    result = invoke(rollout(tmp_path, rows), "events")
    assert result["current_turn_id"] == "t3"
    assert result["command_executions"] == [] and result["patch_applies"] == []


def test_an_event_naming_another_turn_is_attributed_to_that_turn(tmp_path):
    rows = [META, started("t1"), turn("t1"), completed("t1"), started("t2"),
            exec_end("t1", "late", ATTEMPT, 0, "ok")]
    result = invoke(rollout(tmp_path, rows), "events")
    assert result["command_executions"] == []
    every = invoke(rollout(tmp_path, rows), "events", "--turn", "all")["command_executions"]
    assert [(e["turn_id"], e["call_id"]) for e in every] == [("t1", "late")]


@pytest.mark.parametrize("record,error", [
    (exec_end("t1", "c1", ATTEMPT, "1", EROFS), "malformed command execution at line 4"),
    (exec_end("t1", "c1", [1, 2], 1, EROFS), "malformed command execution at line 4"),
    (exec_end("t1", "c1", ATTEMPT, 1, None), "malformed command execution at line 4"),
    (patch_end("t1", "p1", "no", {}), "malformed patch apply at line 4"),
    (patch_end("t1", "p1", True, ["x"]), "malformed patch apply at line 4"),
])
def test_malformed_exec_events_fail_closed(tmp_path, record, error):
    rows = [META, started("t1"), turn("t1"), record]
    assert invoke(rollout(tmp_path, rows), "events", code=2)["error"] == error


def test_events_needs_the_matching_session_identity(tmp_path):
    rows = [{"type": "session_meta", "payload": {"id": "other"}}, started("t1")]
    assert invoke(rollout(tmp_path, rows), "events", code=2)["error"] == "rollout identity does not match requested CID"


@pytest.mark.parametrize("served,requested,code,reasons", [
    ("default", "ultrafast", 2, ["served tier mismatch: requested ultrafast, served default"]),
    ("flex", "default", 2, ["served tier mismatch: requested default, served flex"]),
    ("ultrafast", "ultrafast", 0, []),
])
def test_check_holds_when_the_known_served_tier_differs_from_the_requested_tier(tmp_path, served, requested, code,
                                                                               reasons):
    rows = [META, started("t1"), settings(served), turn("t1")]
    result = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK,
                    "--requested-tier", requested, code=code)
    assert result["reasons"] == reasons
    assert result["observation"]["served_tier"] == served


def test_an_unrequested_model_or_effort_is_unchecked_and_holds():
    sys.path.insert(0, str(TOOL.parent))
    import hierarchy_native
    observation = {"profile": {"model": "gpt-6-astra", "effort": "ultra", "cwd": WORK, "approval_policy": "on-request",
                               "approvals_reviewer": "auto_review",
                               "permission_profile": context()["payload"]["permission_profile"]},
                   "requested_tier": "default", "served_tier": None}
    checked = hierarchy_native.check_profile(observation, None, None, WORK)
    assert checked["state"] == "PROFILE_HOLD"
    assert checked["checks"] == {"model": "unchecked", "effort": "unchecked", "cwd": "checked"}
    assert checked["reasons"] == ["model unchecked: no value was requested", "effort unchecked: no value was requested"]
    assert hierarchy_native.check_profile(observation, "gpt-6-astra", "ultra", WORK)["state"] == "PROFILE_MATCH"


def completed_item(turn_id, item):
    payload = {"type": "item_completed", "thread_id": CID, "item": item}
    if turn_id is not None:
        payload["turn_id"] = turn_id
    return {"type": "event_msg", "payload": payload}


def test_events_read_event_msg_item_completed_command_and_file_change_items(tmp_path):
    shell = {"type": "CommandExecution", "id": "item_0", "command": ATTEMPT, "status": "failed",
             "aggregated_output": EROFS, "exit_code": 1}
    change = {"type": "FileChange", "id": "patch_0", "status": "failed", "stderr": "patch rejected: read-only",
              "changes": [{"path": WORK + "/n0nce", "kind": "add"}]}
    message = {"type": "AgentMessage", "id": "msg", "content": [{"type": "Text", "text": "exit_code 1 EROFS"}]}
    rows = [META, started("t1"), turn("t1"), completed_item("t1", shell), completed_item(None, change),
            completed_item("t1", message), completed("t1"), started("t2"), turn("t2")]
    every = invoke(rollout(tmp_path, rows), "events", "--turn", "all")
    assert [(e["turn_id"], e["call_id"], e["exit_code"], e["source"], e["line"]) for e in every["command_executions"]] == [
        ("t1", "item_0", 1, "item_completed", 4)]
    assert every["command_executions"][0]["command_text"] == "/bin/bash -lc 'python3 .aegis-probe/attempt.py n0nce'"
    assert [(p["turn_id"], p["call_id"], p["success"], p["paths"], p["stderr"], p["source"])
            for p in every["patch_applies"]] == [
        ("t1", "patch_0", False, [WORK + "/n0nce"], "patch rejected: read-only", "item_completed")]
    current = invoke(rollout(tmp_path, rows), "events")
    assert current["command_executions"] == [] and current["patch_applies"] == []


@pytest.mark.parametrize("item,error", [
    ({"type": "CommandExecution", "id": "i", "command": [1], "exit_code": 1}, "malformed command execution at line 4"),
    ({"type": "FileChange", "id": "p", "status": "failed", "changes": "x"}, "malformed patch apply at line 4"),
])
def test_malformed_item_completed_records_fail_closed(tmp_path, item, error):
    rows = [META, started("t1"), turn("t1"), completed_item("t1", item)]
    assert invoke(rollout(tmp_path, rows), "events", code=2)["error"] == error


# Second-round review fixes: stopped turns, once-per-thread settings, item turn ids and tool-call patches.

def aborted(turn):
    return {"type": "event_msg", "payload": {"type": "turn_aborted", "turn_id": turn, "reason": "interrupted"}}


@pytest.mark.parametrize("end", [[], ["aborted"]])
def test_a_resumed_turns_early_settings_are_not_lost_to_the_stopped_turn(tmp_path, end):
    # t1 is stopped (no task_complete; maybe turn_aborted); the resumed process writes settings, then starts t2.
    rows = [META, started("t1"), settings("ultrafast"), turn("t1"), *[aborted("t1") for _ in end],
            settings("flex"), started("t2"), turn("t2")]
    result = invoke(rollout(tmp_path, rows), "inspect", "--requested-tier", "ultrafast")
    assert (result["served_tier"], result["served_tier_source"]) == ("flex", "thread_settings_applied")
    assert result["settings_record"]["line"] == (6 if end else 5)


def test_settings_after_turn_aborted_belong_to_the_next_turn(tmp_path):
    rows = [META, started("t1"), turn("t1"), aborted("t1"), settings("flex"), started("t2"), turn("t2")]
    assert invoke(rollout(tmp_path, rows), "inspect")["served_tier"] == "flex"


def test_an_unknown_served_tier_holds_when_a_tier_was_requested(tmp_path):
    # Settings written once per thread leave every later turn without a served tier.
    rows = [META, settings("ultrafast"), started("t1"), turn("t1"), completed("t1"), started("t2"), turn("t2")]
    result = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK,
                    "--requested-tier", "ultrafast", code=2)
    assert result["observation"]["served_tier"] is None
    assert result["reasons"] == ["served tier unavailable: requested ultrafast"]
    default = invoke(rollout(tmp_path, rows), "check", "--model", "gpt-6-astra", "--effort", "ultra", "--cwd", WORK)
    assert default["reasons"] == []


def test_an_item_completed_record_keeps_its_own_turn_id(tmp_path):
    shell = {"type": "CommandExecution", "id": "late", "command": ATTEMPT, "status": "failed",
             "aggregated_output": EROFS, "exit_code": 1}
    rows = [META, started("t1"), turn("t1"), completed("t1"), started("t2"), turn("t2"), completed_item("t1", shell)]
    every = invoke(rollout(tmp_path, rows), "events", "--turn", "all")["command_executions"]
    assert [(e["turn_id"], e["call_id"]) for e in every] == [("t1", "late")]
    assert invoke(rollout(tmp_path, rows), "events")["command_executions"] == []


def tool_call(call, kind="custom_tool_call", **extra):
    patch = "*** Begin Patch\n*** Add File: %s/n0nce\n+line\n*** End Patch\n" % WORK
    payload = {"type": kind, "name": "apply_patch", "call_id": call, **extra}
    if kind == "custom_tool_call":
        payload["input"] = patch
    else:
        payload["arguments"] = json.dumps({"input": patch})
    return {"type": "response_item", "payload": payload}


def tool_output(call, output, kind="custom_tool_call_output"):
    return {"type": "response_item", "payload": {"type": kind, "call_id": call, "output": output}}


def test_events_read_apply_patch_tool_call_pairs_and_mark_their_shape_unconfirmed(tmp_path):
    rejected = "patch rejected: writing outside of the project; rejected by user approval settings"
    rows = [META, started("t1"), turn("t1"),
            tool_call("c1"), tool_output("c1", rejected),
            tool_call("c2", "function_call"), tool_output("c2", {"content": "Success. Updated the following files"},
                                                          "function_call_output"),
            tool_call("c3", status="declined"), tool_output("c3", "declined"),
            tool_call("c4", "custom_tool_call"),
            tool_output("c5", "an output with no call")]
    patches = invoke(rollout(tmp_path, rows), "events")["patch_applies"]
    found = [(p["call_id"], p["success"], p["paths"], p["source"], p["declined"], p["shape"]) for p in patches]
    shape = "unconfirmed against a real host"
    assert found == [("c1", False, [WORK + "/n0nce"], "custom_tool_call", False, shape),
                     ("c2", True, [WORK + "/n0nce"], "function_call", False, shape),
                     ("c3", False, [WORK + "/n0nce"], "custom_tool_call", True, shape),
                     ("c4", None, [WORK + "/n0nce"], "custom_tool_call", False, shape)]
    assert patches[0]["stderr"] == rejected and patches[0]["line"] == 5 and patches[0]["call_line"] == 4


def test_events_read_a_file_change_item_keyed_by_path_and_a_declined_status(tmp_path):
    change = {"type": "FileChange", "id": "patch_0", "status": "declined",
              "changes": {WORK + "/n0nce": {"type": "add", "content": "x"}}}
    rows = [META, started("t1"), turn("t1"), completed_item("t1", change)]
    patches = invoke(rollout(tmp_path, rows), "events")["patch_applies"]
    assert [(p["paths"], p["success"], p["declined"]) for p in patches] == [([WORK + "/n0nce"], None, True)]


# Item 9: Codex code mode, in the shapes native probe run 1 recorded (codex-cli 0.166.0). The model sends a
# custom_tool_call named exec whose input is a JavaScript cell; its output is a list of input_text parts.

CODE_MODE_SHAPE = "confirmed by native probe run 1 (codex-cli 0.166.0)"
REJECTED = "patch rejected: writing outside of the project; rejected by user approval settings"
NOT_A_FUNCTION = "TypeError: tools.exec_command is not a function"


def attempt_command(target):
    return "/usr/bin/python3 -I /probe/helper/native-probe-attempt.py %s/aegis-probe-%s %s" % (WORK, target, target)


def helper_output(target, errno=None):
    value = {"ok": errno is None, "path": "%s/aegis-probe-%s" % (WORK, target), "nonce": target}
    if errno is not None:
        value.update(errno=errno, error="OSError: [Errno %d] Read-only file system" % errno)
    return json.dumps(value) + "\n"


def cell(call, script):
    return {"type": "response_item", "payload": {"type": "custom_tool_call", "status": "completed", "call_id": call,
                                                 "name": "exec", "input": script}}


def printed(call, *parts, failed=None):
    """The cell's output: its header, one part per text() call and, after an uncaught throw, the Script error."""
    texts = [("Script failed" if failed is not None else "Script completed") + "\nWall time 0.0 seconds\nOutput:\n",
             *parts] + ([] if failed is None else ["Script error:\n" + failed])
    return {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": call,
                                                 "output": [{"type": "input_text", "text": text} for text in texts]}}


def chunk(code, output, **extra):
    value = {"chunk_id": "343926", "wall_time_seconds": 0.0, "exit_code": code, "original_token_count": 36,
             "output": output, **extra}
    return json.dumps({key: item for key, item in value.items() if item is not None}, separators=(",", ":"))


def shell_call(command, options=""):
    return "text(await tools.exec_command({cmd:%s%s}));\n" % (json.dumps(command), options)


def patch_text(target):
    return "*** Begin Patch\n*** Add File: %s/aegis-probe-%s\n+aegis-native-probe %s\n*** End Patch" % (
        WORK, target, target)


def patch_call(target):
    return "text(await tools.apply_patch(%s));\n" % json.dumps(patch_text(target))


def caught(statement, catch="text(String(error));"):
    return "try {\n  %s} catch (error) {\n  %s\n}\n" % (statement, catch)


def code_rows(*records):
    return [META, started("t1"), turn("t1"), *records]


def shells(result):
    return [(e["call_id"], e["command"], e["exit_code"], e["status"], e["source"])
            for e in result["command_executions"]]


def test_code_mode_lists_each_exec_command_call_with_its_own_exit_code(tmp_path):
    rows = code_rows(cell("c0", "text(ALL_TOOLS.filter(x => /exec_command/.test(x.name)));\n"), printed("c0", "[]"),
                     cell("c1", shell_call(attempt_command("in")) + shell_call(attempt_command("out"))),
                     printed("c1", chunk(0, helper_output("in")), chunk(1, helper_output("out", 30))))
    result = invoke(rollout(tmp_path, rows), "events")
    assert shells(result) == [("c1", attempt_command("in"), 0, "completed", "code_mode"),
                              ("c1", attempt_command("out"), 1, "failed", "code_mode")]
    refused = result["command_executions"][1]
    assert refused["aggregated_output"] == helper_output("out", 30)
    assert refused["command_text"] == attempt_command("out") and refused["shape"] == CODE_MODE_SHAPE
    assert (refused["line"], refused["call_line"], len(refused["sha256"])) == (7, 6, 64)
    assert result["patch_applies"] == [] and result["code_mode_unparsed"] == []


def test_a_typed_item_completed_record_wins_over_the_code_mode_parse(tmp_path):
    typed_shell = {"type": "CommandExecution", "id": "exec-1", "status": "completed", "exit_code": 0,
                   "command": ["/usr/bin/zsh", "-lc", attempt_command("in")], "aggregated_output": helper_output("in")}
    typed_patch = {"type": "FileChange", "id": "exec-2", "status": "completed", "stdout": "Success.", "stderr": "",
                   "changes": {"%s/aegis-probe-in" % WORK: {"type": "add", "content": "aegis-native-probe in\n"}}}
    rows = code_rows(cell("c1", shell_call(attempt_command("in")) + shell_call(attempt_command("out"))),
                     completed_item("t1", typed_shell),
                     printed("c1", chunk(0, helper_output("in")), chunk(1, helper_output("out", 30))),
                     cell("c2", patch_call("in") + patch_call("out")), completed_item("t1", typed_patch),
                     printed("c2", "{}", failed=REJECTED))
    result = invoke(rollout(tmp_path, rows), "events")
    assert shells(result) == [("exec-1", ["/usr/bin/zsh", "-lc", attempt_command("in")], 0, "completed",
                               "item_completed"),
                              ("c1", attempt_command("out"), 1, "failed", "code_mode")]
    assert [(p["call_id"], p["paths"], p["success"], p["source"]) for p in result["patch_applies"]] == [
        ("exec-2", ["%s/aegis-probe-in" % WORK], True, "item_completed"),
        ("c2", ["%s/aegis-probe-out" % WORK], False, "code_mode")]


def test_a_script_error_ends_a_plain_cell_so_its_later_calls_never_ran(tmp_path):
    rows = code_rows(cell("c1", "".join(patch_call(target) for target in ("in", "out", "git", "home"))),
                     printed("c1", "{}", failed=REJECTED))
    patches = invoke(rollout(tmp_path, rows), "events")["patch_applies"]
    assert [(p["paths"], p["success"], p["status"], p["stdout"], p["stderr"], p["declined"]) for p in patches] == [
        (["%s/aegis-probe-in" % WORK], True, "completed", "{}", None, False),
        (["%s/aegis-probe-out" % WORK], False, "failed", None, REJECTED, False)]


def test_a_caught_error_prints_one_part_per_call(tmp_path):
    loop = ('const commands = [\n%s,\n%s\n];\nfor (const cmd of commands) {\n  try {\n    text(await '
            'tools.exec_command({cmd}));\n  } catch (error) {\n    text({cmd, error: String(error)});\n  }\n}\n'
            % (json.dumps(attempt_command("in")), json.dumps(attempt_command("out"))))
    rows = code_rows(cell("c1", caught(patch_call("git")) + caught(patch_call("home"))),
                     printed("c1", REJECTED, REJECTED),
                     cell("c2", loop),
                     printed("c2", *[json.dumps({"cmd": attempt_command(target), "error": NOT_A_FUNCTION},
                                                separators=(",", ":")) for target in ("in", "out")]),
                     cell("c3", caught(shell_call(attempt_command("in")))), printed("c3", NOT_A_FUNCTION))
    result = invoke(rollout(tmp_path, rows), "events")
    assert [(p["paths"], p["success"], p["stderr"]) for p in result["patch_applies"]] == [
        (["%s/aegis-probe-git" % WORK], False, REJECTED), (["%s/aegis-probe-home" % WORK], False, REJECTED)]
    assert shells(result) == [("c2", attempt_command("in"), None, "unavailable", "code_mode"),
                              ("c2", attempt_command("out"), None, "unavailable", "code_mode"),
                              ("c3", attempt_command("in"), None, "unavailable", "code_mode")]
    assert {e["stderr"] for e in result["command_executions"]} == {NOT_A_FUNCTION}


@pytest.mark.parametrize("case", ["fewer-parts", "other-statement", "running-cell", "no-output", "header-disagrees",
                                  "other-cmd-in-catch"])
def test_code_mode_output_that_cannot_be_tied_to_its_calls_leaves_each_call_unpaired(tmp_path, case):
    two = shell_call(attempt_command("in")) + shell_call(attempt_command("out"))
    loop = ('const commands = [%s, %s];\nfor (const cmd of commands) { try { text(await tools.exec_command({cmd})); }'
            ' catch (e) { text({cmd, error: String(e)}); } }\n' % (json.dumps(attempt_command("in")),
                                                                     json.dumps(attempt_command("out"))))
    swapped = [json.dumps({"cmd": attempt_command(target), "error": "x"}) for target in ("out", "in")]
    running = {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c1",
                                                    "output": "Script running with cell ID 4\nWall time 31.0 seconds"
                                                              "\nOutput:\n"}}
    disagrees = printed("c1", chunk(0, "a"), chunk(1, "b"))
    disagrees["payload"]["output"].append({"type": "input_text", "text": "Script error:\nboom"})
    script, output = {
        "fewer-parts": (two, printed("c1", chunk(1, helper_output("out", 30)))),
        "other-statement": (two + "text(ALL_TOOLS.length);\n", printed("c1", chunk(0, "a"), chunk(1, "b"), "3")),
        "running-cell": (two, running),
        "no-output": (two, None),
        "header-disagrees": (two, disagrees),
        "other-cmd-in-catch": (loop, printed("c1", *swapped)),
    }[case]
    rows = code_rows(cell("c1", script), *([] if output is None else [output]))
    result = invoke(rollout(tmp_path, rows), "events")
    assert shells(result) == [("c1", attempt_command(target), None, "unpaired", "code_mode")
                              for target in ("in", "out")]
    assert all(e["aggregated_output"] is None and e["stderr"] is None for e in result["command_executions"])


@pytest.mark.parametrize("argument,reason", [
    ("{cmd: 'echo single'}", "expected a string or number or name"),
    ("{cmd: `echo template`}", "expected a string or number or name"),
    ('{cmd: "echo \\x41"}', "a string literal JSON cannot decode"),
    ('{cmd: "echo " + name}', "expected }"),
    ("{cmd: name}", "cmd is not a string literal"),
])
def test_only_a_strict_double_quoted_literal_is_decoded(tmp_path, argument, reason):
    rows = code_rows(cell("c1", "text(await tools.exec_command(%s));\n" % argument), printed("c1", chunk(0, "")))
    result = invoke(rollout(tmp_path, rows), "events")
    assert result["command_executions"] == []
    assert result["code_mode_unparsed"] == [{"tool": "exec_command", "reason": reason, "turn_id": "t1",
                                             "call_id": "c1", "line": 4}]


def test_an_exec_command_option_is_kept_with_its_call(tmp_path):
    options = ',yield_time_ms:1000,"shell":"/tmp/bash",login:false'
    rows = code_rows(cell("c1", shell_call(attempt_command("out"), options)),
                     printed("c1", chunk(1, helper_output("out", 30))))
    entry = invoke(rollout(tmp_path, rows), "events")["command_executions"][0]
    assert (entry["options"], entry["exit_code"], entry["status"]) == (["login", "shell", "yield_time_ms"], 1, "failed")


def test_a_still_running_command_has_no_exit_code_and_code_mode_keeps_turn_attribution(tmp_path):
    rows = code_rows(cell("c1", shell_call("sleep 600", ",yield_time_ms:1000,max_output_tokens:1000")),
                     printed("c1", chunk(None, "", session_id=81995)), completed("t1"), started("t2"), turn("t2"))
    assert invoke(rollout(tmp_path, rows), "events")["command_executions"] == []
    every = invoke(rollout(tmp_path, rows), "events", "--turn", "all")["command_executions"]
    assert [(e["turn_id"], e["command"], e["exit_code"], e["status"], e["options"]) for e in every] == [
        ("t1", "sleep 600", None, "running", ["max_output_tokens", "yield_time_ms"])]
