"""The host registry declares each host kind's mechanisms once (spec binding rule 5).

These tests hold it to the code that already encodes host facts, refuse what it does not qualify, and read
real-shaped Claude stream-json, auth status and Codex totals. Fakes only: nothing here starts a host.
"""
import json
import os
from pathlib import Path
import sys

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_hosts  # noqa: E402
import hierarchy_launcher  # noqa: E402
import hierarchy_meter  # noqa: E402
import hierarchy_provision  # noqa: E402
import hierarchy_team  # noqa: E402


SESSION = "4f1c2b9e-8d7a-4c3b-9a1e-2f6d5c4b3a21"
# Claude 2.1.316 print mode, values from a real wake log.
REAL_RESULT = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 13, "session_id": SESSION,
               "total_cost_usd": 0.820714,
               "usage": {"input_tokens": 24, "cache_creation_input_tokens": 14857, "cache_read_input_tokens": 494692,
                         "output_tokens": 6217, "output_tokens_details": {"thinking_tokens": 1162},
                         "service_tier": "standard"}}
INIT = {"type": "system", "subtype": "init", "session_id": SESSION, "cwd": "/work/lane",
        "tools": ["Read", "Edit", "mcp__aegis_decision__root_decide"], "model": "claude-opus-5-5",
        "permissionMode": "default", "apiKeySource": "none", "claude_code_version": "2.1.319",
        "mcp_servers": [{"name": "aegis_decision", "status": "connected"}]}
ASSISTANT = {"type": "assistant", "session_id": SESSION, "message": {"role": "assistant", "content": [
    {"type": "thinking", "thinking": "plan"},
    {"type": "text", "text": "Deciding the request now."},
    {"type": "tool_use", "id": "toolu_1", "name": "mcp__aegis_decision__root_decide",
     "input": {"request_id": "r-1", "decision": "approve"}},
    {"type": "tool_use", "id": "toolu_2", "name": "Edit", "input": {"file_path": "a.py"}}]}}
TOOL_RESULT = {"type": "user", "session_id": SESSION, "message": {"role": "user", "content": [
    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "decided"}]}}
LOGGED_OUT_KEYS = {"loggedIn": False, "authMethod": "none", "apiProvider": "firstParty", "analyticsDisabled": False}
IDENTITY = {"email": "owner@example.com", "orgId": "org-1", "orgName": "Owner", "planTier": "max",
            "subscriptionType": "max", "storedClaudeAiLogin": True}


def lines(*events):
    return [event if isinstance(event, str) else json.dumps(event) for event in events]


def refusal(call, *arguments):
    with pytest.raises(ValueError) as caught:
        call(*arguments)
    return str(caught.value)


def status(home, **change):
    found = {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty", "analyticsDisabled": False,
             "projectsDirectory": str(Path(home) / "projects"), "configDirectory": str(home), "loginExpiresAt": None,
             **IDENTITY}
    found.update(change)
    return found


def touch(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")
    return path


def test_host_constants_agree_with_the_code_that_already_names_hosts():
    assert (hierarchy_hosts.CLAUDE, hierarchy_hosts.CODEX, hierarchy_hosts.NATIVE) == (
        hierarchy_provision.CLAUDE, hierarchy_provision.CODEX, hierarchy_provision.NATIVE)
    assert hierarchy_hosts.HOST_KINDS == ("claude-code", "codex-cli", "codex")
    assert hierarchy_hosts.SESSION.pattern == hierarchy_provision.SESSION.pattern == hierarchy_meter.SESSION.pattern
    by_family = {}
    for kind in hierarchy_hosts.HOST_KINDS:
        by_family.setdefault(hierarchy_hosts.family(kind), set()).add(kind)
    assert by_family == {"claude": hierarchy_meter.CLAUDE_HOSTS, "codex": hierarchy_meter.CODEX_HOSTS}
    assert set(by_family) <= set(hierarchy_launcher.CONTRACT_HOSTS)
    for kind in (hierarchy_hosts.CODEX, hierarchy_hosts.NATIVE):
        assert tuple(hierarchy_hosts.entry(kind)["billing_variables"]) == hierarchy_team.API_KEYS


def test_describe_is_the_json_registry_and_callers_cannot_change_it():
    described = hierarchy_hosts.describe()
    assert described["schema"] == hierarchy_hosts.SCHEMA == "aegis.hierarchy-host-registry/v1"
    assert list(described["hosts"]) == list(hierarchy_hosts.HOST_KINDS)
    assert json.loads(json.dumps(described)) == described
    keys = {"kind", "family", "team_start", "home", "billing_variables", "session_variable", "transcripts", "usage",
            "write_scope", "qualification"}
    for kind, entry in described["hosts"].items():
        assert set(entry) == keys and entry["kind"] == kind
    claude, codex, native = (described["hosts"][kind] for kind in hierarchy_hosts.HOST_KINDS)
    assert (claude["team_start"], codex["team_start"], native["team_start"]) == ("print", "exec", None)
    assert claude["home"] == {"variable": "CLAUDE_CONFIG_DIR", "run_folder": "claude-home", "owner_folder": ".claude"}
    assert native["home"] == {"variable": "CODEX_HOME", "run_folder": None, "owner_folder": ".codex"}
    assert claude["session_variable"] == {"name": "CLAUDE_CODE_SESSION_ID", "verified_for_mcp": False}
    assert native["session_variable"] == codex["session_variable"] == {"name": "CODEX_THREAD_ID",
                                                                       "verified_for_mcp": False}
    assert (claude["usage"], codex["usage"], native["usage"]) == ("claude-stream-json-result", "codex-token-count",
                                                                  None)
    assert native["write_scope"] is None and native["transcripts"] == codex["transcripts"]
    described["hosts"]["claude-code"]["write_scope"]["boundary"] = "changed"
    described["hosts"]["codex-cli"]["billing_variables"].append("CHANGED")
    hierarchy_hosts.entry("claude-code")["qualification"]["writer"] = "allowed"
    again = hierarchy_hosts.describe()
    assert again["hosts"]["claude-code"]["write_scope"]["boundary"] == "permission rules, not OS-enforced"
    assert "CHANGED" not in again["hosts"]["codex-cli"]["billing_variables"]
    assert again["hosts"]["claude-code"]["qualification"]["writer"] == "weaker-boundary"


@pytest.mark.parametrize("kind", ["claude", "codex-exec", "", None, ["codex"], "x" * 200])
def test_an_unknown_host_kind_is_refused_with_its_name(kind):
    expected = "unsupported host kind: " + repr(kind)[:80]
    for call, arguments in ((hierarchy_hosts.entry, ()), (hierarchy_hosts.family, ()),
                            (hierarchy_hosts.qualify, (False,)), (hierarchy_hosts.billing_set, ({},))):
        assert refusal(call, kind, *arguments) == expected
    assert refusal(hierarchy_hosts.transcripts, kind, "home", SESSION) == expected


def test_qualify_gives_each_role_its_write_scope_and_refuses_native_threads():
    assert hierarchy_hosts.qualify("claude-code", False) == {"boundary": "no write tools"}
    assert hierarchy_hosts.qualify("codex-cli", False) == {"boundary": "no write tools"}
    assert hierarchy_hosts.qualify("claude-code", True) == {
        "boundary": "permission rules, not OS-enforced", "mechanism": "claude --restricted", "os_enforced": False,
        "owner_decision": "teams 2026-11-07 decision 4",
        "ends_when": "T2(b) qualifies an OS-enforced Claude write scope"}
    assert hierarchy_hosts.qualify("codex-cli", True) == {
        "boundary": "OS sandbox, qualification pending T2(b)", "mechanism": "codex sandbox writable_roots",
        "os_enforced": None}
    assert refusal(hierarchy_hosts.qualify, "codex", False) == "codex is not qualified for a reader role in a team run"
    assert refusal(hierarchy_hosts.qualify, "codex", True) == "codex is not qualified for a writer role in a team run"
    hierarchy_hosts.qualify("claude-code", True)["boundary"] = "changed"
    assert hierarchy_hosts.qualify("claude-code", True)["boundary"] == "permission rules, not OS-enforced"


@pytest.mark.parametrize("writer", [1, 0, "true", None])
def test_qualify_takes_only_a_bool_for_writer(writer):
    assert refusal(hierarchy_hosts.qualify, "codex-cli", writer) == "writer must be a bool"


def test_billing_set_names_each_present_billing_variable_even_when_empty():
    environ = {"PATH": "/bin", "ANTHROPIC_API_KEY": "", "CLAUDE_CODE_USE_BEDROCK": "1", "OPENAI_API_KEY": "sk"}
    assert hierarchy_hosts.billing_set("claude-code", environ) == ["ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_BEDROCK"]
    assert hierarchy_hosts.billing_set("codex-cli", environ) == ["OPENAI_API_KEY"]
    assert hierarchy_hosts.billing_set("codex", {"CODEX_API_KEY": "k", "OPENAI_API_KEY": ""}) == [
        "CODEX_API_KEY", "OPENAI_API_KEY"]
    assert hierarchy_hosts.billing_set("claude-code", {"PATH": "/bin"}) == []
    assert hierarchy_hosts.entry("claude-code")["billing_variables"] == [
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"]


def test_transcripts_find_claude_projects_and_both_codex_session_folders(tmp_path):
    claude = tmp_path / "claude-home"
    found = touch(claude / "projects" / "-work-lane" / (SESSION + ".jsonl"))
    touch(claude / "projects" / "-work-lane" / "other-session.jsonl")
    touch(claude / (SESSION + ".jsonl"))
    assert hierarchy_hosts.transcripts("claude-code", claude, SESSION) == [found]
    codex = tmp_path / "codex-home"
    live = touch(codex / "sessions" / "2026" / "11" / "07" / ("rollout-2026-11-07T10-00-00-" + SESSION + ".jsonl"))
    archived = touch(codex / "archived_sessions" / ("rollout-2026-11-06T09-00-00-" + SESSION + ".jsonl"))
    touch(codex / "sessions" / "2026" / "11" / "07" / "rollout-2026-11-07T10-00-00-other.jsonl")
    expected = sorted([live, archived])
    assert hierarchy_hosts.transcripts("codex-cli", codex, SESSION) == expected
    assert hierarchy_hosts.transcripts("codex", str(codex), SESSION) == expected
    assert all(isinstance(path, Path) for path in expected)
    assert hierarchy_hosts.transcripts("claude-code", tmp_path / "missing", SESSION) == []
    assert hierarchy_hosts.transcripts("codex-cli", tmp_path / "missing", SESSION) == []


@pytest.mark.parametrize("session", ["a*b", "../x", "", ".hidden", "a/b", "a?", "[ab]", "x" * 129, None, 7])
def test_transcripts_refuse_a_session_that_is_not_a_plain_id(tmp_path, session):
    assert refusal(hierarchy_hosts.transcripts, "codex-cli", tmp_path, session) == "invalid session"


def test_claude_usage_counts_every_input_token_once_from_the_real_result_shape():
    usage = hierarchy_hosts.claude_usage(lines(INIT, ASSISTANT, TOOL_RESULT, REAL_RESULT))
    assert usage == {"input_tokens": 509573, "cached_input_tokens": 494692, "cache_write_input_tokens": 14857,
                     "output_tokens": 6217,
                     "native": {"usage": REAL_RESULT["usage"], "total_cost_usd": 0.820714, "num_turns": 13,
                                "session_id": SESSION}}
    bare = {"type": "result", "usage": dict(REAL_RESULT["usage"])}
    assert hierarchy_hosts.claude_usage(lines(bare))["native"] == {
        "usage": REAL_RESULT["usage"], "total_cost_usd": None, "num_turns": None, "session_id": None}


def test_claude_usage_ignores_junk_lines():
    junk = ["", "   ", "not json", "[1, 2]", "42", '"text"', "{broken"]
    assert hierarchy_hosts.claude_usage(lines(*junk, REAL_RESULT, *junk))["input_tokens"] == 509573


def test_claude_usage_is_unknown_without_exactly_one_result():
    assert hierarchy_hosts.claude_usage(lines(INIT, ASSISTANT)) is None
    assert hierarchy_hosts.claude_usage([]) is None
    assert hierarchy_hosts.claude_usage(lines(INIT, REAL_RESULT, ASSISTANT, REAL_RESULT)) is None


@pytest.mark.parametrize("key", ["input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens",
                                 "output_tokens"])
@pytest.mark.parametrize("value", ["24", True, False, -1, 1.5, None, "missing"])
def test_claude_usage_is_unknown_when_a_token_count_is_not_a_non_negative_int(key, value):
    result = json.loads(json.dumps(REAL_RESULT))
    if value == "missing":
        del result["usage"][key]
    else:
        result["usage"][key] = value
    assert hierarchy_hosts.claude_usage(lines(result)) is None


def test_claude_usage_is_unknown_without_a_usage_object():
    assert hierarchy_hosts.claude_usage(lines({"type": "result", "subtype": "error_max_turns"})) is None
    assert hierarchy_hosts.claude_usage(lines({"type": "result", "usage": [24, 0, 0, 1]})) is None


def test_codex_usage_keeps_cached_input_inside_input():
    totals = {"input_tokens": 120000, "cached_input_tokens": 90000, "output_tokens": 4000}
    usage = hierarchy_hosts.codex_usage(totals)
    assert usage == {"input_tokens": 120000, "cached_input_tokens": 90000, "cache_write_input_tokens": None,
                     "output_tokens": 4000, "native": totals}
    usage["native"]["input_tokens"] = 1
    assert totals["input_tokens"] == 120000
    assert hierarchy_hosts.codex_usage({"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0})[
        "input_tokens"] == 0


@pytest.mark.parametrize("totals", [
    None, [], {"input_tokens": 1, "cached_input_tokens": 0},
    {"input_tokens": "1", "cached_input_tokens": 0, "output_tokens": 0},
    {"input_tokens": 1, "cached_input_tokens": True, "output_tokens": 0},
    {"input_tokens": 1, "cached_input_tokens": 0, "output_tokens": -2},
    {"input_tokens": 1.0, "cached_input_tokens": 0, "output_tokens": 0}])
def test_codex_usage_is_unknown_for_malformed_totals(totals):
    assert hierarchy_hosts.codex_usage(totals) is None


def test_claude_init_reduces_the_first_init_event():
    stream = lines("noise", ASSISTANT, INIT, dict(INIT, session_id="second"), REAL_RESULT)
    assert hierarchy_hosts.claude_init(stream) == {
        "session_id": SESSION, "tools": ["Read", "Edit", "mcp__aegis_decision__root_decide"],
        "model": "claude-opus-5-5", "permission_mode": "default", "api_key_source": "none", "version": "2.1.319",
        "mcp_servers": [{"name": "aegis_decision", "status": "connected"}]}
    sparse = hierarchy_hosts.claude_init(lines({"type": "system", "subtype": "init", "session_id": SESSION}))
    assert sparse == {"session_id": SESSION, "tools": None, "model": None, "permission_mode": None,
                      "api_key_source": None, "version": None, "mcp_servers": None}
    assert hierarchy_hosts.claude_init(lines({"type": "system", "subtype": "compact_boundary"}, REAL_RESULT)) is None
    assert hierarchy_hosts.claude_init([]) is None


def test_claude_turn_items_mirror_the_codex_turn_item_shape():
    stream = lines(INIT, ASSISTANT, TOOL_RESULT,
                   {"type": "assistant", "message": {"content": [{"type": "text", "text": "x" * 3000}]}},
                   {"type": "assistant", "message": {"content": "not a list"}},
                   {"type": "assistant", "message": "not a dict"}, REAL_RESULT)
    assert hierarchy_hosts.claude_turn_items(stream) == [
        {"type": "agent_message", "text": "Deciding the request now."},
        {"type": "mcp_tool_call", "tool": "root_decide", "arguments": {"request_id": "r-1", "decision": "approve"}},
        {"type": "agent_message", "text": "x" * 2000}]
    assert hierarchy_hosts.claude_turn_items(lines(REAL_RESULT)) == []


def test_claude_auth_check_accepts_a_subscription_login_in_the_run_home_and_records_no_identity(tmp_path):
    record, problems = hierarchy_hosts.claude_auth_check(0, status(tmp_path), tmp_path)
    assert problems == []
    assert record == {"loggedIn": True, "authMethod": "claude.ai", "apiProvider": "firstParty",
                      "configDirectory": str(tmp_path), "projectsDirectory": str(tmp_path / "projects"),
                      "loginExpiresAt": None}
    for key in IDENTITY:
        assert key not in record


def test_claude_auth_check_reports_a_logged_out_home(tmp_path):
    found = {**LOGGED_OUT_KEYS, "projectsDirectory": str(tmp_path / "projects"), "configDirectory": str(tmp_path),
             "loginExpiresAt": None}
    record, problems = hierarchy_hosts.claude_auth_check(1, found, str(tmp_path))
    assert problems == ["claude auth status exited 1", "not logged in", "auth method 'none' is not claude.ai"]
    assert record["loggedIn"] is False and "analyticsDisabled" not in record


def test_claude_auth_check_refuses_an_api_key_login_and_another_provider(tmp_path):
    _, problems = hierarchy_hosts.claude_auth_check(0, status(tmp_path, authMethod="api_key"), tmp_path)
    assert problems == ["auth method 'api_key' is not claude.ai"]
    _, problems = hierarchy_hosts.claude_auth_check(0, status(tmp_path, apiProvider="bedrock"), tmp_path)
    assert problems == ["api provider 'bedrock' is not firstParty"]


def test_claude_auth_check_refuses_a_config_directory_other_than_the_run_home(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    home = tmp_path / "claude-home"
    home.mkdir()
    _, problems = hierarchy_hosts.claude_auth_check(0, status(other), home)
    assert problems == ["config directory is not the run's claude home"]
    _, problems = hierarchy_hosts.claude_auth_check(0, status(home, configDirectory=None), home)
    assert problems == ["claude auth status field configDirectory has an unexpected type",
                        "config directory is not the run's claude home"]
    spelled = str(home) + os.sep + "." + os.sep
    assert hierarchy_hosts.claude_auth_check(0, status(home, configDirectory=spelled), home)[1] == []


@pytest.mark.parametrize("found", [None, [], "loggedIn", 1])
def test_claude_auth_check_refuses_status_that_is_not_an_object(tmp_path, found):
    record, problems = hierarchy_hosts.claude_auth_check(0, found, tmp_path)
    assert record is None
    assert problems == ["claude auth status printed no JSON object"]
    assert hierarchy_hosts.claude_auth_check(2, found, tmp_path)[1] == [
        "claude auth status exited 2", "claude auth status printed no JSON object"]


@pytest.mark.parametrize("separator", [" ", " ", "\x85"])
def test_claude_readers_keep_an_event_whose_text_holds_a_unicode_line_separator(separator):
    # JSON encoders may leave these characters raw inside strings; only "\n" ends a stream-json line.
    reply = {"type": "assistant", "message": {"content": [{"type": "text", "text": "a" + separator + "b"}]}}
    result = dict(REAL_RESULT, result="done" + separator + "here")
    stdout = "\n".join(lines(INIT, reply, result)) + "\n"
    assert hierarchy_hosts.claude_usage(stdout)["input_tokens"] == 509573
    assert hierarchy_hosts.claude_turn_items(stdout) == [{"type": "agent_message", "text": "a" + separator + "b"}]
    assert hierarchy_hosts.claude_init(stdout.encode("utf-8"))["session_id"] == SESSION


def test_claude_events_skip_lines_that_are_not_text_or_nest_too_deeply():
    deep = "[" * 100000 + "]" * 100000
    assert list(hierarchy_hosts.claude_events([b"\xff", None, 7, deep, json.dumps(INIT)])) == [INIT]


def test_codex_usage_is_unknown_when_cached_input_exceeds_input():
    assert hierarchy_hosts.codex_usage({"input_tokens": 10, "cached_input_tokens": 11, "output_tokens": 0}) is None


@pytest.mark.parametrize("code", [False, 0.0, "0", None])
def test_claude_auth_check_needs_an_integer_zero_exit(tmp_path, code):
    assert hierarchy_hosts.claude_auth_check(code, status(tmp_path), tmp_path)[1] == [
        "claude auth status exited %r" % (code,)]


@pytest.mark.parametrize("configured", ["", "."])
def test_claude_auth_check_refuses_a_relative_config_directory(tmp_path, monkeypatch, configured):
    monkeypatch.chdir(tmp_path)
    assert hierarchy_hosts.claude_auth_check(0, status(tmp_path, configDirectory=configured), tmp_path)[1] == [
        "config directory is not the run's claude home"]


@pytest.mark.parametrize("key, value", [
    ("loginExpiresAt", {"email": "owner@example.com", "orgId": "org-1"}),
    ("configDirectory", ["owner@example.com"]),
    ("authMethod", {"name": "claude.ai"}),
    ("loggedIn", "true"),
    ("projectsDirectory", 7)])
def test_claude_auth_check_records_only_scalar_values_of_the_expected_type(tmp_path, key, value):
    record, problems = hierarchy_hosts.claude_auth_check(0, status(tmp_path, **{key: value}), tmp_path)
    assert key not in record
    assert "owner@example.com" not in json.dumps(record)
    assert "claude auth status field %s has an unexpected type" % key in problems


def _symlink_or_skip(link, target):
    try:
        os.symlink(str(target), str(link), target_is_directory=Path(target).is_dir())
    except (OSError, NotImplementedError) as exc:
        pytest.skip("symlinks unavailable here: %s" % exc)


def test_transcripts_stay_inside_the_home_and_skip_symlinks(tmp_path):
    home, outside = tmp_path / "home", tmp_path / "outside"
    touch(outside / "elsewhere" / (SESSION + ".jsonl"))
    real = touch(home / "projects" / "mine" / (SESSION + ".jsonl"))
    (home / "projects").mkdir(exist_ok=True)
    _symlink_or_skip(home / "projects" / "linked", outside / "elsewhere")
    _symlink_or_skip(home / "projects" / "mine2", outside / "elsewhere")
    file_link = home / "projects" / "files"
    file_link.mkdir()
    _symlink_or_skip(file_link / (SESSION + ".jsonl"), outside / "elsewhere" / (SESSION + ".jsonl"))
    assert hierarchy_hosts.transcripts("claude-code", home, SESSION) == [real]


def test_transcripts_refuse_a_symlinked_home_component(tmp_path):
    home, outside = tmp_path / "home", tmp_path / "outside"
    touch(outside / "p" / (SESSION + ".jsonl"))
    home.mkdir()
    _symlink_or_skip(home / "projects", outside)
    assert hierarchy_hosts.transcripts("claude-code", home, SESSION) == []


# -- the run's host plan and session records (T2(a) PR3) ----------------------------------------------------------------

DIGEST = "ab" * 32
CLAUDE_SCOPE = {"boundary": "permission rules, not OS-enforced", "mechanism": "claude --restricted",
                "os_enforced": False, "owner_decision": "teams 2026-11-07 decision 4",
                "ends_when": "T2(b) qualifies an OS-enforced Claude write scope"}
CODEX_SCOPE = {"boundary": "OS sandbox, qualification pending T2(b)", "mechanism": "codex sandbox writable_roots",
               "os_enforced": None}
STAND_IN = {"boundary": "stand-in: runs no host"}


def plan(**change):
    found = hierarchy_hosts.plan_record("m1", "codex-cli", "claude-code", {"m1/front-door": "claude-code"}, DIGEST)
    found.update(change)
    return found


def test_plan_constants_name_the_team_hosts_and_record_schemas():
    assert hierarchy_hosts.TEAM_HOSTS == ("claude-code", "codex-cli")
    assert hierarchy_hosts.PLAN_SCHEMA == "aegis.hierarchy-host-plan/v1"
    assert hierarchy_hosts.PLAN_FILE == "host-plan.json"
    assert hierarchy_hosts.SESSION_SCHEMA == "aegis.team-session/v1"
    assert hierarchy_hosts.STAND_IN_SCOPE == STAND_IN


def test_plan_record_is_the_validated_adr_shape():
    stand_ins = {"m1/front-door": "claude-code"}
    record = hierarchy_hosts.plan_record("m1", "codex-cli", "claude-code", stand_ins, DIGEST)
    assert record == {"schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "m1", "root": "codex-cli",
                      "team": "claude-code", "stand_ins": {"m1/front-door": "claude-code"}, "config_sha256": DIGEST}
    stand_ins["m1/orchestrator"] = "codex-cli"
    assert record["stand_ins"] == {"m1/front-door": "claude-code"}, "the record keeps its own copy"
    assert hierarchy_hosts.validate_plan(json.loads(json.dumps(record))) == record
    assert hierarchy_hosts.plan_record("m1", "claude-code", "codex-cli", {}, DIGEST)["stand_ins"] == {}


@pytest.mark.parametrize("value,error", [
    ([], "host plan must be a JSON object"),
    ({k: v for k, v in plan().items() if k != "config_sha256"}, "host plan is missing config_sha256"),
    (plan(extra=1), "host plan has unexpected fields: extra"),
    (plan(schema="aegis.hierarchy-host-plan/v2"), "unsupported host plan schema: 'aegis.hierarchy-host-plan/v2'"),
    (plan(hierarchy="Bad Id"), "host plan hierarchy is not a hierarchy id: 'Bad Id'"),
    (plan(hierarchy="across"), "host plan hierarchy is not a hierarchy id: 'across'"),
    (plan(hierarchy=7), "host plan hierarchy is not a hierarchy id: 7"),
    (plan(root="codex"), "host plan root must be claude-code or codex-cli, not 'codex'"),
    (plan(team="codex"), "host plan team must be claude-code or codex-cli, not 'codex'"),
    (plan(team="gemini"), "host plan team must be claude-code or codex-cli, not 'gemini'"),
    (plan(team=None), "host plan team must be claude-code or codex-cli, not None"),
    (plan(stand_ins=["m1/front-door"]), "host plan stand_ins must be a JSON object"),
    (plan(stand_ins={"other/front-door": "claude-code"}), "host plan stand-in other/front-door is not an endpoint of m1"),
    (plan(stand_ins={"m1/nowhere": "claude-code"}), "host plan stand-in m1/nowhere is not an endpoint of m1"),
    (plan(stand_ins={"m1/root": "codex-cli"}), "host plan stand-in m1/root is ROOT, which always runs a host"),
    (plan(stand_ins={"m1/front-door": "gemini"}), "host plan stand-in m1/front-door has unknown host kind 'gemini'"),
    (plan(config_sha256="AB" * 32), "host plan config_sha256 must be 64 lowercase hex characters"),
    (plan(config_sha256="ab" * 31), "host plan config_sha256 must be 64 lowercase hex characters"),
    (plan(config_sha256=None), "host plan config_sha256 must be 64 lowercase hex characters"),
])
def test_validate_plan_refuses_each_malformed_field(value, error):
    assert refusal(hierarchy_hosts.validate_plan, value) == error


def test_plan_record_refuses_a_native_team_host():
    assert refusal(hierarchy_hosts.plan_record, "m1", "codex-cli", "codex", {}, DIGEST) == (
        "host plan team must be claude-code or codex-cli, not 'codex'")


def test_a_stand_in_may_name_any_host_kind_because_it_never_runs():
    assert hierarchy_hosts.validate_plan(plan(stand_ins={"m1/front-door": "codex"}))["stand_ins"] == {
        "m1/front-door": "codex"}


def test_read_plan_is_none_without_a_file_and_the_validated_plan_with_one(tmp_path):
    assert hierarchy_hosts.read_plan(tmp_path) is None
    assert hierarchy_hosts.read_plan(tmp_path / "missing-base") is None
    (tmp_path / "host-plan.json").write_text(json.dumps(plan()), encoding="utf-8")
    assert hierarchy_hosts.read_plan(tmp_path) == plan()


def test_read_plan_refuses_malformed_and_invalid_plans(tmp_path):
    path = tmp_path / "host-plan.json"
    path.write_text("{", encoding="utf-8")
    assert refusal(hierarchy_hosts.read_plan, tmp_path).startswith("invalid host plan %s: " % path)
    path.write_text(json.dumps(plan(team="codex")), encoding="utf-8")
    assert refusal(hierarchy_hosts.read_plan, tmp_path) == "host plan team must be claude-code or codex-cli, not 'codex'"
    path.unlink()
    path.mkdir()
    assert refusal(hierarchy_hosts.read_plan, tmp_path) == (
        "invalid host plan %s: input must be a regular file" % path)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
@pytest.mark.parametrize("dangling", [False, True])
def test_read_plan_refuses_a_symlink(tmp_path, dangling):
    real = tmp_path / "real.json"
    if not dangling:
        real.write_text(json.dumps(plan()), encoding="utf-8")
    (tmp_path / "host-plan.json").symlink_to(real)
    assert refusal(hierarchy_hosts.read_plan, tmp_path) == (
        "host plan must not be a symlink: %s" % (tmp_path / "host-plan.json"))


def test_plan_host_maps_root_team_and_stand_ins_and_leaves_other_hierarchies_alone():
    found = plan()
    assert hierarchy_hosts.plan_host(None, "m1/lane/f2") == (None, False)
    assert hierarchy_hosts.plan_host(found, "other/lane/f2") == (None, False)
    assert hierarchy_hosts.plan_host(found, "m1/root") == ("codex-cli", False)
    assert hierarchy_hosts.plan_host(found, "m1/front-door") == ("claude-code", True)
    for endpoint in ("m1/orchestrator", "m1/router", "m1/decider", "m1/lane/f2", "m1/lane/review"):
        assert hierarchy_hosts.plan_host(found, endpoint) == ("claude-code", False)
    assert refusal(hierarchy_hosts.plan_host, found, "m1") == "invalid endpoint"


def test_require_binding_is_unconstrained_only_without_a_plan():
    assert hierarchy_hosts.require_binding(None, "m1/lane/f2", "codex", True) is None
    assert refusal(hierarchy_hosts.require_binding, plan(), "other/lane/f2", "codex-cli", True) == (
        "other/lane/f2 is not an endpoint of host plan hierarchy m1")


def test_base_plan_refuses_a_plan_written_for_another_hierarchy(tmp_path):
    assert hierarchy_hosts.base_plan(tmp_path, "m1") is None
    (tmp_path / "host-plan.json").write_text(json.dumps(plan()), encoding="utf-8")
    assert hierarchy_hosts.base_plan(tmp_path, "m1") == plan()
    assert refusal(hierarchy_hosts.base_plan, tmp_path, "pilot") == (
        "host plan is for hierarchy m1, but this base serves pilot")


@pytest.mark.parametrize("endpoint,host,expected", [
    ("m1/lane/f2", "codex-cli", "claude-code"),
    ("m1/lane/f2", "codex", "claude-code"),
    ("m1/orchestrator", "host-two", "claude-code"),
    ("m1/root", "claude-code", "codex-cli"),
    ("m1/front-door", "codex-cli", "claude-code"),
])
def test_require_binding_refuses_a_host_the_plan_does_not_assign(endpoint, host, expected):
    assert refusal(hierarchy_hosts.require_binding, plan(), endpoint, host, False) == (
        "%s runs on %s in this run's host plan, not %s" % (endpoint, expected, host))


def test_require_binding_returns_the_qualified_write_scope():
    claude_team, codex_team = plan(), plan(team="codex-cli", root="claude-code")
    assert hierarchy_hosts.require_binding(claude_team, "m1/lane/f2", "claude-code", True) == CLAUDE_SCOPE
    assert hierarchy_hosts.require_binding(claude_team, "m1/lane/review", "claude-code", False) == {
        "boundary": "no write tools"}
    assert hierarchy_hosts.require_binding(claude_team, "m1/root", "codex-cli", False) == {"boundary": "no write tools"}
    assert hierarchy_hosts.require_binding(codex_team, "m1/lane/f2", "codex-cli", True) == CODEX_SCOPE
    assert hierarchy_hosts.require_binding(codex_team, "m1/root", "claude-code", False) == {"boundary": "no write tools"}
    assert refusal(hierarchy_hosts.require_binding, codex_team, "m1/lane/f2", "codex-cli", 1) == "writer must be a bool"


def test_a_stand_in_gets_the_stand_in_scope_without_qualification():
    native = plan(stand_ins={"m1/front-door": "codex"})
    scope = hierarchy_hosts.require_binding(native, "m1/front-door", "codex", True)
    assert scope == STAND_IN
    scope["boundary"] = "changed"
    assert hierarchy_hosts.STAND_IN_SCOPE == STAND_IN, "callers get a copy"
    assert hierarchy_hosts.require_binding(plan(), "m1/front-door", "claude-code", False) == STAND_IN


def record_arguments(**change):
    found = {"endpoint": "m1/lane/f2", "role_kind": "implementer", "host_kind": "claude-code", "start_mode": "print",
             "session": SESSION, "generation": 1, "stand_in": False, "write_scope": CLAUDE_SCOPE}
    found.update(change)
    return found


def test_session_record_is_the_adr_shape():
    assert hierarchy_hosts.session_record(**record_arguments()) == {
        "schema": "aegis.team-session/v1", "endpoint": "m1/lane/f2", "role_kind": "implementer",
        "host_kind": "claude-code", "start_mode": "print", "session": SESSION, "generation": 1, "stand_in": False,
        "write_scope": CLAUDE_SCOPE}
    for mode in ("background", "exec", None):
        assert hierarchy_hosts.session_record(**record_arguments(start_mode=mode))["start_mode"] == mode
    roots = dict(CLAUDE_SCOPE, roots=["/work/lane"])
    assert hierarchy_hosts.session_record(**record_arguments(write_scope=roots))["write_scope"] == roots
    stand_in = hierarchy_hosts.session_record(**record_arguments(
        endpoint="m1/front-door", role_kind="front-door", start_mode=None, stand_in=True, write_scope=STAND_IN))
    assert (stand_in["stand_in"], stand_in["write_scope"]) == (True, STAND_IN)


@pytest.mark.parametrize("change,error", [
    ({"endpoint": "m1"}, "invalid endpoint"),
    ({"endpoint": None}, "invalid endpoint"),
    ({"role_kind": ""}, "invalid role_kind"),
    ({"role_kind": 7}, "invalid role_kind"),
    ({"host_kind": "claude"}, "unsupported host kind: 'claude'"),
    ({"start_mode": "bg"}, "invalid start_mode"),
    ({"start_mode": ["print"]}, "invalid start_mode"),
    ({"session": ""}, "invalid session"),
    ({"session": "s" * 257}, "invalid session"),
    ({"generation": 0}, "invalid generation"),
    ({"generation": True}, "invalid generation"),
    ({"generation": "1"}, "invalid generation"),
    ({"stand_in": 0}, "invalid stand_in"),
    ({"write_scope": None}, "invalid write_scope"),
    ({"write_scope": {"mechanism": "x"}}, "invalid write_scope"),
    ({"write_scope": dict(CLAUDE_SCOPE, roots="/work")}, "invalid write_scope"),
    ({"write_scope": dict(CLAUDE_SCOPE, roots=["/work", ""])}, "invalid write_scope"),
    ({"write_scope": dict(CLAUDE_SCOPE, roots=[7])}, "invalid write_scope"),
])
def test_session_record_refuses_each_malformed_field(change, error):
    with pytest.raises(ValueError) as caught:
        hierarchy_hosts.session_record(**record_arguments(**change))
    assert str(caught.value) == error


def test_session_record_path_quotes_the_endpoint_per_generation(tmp_path):
    assert hierarchy_hosts.session_record_path(tmp_path, "m1/lane/f2", 2) == tmp_path / "sessions" / "m1%2Flane%2Ff2-g2.json"
    assert hierarchy_hosts.session_record_path(str(tmp_path), "m1/root", 1) == tmp_path / "sessions" / "m1%2Froot-g1.json"
    assert refusal(hierarchy_hosts.session_record_path, tmp_path, "m1/lane/f2", 0) == "invalid generation"
    assert refusal(hierarchy_hosts.session_record_path, tmp_path, "m1/../x", 1) == "invalid endpoint role"


def test_team_start_mode_follows_the_registry_and_a_stand_in_has_none():
    assert hierarchy_hosts.team_start_mode("claude-code", False) == "print"
    assert hierarchy_hosts.team_start_mode("claude-code", False, True) == "background"
    assert hierarchy_hosts.team_start_mode("codex-cli", False) == "exec"
    assert hierarchy_hosts.team_start_mode("codex", False) is None
    for kind in hierarchy_hosts.HOST_KINDS:
        assert hierarchy_hosts.team_start_mode(kind, True) is None
    assert refusal(hierarchy_hosts.team_start_mode, "codex-cli", False, True) == "background is only for claude-code roles"
    assert refusal(hierarchy_hosts.team_start_mode, "gemini", False) == "unsupported host kind: 'gemini'"


def test_session_recorded_compares_an_existing_record_and_refuses_a_different_one(tmp_path):
    record = hierarchy_hosts.session_record(**record_arguments(generation=3))
    path = hierarchy_hosts.session_record_path(tmp_path, "m1/lane/f2", 3)
    assert hierarchy_hosts.session_recorded(path, record) is False
    path.parent.mkdir()
    path.write_text(json.dumps(record), encoding="utf-8")
    assert hierarchy_hosts.session_recorded(path, record) is True
    path.write_text(json.dumps({**record, "start_mode": "background"}), encoding="utf-8")
    assert refusal(hierarchy_hosts.session_recorded, path, record) == (
        "session record for m1/lane/f2 generation 3 differs from this binding")
