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
    assert problems == ["config directory is not the run's claude home"]
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
