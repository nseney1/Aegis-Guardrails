"""Candidate host adapter contracts; no login, process launch or filesystem probe."""
from concurrent.futures import ThreadPoolExecutor
from collections import UserDict
from collections.abc import Mapping
from copy import deepcopy
import json
from os import _Environ
from pathlib import Path
from types import MappingProxyType

import pytest

from aegis_core import hosts, team_hosts, team_profile


SESSION = "12345678-1234-4234-8234-123456789abc"
OTHER = "abcdefab-1234-4234-8234-123456789abc"


@pytest.fixture
def adapter():
    return team_hosts.host_adapter("antigravity")


@pytest.fixture
def bindings():
    # Tracked repository data stays a plain, cross-platform read.
    path = Path(__file__).resolve().parents[3] / "tools/hierarchy_templates/model-bindings.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_registry_row_and_candidate_profile_kind(adapter):
    assert hosts.get("antigravity").binaries == ("agy",)
    assert isinstance(adapter, team_hosts.HostAdapter)
    assert hosts.get("antigravity").team_adapter == "aegis_core.team_host_agy"
    assert team_profile.PRESET_DATA["hosts"]["antigravity"] == {
        "cli": "agy", "family": "google", "writer": False, "boundary": None}
    assert "antigravity" in team_profile.USER_JSON_SCHEMA["properties"]["model_settings"]["properties"]["hosts"]["properties"]
    assert team_profile.resolve(repo={"version": 1, "preset": "mixed"})["profile"]["model_settings"]["roles"]["lens.extra"]["hosts"] == []


@pytest.mark.parametrize("kind,code", [(None, 2), ([], 2), ({}, 2), ("unknown\nTOKEN=secret", 2),
                                      ("x" * 129, 2), ("nope", 2), ("codex-cli", 1)])
def test_missing_adapter_refuses_without_echo(kind, code):
    with pytest.raises(team_hosts.HostAdapterError, match="^host_adapter_unavailable$") as caught:
        team_hosts.host_adapter(kind)
    assert caught.value.as_dict() == {
        "refused": True, "reason": "host_adapter_unavailable", "exit_code": code,
        "next_action": "Select a registered host with a candidate adapter; no provider fallback is permitted."}


@pytest.mark.parametrize("mode", ["token", "api"])
def test_token_auth_is_explicit_and_never_uses_alternate_key(adapter, mode):
    source = {"PATH": "bin", "GEMINI_API_KEY": "test-key", "GOOGLE_API_KEY": "alternate",
              "TEAMS_GEMINI_MODE": "sso", "TEAMS_GEMINI_KEY_FILE": "untrusted"}
    before = dict(source)
    result = adapter.authentication(mode, source)
    assert result == {"environment": {"PATH": "bin", "GEMINI_API_KEY": "test-key"},
                      "settings": {"modelProvider": "gemini"}}
    assert source == before
    with pytest.raises(team_hosts.HostAdapterError, match="^host_auth_unavailable$"):
        adapter.authentication(mode, {"GOOGLE_API_KEY": "alternate"})
    assert adapter.authentication(mode, source) == result


def test_sso_removes_billing_and_wrapper_overrides(adapter):
    assert adapter.authentication("sso", {
        "PATH": "bin", "GEMINI_API_KEY": "test-key", "GOOGLE_API_KEY": "alternate",
        "TEAMS_GEMINI_MODE": "token", "TEAMS_GEMINI_KEY_FILE": "file"}) == {
            "environment": {"PATH": "bin"}, "settings": {}}


def test_child_environment_handles_windows_case_aliases_portably(adapter):
    source = {"gemini_api_key": "alternate", "Google_Api_Key": "alternate",
              "teams_gemini_mode": "token", "teams_gemini_key_file": "file", "PATH": "bin"}
    assert adapter.authentication("sso", source) == {"environment": {"PATH": "bin"}, "settings": {}}
    with pytest.raises(team_hosts.HostAdapterError, match="^host_auth_unavailable$"):
        adapter.authentication("token", source)
    result = adapter.child_environment({"aegis_team_host": "other", "aegis_team_session": OTHER}, SESSION)
    assert result == {"AEGIS_TEAM_HOST": "antigravity", "AEGIS_TEAM_SESSION": SESSION}


FOREIGN_ENVIRONMENT = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_SESSION_ID", "CLAUDECODE", "CLAUDE_PID", "CLAUDE_EFFORT", "CLAUDE_CODE_CHILD",
    "OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_THREAD_ID", "CODEX_SESSION_ID",
    "CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS", "CODEX_CI", "CODEX_SANDBOX_NETWORK_DISABLED",
    "CODEX_TOOL_CALL_ID", "CODEX_VERSION", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "TEAMS_GEMINI_MODE", "TEAMS_GEMINI_KEY_FILE", "AEGIS_TEAM_HOST", "AEGIS_TEAM_SESSION",
)


@pytest.mark.parametrize("mode", ["sso", "token", "api"])
@pytest.mark.parametrize("spelling", [str.upper, str.lower, str.swapcase])
def test_all_host_credentials_and_markers_are_scrubbed_before_readdition(adapter, mode, spelling):
    source = {spelling(name): "foreign" for name in FOREIGN_ENVIRONMENT}
    source.update(PATH="bin", GEMINI_API_KEY="selected-key")
    before = dict(source)
    expected = {"PATH": "bin"}
    if mode != "sso":
        expected["GEMINI_API_KEY"] = "selected-key"
    assert adapter.authentication(mode, source)["environment"] == expected
    markers = {"AEGIS_TEAM_HOST": "antigravity", "AEGIS_TEAM_SESSION": SESSION}
    assert adapter.child_environment(source, SESSION) == {"PATH": "bin", **markers}
    assert adapter.child_environment(source, SESSION, auth_mode=mode) == {**expected, **markers}
    combined = adapter.authentication(mode, source, session=SESSION)
    assert combined["environment"] == {**expected, **markers}
    with pytest.raises(team_hosts.HostAdapterError, match="^host_auth_unavailable$"):
        adapter.authentication("token", {"OPENAI_API_KEY": "foreign"})
    assert adapter.authentication(mode, source)["environment"] == expected
    assert source == before


@pytest.mark.parametrize("mode,environment,reason,code", [
    (None, {}, "invalid_host_auth", 2), ([], {}, "invalid_host_auth", 2),
    ("key", {}, "invalid_host_auth", 2), ("sso\n", {}, "invalid_host_auth", 2),
    ("sso", [], "invalid_host_environment", 2),
    ("token", {"GEMINI_API_KEY": ""}, "host_auth_unavailable", 1),
    ("token", {"GEMINI_API_KEY": "a\nb"}, "host_auth_unavailable", 1),
    ("token", {"GEMINI_API_KEY": "x" * 4097}, "host_auth_unavailable", 1),
    ("sso", {"x": []}, "invalid_host_environment", 2),
    ("sso", {"bad=key": "value"}, "invalid_host_environment", 2),
    ("sso", {"PATH": "x\x00y"}, "invalid_host_environment", 2),
    ("sso", {str(i): "value" for i in range(257)}, "invalid_host_environment", 2),
])
def test_auth_refusals_have_stable_codes_and_no_input(adapter, mode, environment, reason, code):
    with pytest.raises(team_hosts.HostAdapterError) as caught:
        adapter.authentication(mode, environment)
    result = caught.value.as_dict()
    assert result["refused"] is True and result["exit_code"] == code
    assert result["reason"] == reason
    assert result["next_action"]


def isolated_os_environment(data):
    # Construct over fake data; do not inspect or mutate the process environment.
    return _Environ(data, *(lambda value: value for _ in range(4)))


@pytest.mark.parametrize("factory", [dict, UserDict, MappingProxyType, isolated_os_environment])
def test_environment_mappings_are_accepted_and_copied(adapter, factory):
    data = {"PATH": "bin", "ProgramFiles(x86)": "programs", "CommonProgramFiles(x86)": "common",
            "BASH_FUNC_name%%": "() { :; }", "1START": "numeric", "with space": "space",
            "é": "unicode", "K" * 256: "maximum name"}
    source = factory(dict(data))
    authenticated = adapter.authentication("sso", source)["environment"]
    child = adapter.child_environment(source, SESSION)
    assert authenticated == data
    assert child == {**data, "AEGIS_TEAM_HOST": "antigravity", "AEGIS_TEAM_SESSION": SESSION}
    authenticated["PATH"] = "changed"
    child["PATH"] = "changed"
    assert dict(source) == data
    assert adapter.authentication("sso", source)["environment"] == data


@pytest.mark.parametrize("environment", [
    {"K" + str(i): "v" for i in range(256)}, {"PATH": "v" * 32768},
    {key: "v" * 32767 for key in "ABCD"},
])
def test_environment_at_size_limits_is_accepted(adapter, environment):
    assert adapter.authentication("sso", environment)["environment"] == environment
    assert adapter.child_environment(environment, SESSION) == {
        **environment, "AEGIS_TEAM_HOST": "antigravity", "AEGIS_TEAM_SESSION": SESSION}


class UnreadableEnvironment(Mapping):
    def __len__(self):
        return 1

    def __iter__(self):
        return iter(("PATH",))

    def __getitem__(self, key):
        raise OSError("TOKEN=private")


class MisreportedEnvironment(Mapping):
    def __len__(self):
        return 0

    def __iter__(self):
        return ("K" + str(index) for index in range(257))

    def __getitem__(self, key):
        return "value"


@pytest.mark.parametrize("environment", [
    [], UnreadableEnvironment(), MisreportedEnvironment(), {"PATH": []}, {"PATH": "x" * 32769},
    {"": "value"}, {"bad=key": "value"}, {"bad\x00key": "value"}, {"K" * 257: "value"},
    {1: "value"},
    {"K" + str(i): "v" for i in range(257)},
    {"K" + str(i): "v" * 32768 for i in range(5)},
])
def test_environment_failure_is_distinct_and_retryable(adapter, environment):
    for call in (lambda value: adapter.authentication("sso", value),
                 lambda value: adapter.child_environment(value, SESSION)):
        with pytest.raises(team_hosts.HostAdapterError, match="^invalid_host_environment$") as caught:
            call(environment)
        assert caught.value.exit_code == 2
        assert "Mapping" in caught.value.next_action
        assert call({"PATH": "bin"})


@pytest.mark.parametrize("model_class,base", [("frontier", "gemini-4-carbon"), ("scout", "gemini-4-argon")])
@pytest.mark.parametrize("intent,level", [("light", "low"), ("standard", "medium"), ("deep", "high")])
def test_model_options_consume_registry_without_admission(adapter, bindings, model_class, base, intent, level):
    before = deepcopy(bindings)
    expected = {"model": base + "-" + level, "effort": None, "admission": "unprobed",
                "host_status": "planned"}
    assert adapter.model_options(bindings, model_class, intent) == expected
    assert bindings == before


@pytest.mark.parametrize("model_class,intent", [("coding", "deep"), ("frontier", "max"),
                                               ("scout", []), ([], "deep")])
def test_model_selection_never_substitutes(adapter, bindings, model_class, intent):
    with pytest.raises(team_hosts.HostAdapterError, match="^host_model_unavailable$") as caught:
        adapter.model_options(bindings, model_class, intent)
    assert caught.value.exit_code == 2


@pytest.mark.parametrize("value", ["/untrusted/bindings.json", None, {}, {"hosts": "x" * 262145}])
def test_registry_input_is_bounded_data_never_a_path(adapter, bindings, value):
    with pytest.raises(team_hosts.HostAdapterError, match="^invalid_host_bindings$") as caught:
        adapter.model_options(value, "frontier", "deep")
    assert caught.value.exit_code == 2
    assert adapter.model_options(bindings, "frontier", "deep")["model"] == "gemini-4-carbon-high"


def test_rejected_model_admission_is_a_refusal(adapter, bindings):
    for row in bindings["hosts"]:
        if row["host"] == "antigravity" and row["class"] == "frontier":
            row["admission"]["deep"] = "rejected"
    with pytest.raises(team_hosts.HostAdapterError, match="^host_model_unavailable$") as caught:
        adapter.model_options(bindings, "frontier", "deep")
    assert caught.value.exit_code == 1


@pytest.mark.parametrize("arguments,verdict", [
    (["--conversation", SESSION, "-p", "review"], "OWNED"),
    (["--conversation=" + SESSION, "--model", "gemini-4-carbon-high", "--sandbox"], "OWNED"),
    (["--conversation", OTHER, "--print", SESSION], "NOT_OWNED"),
    (["-p", "--conversation " + SESSION], "HOLD"),
    (["--conversation", SESSION, "-p", "--continue"], "HOLD"),
    (["-p", "--conversation=" + OTHER, "--conversation", SESSION], "HOLD"),
    (["--settings", '{"prompt":"--conversation ' + SESSION + '"}', "-p", "review"], "NOT_OWNED"),
    (["--conversation", SESSION, "--add-dir", "one", "--add-dir", "two"], "OWNED"),
    (["--conversation", SESSION, "--conversation", SESSION], "HOLD"),
    (["--conversation", SESSION, "--conversation", OTHER], "HOLD"),
    (["--conversation", SESSION, "--continue"], "HOLD"),
    (["--continue"], "HOLD"), (["-c"], "HOLD"),
    (["--conversation"], "HOLD"), (["--conversation="], "HOLD"),
    (["--conversation", "latest"], "HOLD"),
    (["--conversation", SESSION, "--unknown"], "HOLD"),
    (["--conversation", SESSION, "--project", "other"], "HOLD"),
    (["--conversation", SESSION, "--remote-agent"], "HOLD"),
    (["--conversation", SESSION, "--model"], "HOLD"),
    (["--conversation", SESSION, "--model", "--sandbox"], "HOLD"),
    (["--conversation", SESSION, "--model", "one", "--model", "two"], "HOLD"),
    (["--conversation", SESSION, "unexpected"], "HOLD"),
    (["--conversation", SESSION, "--", "prompt"], "HOLD"),
    (["--conversation", SESSION + "\n"], "HOLD"),
    (["--conversation", SESSION, "-p", "opaque\n--continue"], "OWNED"),
    (["--conversation", SESSION, "-p", "x" * 32769], "HOLD"),
])
def test_complete_atom_session_grammar(adapter, arguments, verdict):
    assert adapter.session_verdict(["agy", *arguments], SESSION) == verdict


@pytest.mark.parametrize("option,value", [
    ("--conversation", SESSION), ("--model", "candidate"), ("--effort", "high"),
    ("--output-format", "json"), ("--input-format", "text"), ("--mode", "plan"),
    ("--print-timeout", "10s"), ("--settings", "{}"), ("--agent", "candidate"),
    ("--log-file", "log"), ("--json-schema", "{}"), ("--add-dir", "workspace"),
    ("--print", "prompt"), ("-p", "prompt"), ("--prompt", "prompt"),
])
def test_value_options_never_consume_split_selectors(adapter, option, value):
    prefix = [] if option == "--conversation" else ["--conversation", SESSION]
    for atom in ("--continue", "-c", "--conversation=" + OTHER):
        assert adapter.session_verdict(["agy", *prefix, option, atom], SESSION) == "HOLD"
        # Installed help does not document attached dash-leading prompt values.
        assert adapter.session_verdict(["agy", *prefix, option + "=" + atom], SESSION) == "HOLD"
    valid = ["agy", *prefix, option + "=" + value]
    assert adapter.session_verdict(valid, SESSION) == "OWNED"
    assert adapter.session_verdict([*valid, "--continue"], SESSION) == "HOLD"
    duplicate = [*valid, option, value]
    assert adapter.session_verdict(duplicate, SESSION) == ("OWNED" if option == "--add-dir" else "HOLD")
    # A refusal neither changes subsequent selection nor grants ownership on retry.
    assert adapter.session_verdict(valid, SESSION) == "OWNED"


@pytest.mark.parametrize("argv,session,boundaries,verdict", [
    (["/opt/bin/agy", "--conversation", SESSION], SESSION, "proven", "OWNED"),
    (["C:\\bin\\agy.exe", "--conversation", SESSION], SESSION, "proven", "OWNED"),
    (["other", "--conversation", SESSION], SESSION, "proven", "NOT_OWNED"),
    (["sh", "-c", "agy --conversation " + SESSION], SESSION, "proven", "NOT_OWNED"),
    (["agy", "--conversation", SESSION], SESSION, "flattened", "HOLD"),
    (["agy", "--conversation", SESSION], "../escape", "proven", "HOLD"),
    ([], SESSION, "proven", "HOLD"), (None, SESSION, "proven", "HOLD"),
    (["agy", []], SESSION, "proven", "HOLD"),
    (["agy"] * 129, SESSION, "proven", "HOLD"),
])
def test_ownership_needs_proven_argv_and_session(adapter, argv, session, boundaries, verdict):
    assert adapter.session_verdict(argv, session, argv_boundaries=boundaries) == verdict


@pytest.mark.parametrize("prefix,verdict", [
    (["env"], "OWNED"), (["/usr/bin/env"], "OWNED"),
    (["env", "NAME=value"], "OWNED"), (["env", "NAME=--continue", "OTHER=value"], "OWNED"),
    (["env", "-u", "GOOGLE_API_KEY"], "HOLD"), (["env", "--"], "HOLD"),
    (["env", "NAME=value", "-i"], "HOLD"),
    (["env", "NAME=value", "env"], "NOT_OWNED"),
])
def test_launcher_ownership_uses_strict_env_grammar(adapter, prefix, verdict):
    command = [*prefix, "agy", "--conversation", SESSION]
    assert adapter.session_verdict(command, SESSION) == verdict
    assert adapter.session_verdict(["agy", "--conversation", SESSION], SESSION) == "OWNED"


@pytest.mark.parametrize("argv,verdict", [
    (["env"], "HOLD"), (["env", "NAME=value"], "HOLD"),
    (["env", "other", "--conversation", SESSION], "NOT_OWNED"),
    (["C:\\bin\\AGY.EXE", "--conversation", SESSION], "OWNED"),
    (["C:\\bin\\AgY.ExE", "--conversation", SESSION], "OWNED"),
    (["C:\\bin\\ENV.EXE", "C:\\bin\\AGY.EXE", "--conversation", SESSION], "OWNED"),
    (["AGY", "--conversation", SESSION], "NOT_OWNED"),
])
def test_launcher_basename_and_missing_command_cases(adapter, argv, verdict):
    assert adapter.session_verdict(argv, SESSION) == verdict


def test_transcript_locator_and_child_markers_are_data_only(adapter):
    assert adapter.transcript_parts(SESSION) == (
        ".gemini", "antigravity", "brain", SESSION, "transcript.jsonl")
    source = {"PATH": "bin", "AEGIS_TEAM_SESSION": OTHER, "AEGIS_TEAM_HOST": "other"}
    assert adapter.child_environment(source, SESSION) == {
        "PATH": "bin", "AEGIS_TEAM_SESSION": SESSION, "AEGIS_TEAM_HOST": "antigravity"}
    assert source["AEGIS_TEAM_SESSION"] == OTHER
    for value in (None, [], "../escape", SESSION + "\n", "x" * 10000):
        with pytest.raises(team_hosts.HostAdapterError, match="^invalid_host_session$"):
            adapter.transcript_parts(value)
        with pytest.raises(team_hosts.HostAdapterError, match="^invalid_host_session$"):
            adapter.child_environment({}, value)


def test_candidate_runtime_does_not_claim_unmeasured_controls(adapter):
    description = adapter.describe()
    assert description["family"] == "google"
    assert description["qualification"] == "pending"
    assert description["auto_update"] == {"verified": False, "control": None}
    assert description["native_session_marker"] is None
    with pytest.raises(team_hosts.HostAdapterError, match="^host_runtime_unqualified$") as caught:
        adapter.require_launchable()
    assert caught.value.as_dict()["next_action"]


def test_adapter_retries_and_concurrent_calls_do_not_share_mutable_state(adapter, bindings):
    def observe(_):
        result = adapter.describe()
        result["qualification"] = "caller mutation"
        return (adapter.authentication("sso", {"PATH": "bin"}),
                adapter.session_verdict(["agy", "--conversation", SESSION], SESSION),
                adapter.model_options(bindings, "frontier", "deep"), adapter.describe())
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(observe, range(9)))
    assert all(result == results[0] for result in results)
    assert observe(None) == results[0]
    assert adapter.describe()["qualification"] == "pending"


def test_round2_refusals_and_retries_remain_independent_under_concurrency(adapter, bindings):
    source = MappingProxyType({"PATH": "bin", "GEMINI_API_KEY": "selected", "OPENAI_API_KEY": "foreign",
                               "CLAUDECODE": "foreign", "CODEX_SESSION_ID": "foreign",
                               "ProgramFiles(x86)": "programs", "CommonProgramFiles(x86)": "common",
                               "BASH_FUNC_name%%": "() { :; }"})

    def observe(_):
        for call, reason, code in (
            (lambda: team_hosts.host_adapter("unknown"), "host_adapter_unavailable", 2),
            (lambda: adapter.authentication("token", {}), "host_auth_unavailable", 1),
            (lambda: adapter.authentication("sso", UnreadableEnvironment()), "invalid_host_environment", 2),
            (lambda: adapter.child_environment([], SESSION), "invalid_host_environment", 2),
            (lambda: adapter.model_options(None, "frontier", "deep"), "invalid_host_bindings", 2),
            (lambda: adapter.model_options({}, "frontier", "deep"), "invalid_host_bindings", 2),
        ):
            with pytest.raises(team_hosts.HostAdapterError, match="^" + reason + "$") as caught:
                call()
            assert caught.value.exit_code == code
        assert adapter.model_options(bindings, "frontier", "deep")["model"] == "gemini-4-carbon-high"
        assert adapter.session_verdict(["agy", "--conversation", SESSION, "-p", "--continue"], SESSION) == "HOLD"
        assert adapter.session_verdict(["env", "-u", "NAME", "agy", "--conversation", SESSION], SESSION) == "HOLD"
        assert adapter.session_verdict(["env", "agy", "--conversation", SESSION], SESSION) == "OWNED"
        return adapter.authentication("token", source, session=SESSION)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(observe, range(9)))
    expected = {"environment": {"PATH": "bin", "GEMINI_API_KEY": "selected",
                                "ProgramFiles(x86)": "programs", "CommonProgramFiles(x86)": "common",
                                "BASH_FUNC_name%%": "() { :; }",
                                "AEGIS_TEAM_HOST": "antigravity", "AEGIS_TEAM_SESSION": SESSION},
                "settings": {"modelProvider": "gemini"}}
    assert all(result == expected for result in results)
    assert observe(None) == expected
