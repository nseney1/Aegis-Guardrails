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


@pytest.mark.parametrize("arguments,verdict", [
    (["--session-id", SESSION, "--fork-session", "--resume", "/owned/source.jsonl"], "OWNED"),
    (["--fork-session", "--resume", "/owned/source.jsonl", "--session-id", SESSION], "OWNED"),
    (["--resume", "/owned/source.jsonl", "--fork-session", "--session-id", SESSION], "OWNED"),
    (["--resume=/owned/source.jsonl", "--session-id=" + SESSION, "--fork-session"], "OWNED"),
    (["--session-id", SESSION, "--fork-session", "--continue"], "OWNED"),
    (["--fork-session", "-c", "--session-id", SESSION], "OWNED"),
    (["--resume", SESSION, "--fork-session"], "NOT_OWNED"),
    (["--fork-session", "--resume", SESSION], "NOT_OWNED"),
    (["--session-id", "00000000-0000-0000-0000-000000000001", "--fork-session", "--resume", SESSION], "NOT_OWNED"),
    (["--session-id", SESSION, "--session-id", "00000000-0000-0000-0000-000000000001", "--fork-session"], "HOLD"),
    (["--session-id", SESSION, "--fork-session", "--resume"], "HOLD"),
    (["--session-id", SESSION, "--fork-session", "--unlisted", "value"], "HOLD"),
])
def test_r23_fork_selects_the_explicit_session_id(arguments, verdict):
    assert hierarchy_hosts.session_verdict("claude-code", ["claude", *arguments], SESSION) == verdict
    assert not hierarchy_hosts.matches_session("claude-code", ["claude", *arguments], SESSION, "unproven")


def test_r23_unrelated_discovery_never_runs_the_host_grammar(monkeypatch):
    parsing, calls = hierarchy_hosts.session_verdict, []
    def parsed(*args, **kwargs):
        calls.append(args)
        return parsing(*args, **kwargs)
    monkeypatch.setattr(hierarchy_hosts, "session_verdict", parsed)
    for index in range(100):
        assert not hierarchy_hosts.names_session(["python3", "worker-%d.py" % index], SESSION)
    assert calls == []


def test_r23_ownership_parsing_never_copies_the_host_registry(monkeypatch):
    copying, calls = hierarchy_hosts.entry, []
    def copied(*args, **kwargs):
        calls.append(args)
        return copying(*args, **kwargs)
    monkeypatch.setattr(hierarchy_hosts, "entry", copied)
    assert hierarchy_hosts.matches_session("claude-code", ["claude", "--resume", SESSION], SESSION)
    assert hierarchy_hosts.matches_session("codex-cli", ["codex", "exec", "resume", SESSION], SESSION)
    assert hierarchy_hosts.names_session(["claude", "--resume=modelled legacy session"], "modelled legacy session")
    assert not hierarchy_hosts.names_session(["python3", "--config=modelled legacy session"], "modelled legacy session")
    assert calls == []


def test_r23_unsupported_mailbox_inspection_refuses_before_io(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(hierarchy_launcher, "mailbox_wake_inspection_capable", lambda: False)
    with pytest.raises(ValueError, match="^mailbox wake inspection unsupported on this platform; "
                       "preserve the worktree and reconcile the marker manually$"):
        hierarchy_launcher.mailbox_wake_pending(SimpleNamespace(root=tmp_path), "pilot/lane/review")
    assert list(tmp_path.iterdir()) == []


def test_r23_unsupported_admission_publication_refuses_before_io(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(hierarchy_launcher, "running_wake_publication_capable", lambda: False)
    with pytest.raises(ValueError, match="^running wake atomic publication unsupported on this platform$"):
        hierarchy_launcher.publish_wake_record(SimpleNamespace(base=tmp_path), "pilot/lane/review", {})
    assert list(tmp_path.iterdir()) == []


def test_r22_unsupported_running_publication_refuses_before_effects(tmp_path, monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(hierarchy_launcher, "running_wake_publication_capable", lambda: False, raising=False)
    launches = SimpleNamespace(base=tmp_path, folder=lambda endpoint: tmp_path / "launches" / endpoint.replace("/", "%2F"))
    known = dict(host="codex-cli", session=SESSION, generation=1)
    with pytest.raises(ValueError, match="^running wake atomic publication unsupported on this platform$"):
        hierarchy_launcher.write_running_wake(launches, "pilot/lane/review", known, "wake-" + "a" * 32, 123)
    assert list(tmp_path.iterdir()) == []


def test_r20_unsupported_launch_descriptors_refuse_without_creating_files(tmp_path, monkeypatch):
    from types import SimpleNamespace
    # Only this module's OS boundary is modelled. No POSIX flags, symlinks or dir_fd are required by the test.
    monkeypatch.setattr(hierarchy_launcher, "os", SimpleNamespace(name="nt"))
    with pytest.raises(ValueError, match="^launch record descriptors unsupported on this platform$"):
        hierarchy_launcher.launch_record_paths(tmp_path, "pilot/lane/review")
    assert list(tmp_path.iterdir()) == []


def test_r20_descriptor_probe_can_refuse_a_missing_os_capability(tmp_path, monkeypatch):
    monkeypatch.setattr(hierarchy_launcher, "launch_descriptor_capable", lambda: False)
    with pytest.raises(ValueError, match="^launch record descriptors unsupported on this platform$"):
        hierarchy_launcher.launch_record_paths(tmp_path, "pilot/lane/review")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("historical", [False, True])
def test_r21_public_status_reads_without_descriptors(tmp_path, monkeypatch, capsys, historical):
    mailbox = tmp_path / "mailbox"
    mailbox.mkdir()
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {
        "pilot/front-door": {}, "pilot/orchestrator": {}, "pilot/lane/review": {"kind": "reviewer"}},
        "counterparts": [], "writer_limit": 1}
    (mailbox / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "provision.json").write_text(json.dumps({"mailbox_root": str(mailbox)}), encoding="utf-8")
    record = {"schema": hierarchy_launcher.SCHEMA, "action": "resume", "state": "resumed"}
    if historical:
        folder = tmp_path / "launches" / "pilot%2Flane%2Freview"
        folder.mkdir(parents=True)
        (folder / "old.json").write_text(json.dumps(record), encoding="utf-8")
    monkeypatch.setattr(hierarchy_launcher, "launch_descriptor_capable", lambda: False)
    assert hierarchy_launcher.main(["--base", str(tmp_path), "status", "--endpoint", "pilot/lane/review"]) == 0
    assert json.loads(capsys.readouterr().out)["endpoints"]["pilot/lane/review"] == {
        "binding": None, "last": record if historical else None, "records": int(historical)}
    assert (tmp_path / "launches").exists() == historical and not (mailbox / "bindings").exists()


@pytest.mark.parametrize("portable", [False, True])
@pytest.mark.parametrize("bad", ["directory", "symlink", "fifo", "limit", "json", "oversize"])
def test_r21_status_contains_bad_history_to_one_endpoint(tmp_path, monkeypatch, capsys, portable, bad):
    from tests.conftest import symlink_or_skip

    if not portable and not hierarchy_launcher.launch_descriptor_capable():
        pytest.skip("launch descriptors unavailable")
    if bad == "fifo" and os.name != "posix":
        pytest.skip("FIFOs require POSIX")
    mailbox = tmp_path / "mailbox"
    mailbox.mkdir()
    names = ["pilot/lane/review", "pilot/orchestrator"]
    (mailbox / "manifest.json").write_text(json.dumps({"schema": "aegis.hierarchy-pilot/v1",
        "endpoints": {"pilot/front-door": {}, "pilot/orchestrator": {}, "pilot/lane/review": {"kind": "reviewer"}},
        "counterparts": [], "writer_limit": 1}), encoding="utf-8")
    (tmp_path / "provision.json").write_text(json.dumps({"mailbox_root": str(mailbox)}), encoding="utf-8")
    folders = [tmp_path / "launches" / name.replace("/", "%2F") for name in names]
    record = {"state": "resumed"}
    for folder in folders:
        folder.mkdir(parents=True)
        (folder / "old.json").write_text(json.dumps(record), encoding="utf-8")
    path = folders[0] / "z-bad.json"
    if bad == "directory":
        path.mkdir()
    elif bad == "symlink":
        symlink_or_skip(folders[1] / "old.json", path)
    elif bad == "fifo":
        os.mkfifo(path)
    else:
        path.write_text("x" * 262145 if bad == "oversize" else "{" if bad == "json" else "{}", encoding="utf-8")
    if bad == "limit":
        monkeypatch.setattr(hierarchy_launcher, "MAX_RECORDS", 1)
    if portable:
        monkeypatch.setattr(hierarchy_launcher, "launch_descriptor_capable", lambda: False)
    assert hierarchy_launcher.main(["--base", str(tmp_path), "status"]) == 0
    rows = json.loads(capsys.readouterr().out)["endpoints"]
    assert set(rows) == set(names)
    assert rows[names[0]]["state"] == "unknown" and rows[names[0]]["error"]
    assert rows[names[0]]["last"] is None
    assert rows[names[1]] == {"binding": None, "last": record, "records": 1}


@pytest.mark.parametrize("size", [b"1048577\n", b"untrusted-size\n"])
def test_r21_wake_source_limit_precedes_loading(tmp_path, monkeypatch, size):
    from types import SimpleNamespace

    calls = []
    def git(source, *arguments):
        calls.append(arguments)
        assert arguments[:2] == ("cat-file", "-s"), "the oversized source body must never be read"
        return size
    monkeypatch.setattr(hierarchy_launcher, "hierarchy_runtime_source", SimpleNamespace(git=git))
    launches = SimpleNamespace(setup={"source": str(tmp_path), "source_commit": "a" * 40})
    with pytest.raises(ValueError, match="^invalid or oversized wake source$"):
        hierarchy_launcher.load_wake(launches)
    assert len(calls) == 1


NODE_ARITIES = {"--loader": 1, "--experimental-loader": 1, "--import": 1, "-r": 1, "--require": 1,
                "--env-file": 1, "--conditions": 1, "-C": 1, "--title": 1, "--input-type": 1,
                "--no-warnings": 0, "--trace-warnings": 0}
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
            "write_scope", "qualification", "entrypoints", "session_selectors"}
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


@pytest.mark.parametrize("kind,expected", [
    ("claude-code", {"program_basenames": ["claude", "claude.exe", ".claude-wrapped"],
                     "node_script_basenames": ["claude", ".claude-wrapped"],
                     "node_script_suffixes": ["@anthropic-ai/claude-code/cli.js"]}),
    ("codex-cli", {"program_basenames": ["codex"], "node_script_basenames": ["codex", "codex.js"],
                   "node_script_suffixes": []}),
    ("codex", {"program_basenames": [], "node_script_basenames": [], "node_script_suffixes": []}),
])
def test_host_entrypoints_are_json_data_and_cannot_be_mutated_by_callers(kind, expected):
    expected["node_option_arities"] = {} if kind == "codex" else dict(NODE_ARITIES)
    described = json.loads(json.dumps(hierarchy_hosts.describe()))
    assert described["hosts"][kind]["entrypoints"] == expected
    described["hosts"][kind]["entrypoints"]["program_basenames"].append("CHANGED")
    assert hierarchy_hosts.entry(kind)["entrypoints"] == expected


@pytest.mark.parametrize("kind,argv,expected", [
    ("claude-code", ["node", "/nix/store/package/bin/.claude-wrapped"], True),
    ("claude-code", ["node", "/lib/@anthropic-ai/claude-code/cli.js"], True),
    ("claude-code", ["node", "/other/cli.js"], False),
    ("codex-cli", ["/vendor/platform/bin/codex"], True),
    ("codex-cli", ["node", "/lib/bin/codex"], True),
    ("codex-cli", ["claude"], False),
    ("claude-code", [], False),
])
def test_registry_matches_only_the_declared_entrypoints(kind, argv, expected):
    assert hierarchy_hosts.matches_entrypoint(kind, argv) is expected


def test_hosts_without_process_entrypoints_are_refused():
    assert refusal(hierarchy_hosts.matches_entrypoint, "codex", ["codex"]) == "codex has no process entrypoints"
    assert refusal(hierarchy_hosts.matches_entrypoint, "unknown", []) == "unsupported host kind: 'unknown'"


@pytest.mark.parametrize("kind,argv", [
    ("claude-code", ["node", "--no-warnings", "/nix/store/p/bin/.claude-wrapped"]),
    ("claude-code", ["node", "--no-warnings", "/lib/@anthropic-ai/claude-code/cli.js"]),
    ("claude-code", ["node", "-r", "preload", "--import", "module", "/lib/@anthropic-ai/claude-code/cli.js"]),
    ("claude-code", ["node", "--require=preload", "--no-warnings", "--trace-warnings", "--flag=value", "/bin/claude"]),
    ("codex-cli", ["node", "--require", "module", "/lib/@openai/codex/bin/codex.js"]),
])
def test_node_interpreter_options_precede_the_script(kind, argv):
    assert hierarchy_hosts.matches_entrypoint(kind, argv)


@pytest.mark.parametrize("option", ["-e", "--eval", "--eval=source", "--print=source", "-psource"])
def test_node_source_text_does_not_make_a_host_script(option):
    argv = ["node", option, "/lib/@anthropic-ai/claude-code/cli.js", "--resume", SESSION]
    assert not hierarchy_hosts.matches_session("claude-code", argv, SESSION)


@pytest.mark.parametrize("kind,argv,expected", [
    ("claude-code", ["claude", "--resume", SESSION], True),
    ("claude-code", ["claude", "--resume=" + SESSION], True),
    ("claude-code", ["claude", "--session-id", SESSION, "--print", "prompt"], True),
    ("claude-code", ["claude", "--session-id", "other", "--print", SESSION], False),
    ("claude-code", ["claude", "--resume", SESSION, "--session-id", "other"], False),
    ("claude-code", ["claude", "--resume", SESSION, "--session-id=" + SESSION], True),
    ("claude-code", ["claude", "--print", SESSION], False),
    ("claude-code", ["claude", "--", "--resume", SESSION], False),
    ("claude-code", ["claude", "--resume"], False),
    ("claude-code", ["node", "--no-warnings", "/nix/store/p/bin/.claude-wrapped", "--resume", SESSION], True),
    ("claude-code", ["node", "--no-warnings", "/lib/@anthropic-ai/claude-code/cli.js", "--resume", SESSION], True),
    ("codex-cli", ["codex", "resume", SESSION], True),
    ("codex-cli", ["codex", "exec", "resume", SESSION], True),
    ("codex-cli", ["node", "--require", "module", "/lib/@openai/codex/bin/codex.js", "exec", "resume", SESSION], True),
    ("codex-cli", ["codex", "--disable", "apps", "exec", "--json", "-c", "model=\"fake\"", "resume", SESSION], True),
    ("codex-cli", ["codex", "exec", SESSION], False),
    ("codex-cli", ["codex", "exec", "--json", "prompt", "resume", SESSION], False),
    ("codex-cli", ["codex", "resume", SESSION, "resume", "other"], False),
])
def test_session_selector_is_positional_and_unambiguous(kind, argv, expected):
    assert hierarchy_hosts.matches_session(kind, argv, SESSION) is expected


@pytest.mark.parametrize("value,expected", [(SESSION, True), (SESSION.upper(), True),
                                         (SESSION.replace("-", ""), True), ("the", False),
                                         ("review", False), ("prefix-" + SESSION, False)])
def test_session_uuid_shape_distinguishes_ids_from_prompt_words(value, expected):
    assert bool(hierarchy_hosts.SESSION_UUID.fullmatch(value)) is expected


def test_unproven_selector_still_accepts_its_bound_legacy_session_id():
    session = "modelled-legacy-session"
    assert not hierarchy_hosts.matches_session("codex-cli", ["codex", "exec", "resume", session], session, "unproven")


@pytest.mark.parametrize("argv,verdict", [
    (["python3", "tools/hierarchy_mailbox.py", "--after", "<T>"], "CLEAR"),
    (["job.py", "--run", "<T>"], "CLEAR"),
    (["claude", "--resume", "<T>"], "OTHER"),
    (["codex", "exec", "resume", "<T>"], "OTHER"),
    (["claude", "--resume", "--print", "<T>"], "HOLD"),
    (["claude", "-r<T>", "-p", "wait"], "HOLD"),
])
def test_r20_only_parsed_other_host_selectors_spare_a_subtree(argv, verdict):
    other = "00000000-0000-0000-0000-000000000001"
    argv = [word.replace("<T>", other) for word in argv]
    assert hierarchy_hosts.descendant_verdict(argv, SESSION) == verdict


@pytest.mark.parametrize("spelling", ["--resume", "--session-id"])
def test_r20_discovery_preserves_whole_equals_selector_values(spelling):
    session = "modelled legacy session"
    argv = ["claude", spelling + "=" + session]
    assert hierarchy_hosts.matches_session("claude-code", argv, session)
    assert hierarchy_hosts.names_session(argv, session)


@pytest.mark.parametrize("evidence", ["proven", "unproven"])
@pytest.mark.parametrize("kind,arguments", [
    pytest.param("claude-code", ["--resume", "--", "--resume", SESSION], id="modelled-consumed-terminator"),
    pytest.param("claude-code", ["--resume", "unknown", "--resume", SESSION], id="modelled-unknown-selection"),
    pytest.param("claude-code", ["--resume", SESSION, "--session-id"], id="modelled-missing-selection"),
    pytest.param("claude-code", ["--resume", SESSION, "--resume=--print"], id="modelled-equals-option-value"),
    pytest.param("claude-code", ["--resume", "--print", "please", "--resume", SESSION],
                 id="modelled-option-valued-selection"),
    pytest.param("codex-cli", ["exec", "resume", "--last", "resume", SESSION],
                 id="modelled-codex-option-valued-selection"),
])
def test_ambiguous_selection_cannot_be_replaced_by_a_later_match(kind, arguments, evidence):
    program = "claude" if kind == "claude-code" else "codex"
    assert not hierarchy_hosts.matches_session(kind, [program, *arguments], SESSION, evidence)
    assert hierarchy_hosts.selects_other_session([program, *arguments], SESSION)


@pytest.mark.parametrize("word", [
    pytest.param("-r<T>", id="modelled-attached-short-alias"),
    pytest.param("-a<T>", id="modelled-attached-hex-letter-alias"),
    pytest.param("--unlisted=<T>", id="equals"),
    pytest.param("prefix/<T>/suffix", id="bounded-path-occurrence"),
    pytest.param("<T>", id="whole"),
])
def test_bounded_uuid_occurrences_only_spare_descendants(word):
    other = "00000000-0000-0000-0000-000000000001"
    argv = ["claude", word.replace("<T>", other)]
    assert hierarchy_hosts.selects_other_session(argv, SESSION)
    assert not hierarchy_hosts.matches_session("claude-code", argv, other)


@pytest.mark.parametrize("word", ["-r<S>", "--unlisted=<S>", "a" * 64, "a<S>b"])
def test_bound_uuid_and_longer_hex_values_do_not_claim_another_session(word):
    word = word.replace("<S>", SESSION.replace("-", "") if word == "a<S>b" else SESSION)
    assert not hierarchy_hosts.selects_other_session(["worker", word], SESSION)


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
    (plan(stand_ins={"m1/root": "codex-cli"}), "only the front door may be a stand-in, not m1/root"),
    (plan(stand_ins={"m1/orchestrator": "claude-code"}), "only the front door may be a stand-in, not m1/orchestrator"),
    (plan(stand_ins={"m1/lane/f2": "claude-code"}), "only the front door may be a stand-in, not m1/lane/f2"),
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
    scope = hierarchy_hosts.require_binding(native, "m1/front-door", "codex", False)
    assert scope == STAND_IN
    scope["boundary"] = "changed"
    assert hierarchy_hosts.STAND_IN_SCOPE == STAND_IN, "callers get a copy"
    assert hierarchy_hosts.require_binding(plan(), "m1/front-door", "claude-code", False) == STAND_IN


def test_a_stand_in_whose_role_writes_source_is_refused_even_past_validation():
    # validate_plan admits only the front door; this plan skips it, as a hand-edited file read elsewhere might.
    unchecked = dict(plan(), stand_ins={"m1/lane/f2": "claude-code"})
    assert refusal(hierarchy_hosts.require_binding, unchecked, "m1/lane/f2", "claude-code", True) == (
        "m1/lane/f2 cannot be a stand-in: its role writes source")


def test_governing_plan_reads_the_request_base_and_the_mailboxs_own_base(tmp_path):
    own, copy = tmp_path / "own", tmp_path / "copy"
    (own / "mailbox").mkdir(parents=True)
    copy.mkdir()
    mailbox = own / "mailbox"
    assert hierarchy_hosts.governing_plan(own, mailbox, "m1") is None
    assert hierarchy_hosts.governing_plan(copy, mailbox, "m1") is None
    (own / "host-plan.json").write_text(json.dumps(plan()), encoding="utf-8")
    assert hierarchy_hosts.governing_plan(own, mailbox, "m1") == plan()
    assert hierarchy_hosts.governing_plan(copy, mailbox, "m1") == plan(), "a copied provision.json still answers to it"
    (copy / "host-plan.json").write_text(json.dumps(plan()), encoding="utf-8")
    assert hierarchy_hosts.governing_plan(copy, mailbox, "m1") == plan()
    (copy / "host-plan.json").write_text(json.dumps(plan(team="codex-cli")), encoding="utf-8")
    assert refusal(hierarchy_hosts.governing_plan, copy, mailbox, "m1") == (
        "host plans in %s and %s differ" % (copy, own))
    (own / "host-plan.json").unlink()
    assert hierarchy_hosts.governing_plan(copy, mailbox, "m1") == plan(team="codex-cli")
    assert refusal(hierarchy_hosts.governing_plan, copy, mailbox, "pilot") == (
        "host plan is for hierarchy m1, but this base serves pilot")


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


# R2's finite, source-bound catalog, copied as test data rather than read from the matcher under test.
# Public Codex rust-v0.167.0, commit 086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a:
# G: cli/src/main.rs:127-141 + tui/src/cli.rs:66-67,128-135; E: exec/src/cli.rs:15-25;
# R_exec globals: config_override.rs:29-36, main.rs:958-965 and exec/src/cli.rs:36-79,163-170.
R2_CODEX_OPTIONS = [
    (("-c", "--config"), ("G", "E", "R_exec"), 'model="modelled"'),
    (("--enable",), ("G", "E", "R_exec"), "apps"),
    (("--disable",), ("G", "E", "R_exec"), "apps"),
    (("--model", "-m"), ("G", "E", "R_exec"), "modelled"),
    (("--sandbox", "-s"), ("G", "E"), "workspace-write"),
    (("--cd", "-C"), ("G", "E"), "/modelled path/resume data"),
    (("--add-dir",), ("G", "E"), "/modelled path/additional"),
    (("--profile", "-p"), ("G", "E"), "modelled-profile"),
    (("--output-last-message", "-o"), ("E", "R_exec"), "/modelled output/message"),
    (("--output-schema",), ("E", "R_exec"), "/modelled output/schema.json"),
    (("--json", "--experimental-json"), ("E", "R_exec"), None),
    (("--ignore-user-config",), ("E", "R_exec"), None),
    (("--skip-git-repo-check",), ("E", "R_exec"), None),
]


@pytest.mark.parametrize("names,stages,value", R2_CODEX_OPTIONS)
@pytest.mark.parametrize("stage", ["G", "E", "R_exec", "R_direct"])
def test_r2_codex_option_stages_and_aliases_are_finite(names, stages, value, stage):
    for name in names:
        option = [name] + ([] if value is None else [value])
        argv = {"G": ["codex", *option, "exec", "resume", SESSION],
                "E": ["codex", "exec", *option, "resume", SESSION],
                "R_exec": ["codex", "exec", "resume", *option, SESSION],
                "R_direct": ["codex", "resume", *option, SESSION]}[stage]
        assert hierarchy_hosts.matches_session("codex-cli", argv, SESSION) is (stage in stages), argv


@pytest.mark.parametrize("names,stages,value", R2_CODEX_OPTIONS)
def test_r2_codex_unadmitted_equals_attached_and_post_sid_forms_hold(names, stages, value):
    stage = "G" if "G" in stages else "E"
    for name in names:
        forms = [name + "=" + (value if value is not None else "true")]
        if name.startswith("-") and not name.startswith("--") and value is not None:
            forms.append(name + value)
        for form in forms:
            argv = (["codex", form, "exec", "resume", SESSION] if stage == "G" else
                    ["codex", "exec", form, "resume", SESSION])
            assert not hierarchy_hosts.matches_session("codex-cli", argv, SESSION), argv
        after = ["codex", "exec", "resume", SESSION, name, *([] if value is None else [value])]
        assert not hierarchy_hosts.matches_session("codex-cli", after, SESSION), after


def test_r2_all_codex_builder_optional_combinations_preserve_opaque_atoms():
    from itertools import product

    other = "00000000-0000-0000-0000-000000000001"
    disabled_lists = [[], ["apps"], ["apps", "plugins"], hierarchy_provision.CODEX_DISABLED,
                      hierarchy_provision.CODEX_DISABLED + hierarchy_provision.CODEX_SHELL]
    dirs = [[], ["/modelled path/one"], ["/modelled path/one", "/modelled path/resume " + other]]
    profiles = vectors = 0
    for sandbox, ignore, model, effort, tier, tmpdir, skip in product(
            ("read-only", "workspace-write"), (False, True), (None, "model with spaces"), (None, "high"),
            (None, "priority"), (None, "/modelled temp/quotes' resume " + other), (False, True)):
        for disabled, add_dirs in product(disabled_lists, dirs):
            profile = {"disabled_features": disabled, "ignore_user_config": ignore, "sandbox": sandbox,
                       "approval_policy": "never", "writable_roots": ["/modelled roots/resume " + other],
                       "network_access": False, "mcp_servers": {"mailbox": {"command": "python", "args": [
                           "/modelled mcp.py", "--root", "resume " + other]}}, "cwd": "/modelled cwd/resume " + other,
                       "model": model, "effort": effort, "service_tier": tier, "tmpdir": tmpdir,
                       "add_dirs": add_dirs, "skip_git_repo_check": skip}
            profiles += 1
            for tail, expected in ((["resume " + SESSION], False), (["resume", SESSION], True),
                                   (["resume", SESSION, "resume"], True),
                                   (["resume", SESSION, "please resume " + other + " --resume " + other], True)):
                argv = hierarchy_provision.codex_argv(profile, tail)
                assert hierarchy_hosts.matches_session("codex-cli", argv, SESSION) is expected, argv
                vectors += 1
    assert profiles == 1920 and vectors == 7680


def test_r2_descendant_negative_guard_keeps_the_complete_resume_prompt_opaque():
    # MODELLED complete atoms, using the admitted builder tail; the final resume is owner prompt data.
    argv = ["codex", "exec", "resume", SESSION, "resume"]
    assert hierarchy_hosts.matches_session("codex-cli", argv, SESSION)
    assert not hierarchy_hosts.selects_other_session(argv, SESSION)


def test_r2_all_claude_builder_optional_combinations_preserve_opaque_atoms():
    from itertools import product

    # Producer/modelled grammar only: no claim that an installed Claude accepted these option combinations.
    other = "00000000-0000-0000-0000-000000000001"
    catalog = json.dumps({"worker": {"prompt": "Explain --resume " + other}})
    cases = 0
    for bg, assistants, model, effort, ultra, allowed, dirs, selector, tools in product(
            (False, True), (None, catalog), (None, "modelled"), (None, "high"), (False, True),
            ([], ["Read", "Edit"]), ([], ["/modelled path/one"], ["/modelled path/one", "/modelled path/two"]),
            ("--resume", "--session-id"), ([], ["Read", "Edit"])):
        request = {"add_dirs": dirs}
        if model is not None:
            request["model"] = model
        if effort is not None:
            request["effort"] = effort
        if ultra:
            request["ultracode"] = True
        argv = hierarchy_provision.claude_argv([selector, SESSION], "/modelled connection.json", tools, allowed,
                                             request, assistants, "modelled background" if bg else None)
        if bg:
            argv += ["resume"]  # The builder's genuine -- protects its one opaque background prompt.
        assert hierarchy_hosts.matches_session("claude-code", argv, SESSION), argv
        cases += 1
    assert cases == 768


@pytest.mark.parametrize("kind,argv", [
    ("codex-cli", ["codex", "--unknown=value", "exec", "resume", SESSION]),
    ("codex-cli", ["node", "--unknown=value", "/bin/codex", "exec", "resume", SESSION]),
    ("claude-code", ["claude", "--unknown=value", "--resume", SESSION]),
    ("claude-code", ["node", "--unknown=value", "/bin/claude", "--resume", SESSION]),
])
def test_r2_unknown_host_or_node_options_cannot_establish_ownership(kind, argv):
    assert not hierarchy_hosts.matches_session(kind, argv, SESSION)


@pytest.mark.parametrize("family", [None, "", "unknown", "codex-with-empty-options"])
def test_r13_unknown_grammar_family_refuses(monkeypatch, family):
    grammar = hierarchy_hosts._HOSTS["claude-code"]["session_selectors"]["grammar"]
    monkeypatch.setitem(grammar, "family", family)
    assert hierarchy_hosts.session_verdict("claude-code", ["claude", "--resume", SESSION], SESSION) == "HOLD"
