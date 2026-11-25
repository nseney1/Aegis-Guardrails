"""Exercise the native scanner and observer against legacy evidence."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from threading import Barrier

import pytest

from aegis_core import team_native_codemode as scanner
from aegis_core import team_native_events as events
from aegis_core import team_native_rollout as rollout
from aegis_core.team_mailbox_store import descriptor_supported
from tools import hierarchy_native as legacy

ROOT = Path(__file__).resolve().parents[3]
CID = "11111111-1111-7111-8111-111111111111"
META = {"type": "session_meta", "payload": {"id": CID}}


@pytest.fixture
def make_store(tmp_path):
    if not descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    selected = tmp_path / "selected"
    selected.mkdir(mode=0o700)
    return selected


def write_rollout(directory, *rows, name="rollout.jsonl"):
    path = directory / name
    path.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    return path


def event(kind, **fields):
    return {"type": "event_msg", "payload": {"type": kind, **fields}}


def response(kind, **fields):
    return {"type": "response_item", "payload": {"type": kind, **fields}}


def script(call_id, source):
    return response("custom_tool_call", name="exec", call_id=call_id, input=source)


def printed(call_id, *parts, failed=None):
    header = "Script completed\n" if failed is None else "Script failed\n"
    body = [header, *parts]
    if failed is not None:
        body.append("Script error:\n" + failed)
    return response("custom_tool_call_output", call_id=call_id,
                    output=[{"type": "input_text", "text": part} for part in body])


def shell(command="echo sample", options=""):
    return "text(await tools.exec_command({cmd:%s%s}));" % (json.dumps(command), options)


def patch(target="sample.txt"):
    content = "*** Begin Patch\n*** Add File: %s\n+sample\n*** End Patch" % target
    return "text(await tools.apply_patch(%s));" % json.dumps(content)


def chunk(output="sample", **fields):
    return json.dumps({"chunk_id": "sample", "output": output, **fields})


def assert_refusal(caught, reason):
    error = caught.value
    assert error.reason == reason
    assert error.code == 2 and error.next_action
    assert "private-marker" not in str(error)


def script_diagnostic(reason):
    return {
        "tool": "exec", "reason": reason, "code": 2,
        "next_action": "Use the documented code-mode statement and literal forms, then retry.",
    }


def assert_script_diagnostic(result, reason):
    diagnostic, = result["code_mode_unparsed"]
    expected = script_diagnostic(reason)
    assert {key: diagnostic[key] for key in expected} == expected
    return diagnostic


def assert_no_script_proposals(result, reason):
    assert result["command_executions"] == result["patch_applies"] == []
    assert_script_diagnostic(result, reason)


def assert_unparsed_script(source):
    with pytest.raises(scanner.Unrecognized) as caught:
        scanner.scan_code_mode(source)
    assert scanner.code_mode_calls(source) == ([], False, [script_diagnostic(caught.value.reason)], True)


@pytest.mark.parametrize("source,parts,failed", [
    (shell() + shell("echo next"), [chunk(exit_code=0), chunk(exit_code=1)], None),
    (shell(options=",yield_time_ms:1000"), [chunk(session_id=3)], None),
    (patch() + patch("next.txt") + patch("later.txt"), ["{}"], "patch declined"),
    ("const commands = [\"echo one\", \"echo two\"]; for (const cmd of commands) { "
     "try { text(await tools.exec_command({cmd})); } catch (error) { text({cmd, error: String(error)}); } }",
     [chunk(exit_code=0), json.dumps({"cmd": "echo two", "error": "TypeError: tools.exec_command is not a function"})],
     None),
    (shell() + shell("echo next"), [chunk(exit_code=0)], None),
    (shell(), [chunk(exit_code=1, error="incomplete")], None),
], ids=["two-results", "running", "script-failure", "caught-loop", "few-parts", "unknown-chunk"])
def test_code_mode_events_match_legacy(make_store, source, parts, failed):
    path = write_rollout(make_store, META, event("task_started", turn_id="one"), script("call", source),
                         printed("call", *parts, failed=failed), event("task_started", turn_id="two"))
    for scope in ("current", "all"):
        actual, expected = events.exec_events(path, CID, scope), legacy.exec_events(path, CID, scope)
        assert actual == expected


def test_typed_and_response_events_match_legacy(make_store):
    command = "echo sample"
    typed = {"type": "CommandExecution", "id": "typed", "command": ["sh", "-c", command], "exit_code": 0}
    path = write_rollout(
        make_store, META, event("task_started", turn_id="one"),
        script("shell", shell(command) + shell(command, ',workdir:"example"')),
        event("item_completed", item=typed), event("item_completed", item={**typed, "id": "typed-next"}),
        printed("shell", chunk(exit_code=0), chunk(exit_code=0)),
        script("patch", patch()), event("item_completed", item={"type": "FileChange", "status": "completed",
                                                              "changes": [{"path": "sample.txt"}]}),
        printed("patch", "{}"),
        response("function_call", name="apply_patch", call_id="response", arguments="*** Add File: another.txt"),
        response("function_call_output", call_id="response", output="Success"),
        response("custom_tool_call", name="apply_patch", call_id="pending", input="*** Add File: pending.txt"),
        event("exec_command_end", turn_id="explicit", command="echo separate", exit_code=0),
        event("patch_apply_end", success=False, changes={"denied.txt": {}}, status="declined"),
        {"type": "item.updated", "item": {"type": "command_execution", "command": "echo stream"}},
        {"type": "item.completed", "item": {"type": "file_change", "status": "failed", "changes": []}},
    )
    result = events.exec_events(path, CID, "all")
    assert result == legacy.exec_events(path, CID, "all")
    assert [item["options"] for item in result["command_executions"][:2]] == [["workdir"], ["workdir"]]
    assert result["native_execution_qualified"] is False


@pytest.mark.parametrize("name", ["reviewer", "orchestrator", "integrator", "implementer", "router",
                                  "decider", "front-door"])
def test_retained_native_probe_samples_match_legacy(make_store, name):
    source = ROOT / "tests" / "fixtures" / "hierarchy_native_probe_run1" / (name + ".jsonl")
    data = source.read_bytes()
    cid = next(row["payload"]["id"] for row in map(json.loads, data.splitlines()) if row["type"] == "session_meta")
    path = make_store / source.name
    path.write_bytes(data)
    actual, expected = events.exec_events(path, cid, "all", True), legacy.exec_events(path, cid, "all", True)
    if name == "implementer":
        diagnostic = assert_script_diagnostic(actual, "expected = [")
        proposals = expected["command_executions"]
        removed, = (entry for entry in proposals if entry["source"] == "code_mode"
                    and entry["call_id"] == diagnostic["call_id"])
        assert removed["status"] == "unpaired"
        proposals.remove(removed)
        assert {**actual, "code_mode_unparsed": []} == expected
    else:
        assert actual == expected


def test_catalogs_match_legacy(make_store):
    source = ROOT / "tests" / "fixtures" / "hierarchy_native_multi_agent" / "v2.jsonl"
    path = make_store / source.name
    path.write_bytes(source.read_bytes())
    assert events.multi_agent_state(path) == legacy.multi_agent_state(path)
    path = write_rollout(
        make_store, META, {"type": "turn_context", "payload": {"multi_agent_version": "v2"}},
        response("additional_tools", tools=[{"name": "spawn_agent"}, {"name": "clock.sleep"},
                  {"type": "namespace", "name": "workers", "tools": [{"name": "launch"}]}]),
        response("additional_tools", tools=[]), {"type": "turn_context", "payload": {}},
    )
    assert events.multi_agent_state(path, CID) == legacy.multi_agent_state(path, CID)


@pytest.mark.parametrize("source,reason", [
    (None, "code-mode input must be text"),
    ("text(foo());", "expected text ( await"),
    (shell() + "/* unfinished", "expected text ( await"),
    ("text(await tools.exec_command({cmd: private_marker}));", "cmd is not a string literal"),
    (shell(options=',"cmd":"echo alternate"'), "duplicate command option"),
    (shell(options=',yield_time_ms:001'), "an option is not a literal"),
    ("const commands = [\"echo sample\"]; for (const cmd of commands) { "
     "try { text(await tools.exec_command({cmd})); } catch (cmd) { text({cmd, error: String(cmd)}); } }",
     "unsupported catch binding"),
])
def test_closed_grammar_refuses_and_retries(source, reason):
    with pytest.raises(scanner.Unrecognized) as caught:
        scanner.scan_code_mode(source)
    assert_refusal(caught, reason)
    assert scanner.scan_code_mode(shell())[0]["command"] == "echo sample"


def test_scan_counts_calls_before_expanding_and_retries():
    limit = scanner.CODE_MODE_MAX_CALLS
    source = "const commands = %s; for (const cmd of commands) { text(await tools.exec_command({cmd})); }"
    assert len(scanner.scan_code_mode(source % json.dumps(["echo sample"] * limit))) == limit
    with pytest.raises(scanner.CodeModeLimit) as caught:
        scanner.scan_code_mode(source % json.dumps(["echo sample"] * (limit + 1)))
    assert_refusal(caught, "code-mode script exceeds %d calls" % limit)
    assert len(scanner.scan_code_mode(shell())) == 1


def test_token_budget_refuses_before_scanning_calls(monkeypatch):
    monkeypatch.setattr(scanner, "MAX_CODE_MODE_TOKENS", 32)
    with pytest.raises(scanner.CodeModeLimit) as caught:
        scanner.scan_code_mode("?" * 33)
    assert_refusal(caught, "code-mode input exceeds token limit")
    assert len(scanner.scan_code_mode(shell())) == 1


def test_source_budget_refuses_before_decoding(monkeypatch):
    monkeypatch.setattr(scanner, "MAX_RECORD_BYTES", 96)
    source = "/*" + "é" * 48 + "*/"
    with pytest.raises(scanner.CodeModeLimit) as caught:
        scanner.scan_code_mode(source)
    assert_refusal(caught, "code-mode input exceeds observation byte limit")
    assert len(scanner.scan_code_mode(shell())) == 1


def test_over_budget_script_does_not_return_partial_events(make_store):
    source = shell() * (scanner.CODE_MODE_MAX_CALLS + 1)
    path = write_rollout(make_store, META, script("call", source), printed("call", chunk(exit_code=0)))
    result = events.exec_events(path, CID)
    assert result["command_executions"] == result["patch_applies"] == []
    refusal, = result["code_mode_unparsed"]
    assert refusal["reason"] == "code-mode script exceeds %d calls" % scanner.CODE_MODE_MAX_CALLS
    assert refusal["code"] == 2 and refusal["next_action"]


@pytest.mark.parametrize("source", ["text(await tools.exec_command({cmd: private_marker}));",
                                  shell(options=',"cmd":"echo alternate"')])
def test_unrecognized_calls_have_fixed_inert_diagnostics(make_store, source):
    path = write_rollout(make_store, META, script("call", source), printed("call", chunk(exit_code=0)))
    actual = events.exec_events(path, CID)
    assert actual["command_executions"] == actual["patch_applies"] == []
    reason = "cmd is not a string literal" if "private_marker" in source else "duplicate command option"
    assert_script_diagnostic(actual, reason)


def test_observation_budget_counts_pending_and_completed_calls(make_store, monkeypatch):
    command = "echo " + "sample" * 200
    call = shell(command)
    start = script("first", call)
    finish = printed("first", chunk(exit_code=0))
    remaining = script("second", call + call)
    path = write_rollout(make_store, META, start, finish, remaining)
    # The closed emission stays charged beside the next script. One pending
    # call still fits; a second pending call does not.
    budget = 6 * len(command)
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", budget)
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "too_large")
    write_rollout(make_store, META, start, finish, script("second", call))
    assert len(events.exec_events(path, CID)["command_executions"]) == 2


def test_catalog_budget_counts_repeated_namespace_text(make_store, monkeypatch):
    names = [{"name": str(index)} for index in range(3)]
    name = "private-marker-sample"
    monkeypatch.setattr(events, "MAX_ROLLOUT_BYTES", sum(len(name + "." + tool["name"]) for tool in names[:2]))
    catalog = response("additional_tools", tools=[{"type": "namespace", "name": name, "tools": names}])
    path = write_rollout(make_store, META, catalog)
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.multi_agent_state(path, CID)
    assert_refusal(caught, "too_large")
    catalog["payload"]["tools"][0]["tools"].pop()
    write_rollout(make_store, META, catalog)
    assert events.multi_agent_state(path, CID)["unknown_tools"] == [name + ".0", name + ".1"]


@pytest.mark.parametrize("reader,kwargs,rows", [
    (events.exec_events, {"scope": []}, [META]),
    (events.exec_events, {}, []),
    (events.exec_events, {}, [{"type": "session_meta", "payload": []}]),
    (events.exec_events, {}, [META, {"type": [], "payload": {}}]),
    (events.exec_events, {}, [META, response([], call_id="private-marker")]),
    (events.exec_events, {}, [META, script("private-marker", shell()), script("private-marker", patch())]),
    (events.exec_events, {}, [META, event("item_completed", item={"type": []})]),
    (events.exec_events, {}, [META, event("exec_command_end", turn_id=[], command="echo sample")]),
    (events.multi_agent_state, {}, [META, response("additional_tools", tools=[{"name": "private-marker",
                                                                              "type": "namespace", "tools": [0]}])]),
], ids=["scope", "missing-identity", "payload", "record-kind", "response-kind", "duplicate-call",
        "item-kind", "turn", "catalog"])
def test_malformed_observations_refuse_and_retry(make_store, reader, kwargs, rows):
    path = write_rollout(make_store, *rows)
    original = path.read_bytes()
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        reader(path, CID, **kwargs)
    assert_refusal(caught, "invalid_record")
    assert path.read_bytes() == original
    write_rollout(make_store, META)
    assert reader(path, CID)["cid"] == CID


def test_unsupported_platform_refuses_without_descriptor_io(monkeypatch, tmp_path):
    monkeypatch.setattr(rollout, "descriptor_supported", lambda: False)
    for reader in (events.exec_events, events.multi_agent_state):
        with pytest.raises(rollout.NativeRolloutRefusal) as caught:
            reader(tmp_path / "unavailable", CID)
        assert_refusal(caught, "unsupported_platform")


def test_observations_remain_unqualified_with_an_injected_gate(make_store):
    path = write_rollout(make_store, META)
    result = events.exec_events(path, CID, qualification_gate=lambda: True)
    assert result["native_execution_qualified"] is False
    assert result["qualification_blocker"] == rollout.NATIVE_GAP


def test_interleaved_reads_and_incomplete_tail_retry(make_store):
    def records(label):
        return (META, script("same", shell("echo " + label)), printed("same", chunk(label, exit_code=0)))

    first = write_rollout(make_store, *records("first"), name="first.jsonl")
    second = write_rollout(make_store, *records("second"), name="second.jsonl")
    complete = first.read_bytes()
    first.write_bytes(complete[:-1])
    start = Barrier(2, timeout=5)

    def observe(path):
        start.wait()
        return events.exec_events(path, CID)

    with ThreadPoolExecutor(max_workers=2) as workers:
        bad = workers.submit(observe, first)
        good = workers.submit(observe, second)
        with pytest.raises(rollout.NativeRolloutRefusal) as caught:
            bad.result(timeout=5)
        assert_refusal(caught, "incomplete_record")
        assert good.result(timeout=5)["command_executions"][0]["aggregated_output"] == "second"
    assert events.exec_events(first, CID, tolerant=True)["command_executions"][0]["status"] == "unpaired"
    first.write_bytes(complete)
    assert events.exec_events(first, CID)["command_executions"][0]["aggregated_output"] == "first"


@pytest.mark.parametrize("array,binding", [("array", "cmdé"), ("cafés", "cmd")])
def test_unicode_binding_keeps_paired_results(make_store, array, binding):
    source = ('const %s = ["echo one"]; for (const %s of %s) '
              'text(await tools.exec_command({cmd:%s}));') % (array, binding, array, binding)
    path = write_rollout(make_store, META, script("one", source), printed("one", chunk(exit_code=0)))
    assert events.exec_events(path, CID) == legacy.exec_events(path, CID)


def test_valid_option_escape_keeps_paired_results(make_store):
    source = shell(options=r',workdir:"\x2e"')
    path = write_rollout(make_store, META, script("one", source), printed("one", chunk(exit_code=0)))
    assert events.exec_events(path, CID) == legacy.exec_events(path, CID)


def test_unparsed_loop_proposes_nothing_and_keeps_the_strict_refusal(make_store):
    source = ('const a = ["echo one"]; for (const cmd of a) text(await tools.exec_command({cmd})); '
              'text("done");')
    path = write_rollout(make_store, META, script("one", source))
    result = events.exec_events(path, CID)
    assert_no_script_proposals(result, "expected text ( await")


@pytest.mark.parametrize("scope", ["all", "current"])
def test_long_typed_history_matches_legacy(make_store, scope):
    old = event("exec_command_end", command="echo old", exit_code=0)
    path = write_rollout(make_store, META, event("task_started", turn_id="one"), *([old] * 32769),
                         event("task_started", turn_id="two"), event("exec_command_end", command="echo current"))
    assert events.exec_events(path, CID, scope) == legacy.exec_events(path, CID, scope)


def test_caught_batch_with_both_safe_options_matches_legacy(make_store):
    source = ('try { ' + shell(options=',yield_time_ms:1,max_output_tokens:1') +
              ' } catch (error) { text(String(error)); }') * 900
    path = write_rollout(make_store, META, script("one", source), printed("one", *([chunk(exit_code=0)] * 900)))
    assert events.exec_events(path, CID) == legacy.exec_events(path, CID)


def test_repeated_catalogs_match_legacy(make_store):
    source = ROOT / "tests" / "fixtures" / "hierarchy_native_multi_agent" / "v2.jsonl"
    catalog = next(row for row in map(json.loads, source.read_bytes().splitlines())
                   if row["payload"].get("type") == "additional_tools")
    path = write_rollout(make_store, META, *([catalog] * 2979))
    assert events.multi_agent_state(path, CID) == legacy.multi_agent_state(path, CID)


@pytest.mark.parametrize("options", [',workdir:"example",cmd:"echo sample"', ',workdir:"/attacker",cmd:"echo sample"',
                                     r',workdir:"\x2e"',
                                     r',workdir:"\xZZ"'])
def test_refused_or_escaped_options_never_make_typed_evidence_exact(make_store, options):
    from tools.hierarchy_probe_evidence import command_matches

    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample"})
    path = write_rollout(make_store, META, script("one", shell(options=options)), typed, printed("one", chunk(exit_code=0)))
    expected = legacy.exec_events(path, CID)
    reference, = expected["command_executions"]
    assert command_matches(reference, "echo sample", True, events.CODE_MODE_SAFE_OPTIONS) == "untrusted"
    try:
        result = events.exec_events(path, CID)
    except rollout.NativeRolloutRefusal as error:
        assert error.code == 2 and error.next_action
    else:
        entry, = result["command_executions"]
        assert command_matches(entry, "echo sample", True, events.CODE_MODE_SAFE_OPTIONS) == "untrusted"
        if options == r',workdir:"\x2e"':
            assert result == expected


@pytest.mark.parametrize("call", [script("same", shell()),
                                  response("function_call", call_id="same", name="apply_patch", arguments="")])
def test_unrelated_duplicate_calls_refuse_and_recover(make_store, call):
    other = response("custom_tool_call", call_id="same", name="unrelated", input="")
    output = printed("same", chunk(exit_code=0)) if call["payload"]["name"] == "exec" else response(
        "function_call_output", call_id="same", output="Success")
    path = write_rollout(make_store, META, call, other, output)
    reference = legacy.exec_events(path, CID)
    key = "command_executions" if call["payload"]["name"] == "exec" else "patch_applies"
    assert reference[key][0]["line"] == 4
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "invalid_record")
    write_rollout(make_store, META, call)
    assert events.exec_events(path, CID)["cid"] == CID


@pytest.mark.parametrize("kind,wrong", [("function_call", "custom_tool_call_output"),
                                       ("custom_tool_call", "function_call_output")])
def test_mismatched_output_kind_preserves_pending_patch(make_store, kind, wrong):
    path = write_rollout(make_store, META, response(kind, call_id="one", name="apply_patch",
                         arguments="*** Add File: sample.txt", input="*** Add File: sample.txt"),
                         response(wrong, call_id="one", output="irrelevant"),
                         response(legacy.PATCH_CALLS[kind], call_id="one", output="Success"))
    entry, = events.exec_events(path, CID)["patch_applies"]
    assert entry["success"] is True and entry["line"] == 4
    assert legacy.exec_events(path, CID)["patch_applies"] == []


def test_mismatched_explicit_turn_preserves_pending_script(make_store):
    wrong = printed("one", chunk(exit_code=1))
    wrong["payload"]["turn_id"] = "two"
    path = write_rollout(make_store, META, event("task_started", turn_id="one"), script("one", shell()), wrong,
                         printed("one", chunk(exit_code=0)))
    entry, = events.exec_events(path, CID)["command_executions"]
    assert entry["exit_code"] == 0 and entry["line"] == 5
    assert legacy.exec_events(path, CID)["command_executions"][0]["exit_code"] == 1


@pytest.mark.parametrize("source", [shell(), patch(), "try { " + shell() + " } catch (e) { text(String(e)); }",
                                    "try { " + patch() + " } catch (e) { text(String(e)); }"])
def test_nested_printed_results_refuse_for_patch_and_shell(make_store, source):
    deep = "[" * 40 + "0" + "]" * 40
    part = '{"chunk_id":"a","output":"","exit_code":0,"extra":' + deep + "}"
    path = write_rollout(make_store, META, script("one", source), printed("one", part))
    key = "command_executions" if "exec_command" in source else "patch_applies"
    assert legacy.exec_events(path, CID)[key][0]["status"] in ("completed", "unknown")
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "too_large")
    write_rollout(make_store, META, script("one", source), printed("one", chunk(exit_code=0)))
    assert events.exec_events(path, CID)["cid"] == CID


def test_excess_printed_parts_are_a_typed_refusal(make_store):
    path = write_rollout(make_store, META, script("one", shell()),
                         printed("one", *(["{}"] * (scanner.CODE_MODE_MAX_CALLS + 2))))
    assert legacy.exec_events(path, CID)["command_executions"][0]["status"] == "unpaired"
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "too_large")


@pytest.mark.parametrize("option", ["true", "false"])
def test_options_cannot_use_unbound_shorthand(option):
    assert legacy.code_mode_calls(shell(options="," + option))[1]
    with pytest.raises(scanner.Unrecognized) as caught:
        scanner.scan_code_mode(shell(options="," + option))
    assert_refusal(caught, "unsupported shorthand property")


def test_unterminated_comment_keeps_strict_refusal(make_store):
    path = write_rollout(make_store, META, script("one", shell() + "/* unfinished"),
                         printed("one", chunk(exit_code=0)))
    result = events.exec_events(path, CID)
    assert_no_script_proposals(result, "expected text ( await")


def test_catalog_charges_utf8_before_qualifying(monkeypatch, make_store):
    name = "😀" * 40
    monkeypatch.setattr(events, "MAX_ROLLOUT_BYTES", 100)
    catalog = response("additional_tools", tools=[{"type": "namespace", "name": name, "tools": [{"name": "sample"}]}])
    path = write_rollout(make_store, META, catalog)
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.multi_agent_state(path, CID)
    assert_refusal(caught, "too_large")


def test_pending_option_union_is_reused_for_repeated_completions(make_store):
    source = shell(options="".join(",opt%d:1" % index for index in range(200)))
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample"})
    path = write_rollout(make_store, META, script("one", source), *([typed] * 50))
    entries = events.exec_events(path, CID)["command_executions"]
    assert len(entries) == 50 and len(entries[0]["options"]) == 200
    assert all(entry["options"] is entries[0]["options"] for entry in entries)


def test_option_view_preserves_already_emitted_evidence_when_a_script_closes(make_store):
    first = shell(options=",yield_time_ms:1") * 2
    second = shell(options=',workdir:"example"')
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample"})
    path = write_rollout(make_store, META, script("first", first), script("second", second),
                         typed, printed("second", chunk(exit_code=0)), typed,
                         printed("first", chunk(exit_code=0), chunk(exit_code=0)))
    result = events.exec_events(path, CID)
    assert result == legacy.exec_events(path, CID)
    assert [entry["options"] for entry in result["command_executions"]] == [
        ["workdir", "yield_time_ms"], ["workdir"], ["yield_time_ms"]]


def test_repeated_options_are_charged_even_when_the_view_is_shared(make_store, monkeypatch):
    # Pending calls, one shared option view and the unpaired emission use one budget.
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", 34000)
    source = shell(options="".join(",opt%d:1" % index for index in range(200)))
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample"})
    path = write_rollout(make_store, META, script("one", source), *([typed] * 50))
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "too_large")
    write_rollout(make_store, META, script("one", source), typed)
    entry, = events.exec_events(path, CID)["command_executions"]
    assert len(entry["options"]) == 200


def test_covered_output_still_refuses_embedded_json_that_exceeds_depth(make_store):
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample"})
    deep = '{"extra":' + "[" * 40 + "0" + "]" * 40 + "}"
    path = write_rollout(make_store, META, script("one", shell()), typed, printed("one", deep))
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "too_large")


def test_opaque_refusal_cannot_leave_typed_completions_exact(make_store):
    from tools.hierarchy_probe_evidence import command_matches

    opened = script("one", "text(foo());")
    shell_event = event("item_completed", item={"type": "CommandExecution", "command": "echo sample"})
    path = write_rollout(make_store, META, opened, shell_event)
    entry, = events.exec_events(path, CID)["command_executions"]
    assert command_matches(entry, "echo sample", True, events.CODE_MODE_SAFE_OPTIONS) == "untrusted"
    patch_event = event("item_completed", item={"type": "FileChange", "changes": [{"path": "sample.txt"}],
                                               "status": "failed"})
    write_rollout(make_store, META, opened, patch_event, event("task_started", turn_id="later"),
                  event("exec_command_end", command="echo later", exit_code=0))
    result = events.exec_events(path, CID, "all")
    assert result["patch_applies"][0]["options"] == ["code_mode_unparsed"]
    assert result["command_executions"][-1]["command"] == "echo later"
    assert events.exec_events(path, CID, "current")["command_executions"][0]["command"] == "echo later"


def test_unparsed_suffix_preserves_unrelated_typed_completion(make_store):
    source = shell() + 'text("done");'
    command = "echo independent"
    typed = event("item_completed", item={"type": "CommandExecution", "command": command})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    entry, = actual["command_executions"]
    assert _exact(entry, command) == "untrusted"
    assert_script_diagnostic(actual, "expected text ( await")


@pytest.mark.parametrize("source,reason", [
    ('const a=["echo one"]; for (const cmd of a) { text(await tools.exec_command({cmd})); text("done"); '
     + shell("echo two") + '}', "expected }"),
    ('const a=["echo x"]; for (const cmd of a) { try { text(await tools.exec_command({cmd})); } '
     'catch (e) { text("failed"); } }', "a catch that prints something else"),
], ids=["braced-body-and-literal", "loop-catch"])
def test_unparsed_loop_records_only_the_strict_diagnostic(make_store, source, reason):
    path = write_rollout(make_store, META, script("one", source), printed("one", chunk(exit_code=0)))
    assert_no_script_proposals(events.exec_events(path, CID), reason)


@pytest.mark.parametrize("character", ["\r", "\u2028", "\u2029"], ids=["cr", "line", "paragraph"])
def test_legacy_line_comments_end_only_at_lf(make_store, character):
    for source in ("//" + character + shell(), shell() + "//keep" + character + "ok"):
        path = write_rollout(make_store, META, script("one", source), printed("one", chunk(exit_code=0)))
        assert events.exec_events(path, CID) == legacy.exec_events(path, CID)
    source = "// comment" + character + "\n" + shell()
    path = write_rollout(make_store, META, script("one", source), printed("one", chunk(exit_code=0)))
    assert events.exec_events(path, CID) == legacy.exec_events(path, CID)


@pytest.mark.parametrize("source,diagnostic", [
    (shell() + "\ufeff", "expected text ( await"),
    (shell().replace("await ", "await\u0085"), None),
], ids=["bom", "next-line"])
def test_legacy_python_whitespace_class(make_store, source, diagnostic):
    path = write_rollout(make_store, META, script("one", source), printed("one", chunk(exit_code=0)))
    expected, actual = legacy.exec_events(path, CID), events.exec_events(path, CID)
    if diagnostic is None:
        assert actual == expected
    else:
        assert_no_script_proposals(actual, diagnostic)


@pytest.mark.parametrize("source", [shell(), patch(), "try { " + shell() + " } catch (e) { text(String(e)); }",
                                    "try { " + patch() + " } catch (e) { text(String(e)); }"])
def test_printed_numeric_bound_is_a_fixed_refusal(make_store, source):
    valid = '{"chunk_id":"x","output":"","exit_code":0,"extra":18446744073709551615}'
    overflow = '{"chunk_id":"x","output":"","exit_code":0,"extra":18446744073709551616}'
    path = write_rollout(make_store, META, script("one", source), printed("one", overflow))
    expected = legacy.exec_events(path, CID)
    assert expected["command_executions" if "exec_command" in source else "patch_applies"][0]["status"] == (
        "completed" if "exec_command" in source else "unknown")
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "too_large")
    write_rollout(make_store, META, script("one", source), printed("one", valid))
    assert events.exec_events(path, CID) == legacy.exec_events(path, CID)


def record_bytes(row):
    return json.dumps(row, separators=(",", ":"), sort_keys=True).encode() + b"\n"


def history_hash(history):
    """Compare every observation without retaining both readers' large lists."""
    digest = hashlib.sha256()
    for entry in history["command_executions"]:
        digest.update(record_bytes(entry))
    return digest.hexdigest()


def test_legacy_byte_ceiling_accepts_dense_typed_history(make_store, monkeypatch):
    # Keep the density and the input-to-observation ceiling ratio of the
    # original history. Charging the fixed typed envelope would still overflow.
    scale = 16
    scaled_legacy_limit = legacy.MAX_ROLLOUT_BYTES // scale
    record_count = 1_400_000 // scale
    monkeypatch.setattr(rollout, "MAX_ROLLOUT_BYTES", rollout.MAX_ROLLOUT_BYTES // scale)
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", events.MAX_OBSERVATION_BYTES // scale)
    sample = record_bytes(event("exec_command_end", command="echo x", exit_code=0))
    path = make_store / ("long-history-" + "x" * 64 + ".jsonl")
    batches, tail = divmod(record_count, 1000)
    with path.open("wb") as stream:
        stream.write(record_bytes(META))
        block = sample * 1000
        for _ in range(batches):
            stream.write(block)
        stream.write(sample * tail)
        stream.write(record_bytes(event("task_started", turn_id="last")))
        stream.write(record_bytes(event("exec_command_end", command="echo current")))
    assert scaled_legacy_limit * 95 // 100 < path.stat().st_size < scaled_legacy_limit
    current = legacy.exec_events(path, CID, "current")
    assert [entry["command"] for entry in current["command_executions"]] == ["echo current"]
    assert events.exec_events(path, CID, "current") == current
    history = legacy.exec_events(path, CID, "all")
    assert len(history["command_executions"]) == record_count + 1
    expected = history_hash(history)
    del history
    history = events.exec_events(path, CID, "all")
    assert len(history["command_executions"]) == record_count + 1
    assert history_hash(history) == expected


def test_current_scope_filters_after_one_aggregate_budget(make_store, monkeypatch):
    """Scope filters output after every turn is read. An earlier turn shares the budget."""
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", 1600)
    fitting = write_rollout(make_store, META, event("task_started", turn_id="old"),
                            script("one", shell("echo old")), event("task_started", turn_id="new"),
                            event("exec_command_end", command="echo current"), name="fitting.jsonl")
    start = Barrier(2, timeout=5)

    def observe(scope):
        start.wait()
        return events.exec_events(fitting, CID, scope)

    with ThreadPoolExecutor(max_workers=2) as workers:
        current = workers.submit(observe, "current")
        history = workers.submit(observe, "all")
        assert current.result(timeout=5) == legacy.exec_events(fitting, CID, "current")
        assert history.result(timeout=5) == legacy.exec_events(fitting, CID, "all")
    command = "echo " + "x" * 300
    call = shell(command)
    heavy = write_rollout(make_store, META, event("task_started", turn_id="old"),
                          script("one", call + call + call), event("task_started", turn_id="new"),
                          event("exec_command_end", command="echo current"), name="heavy.jsonl")
    start_fail = Barrier(2, timeout=5)

    def refuse(scope):
        start_fail.wait()
        events.exec_events(heavy, CID, scope)

    with ThreadPoolExecutor(max_workers=2) as workers:
        jobs = [workers.submit(refuse, scope) for scope in ("current", "all")]
        for job in jobs:
            with pytest.raises(rollout.NativeRolloutRefusal) as caught:
                job.result(timeout=5)
            assert_refusal(caught, "too_large")
    retry = write_rollout(make_store, META, event("task_started", turn_id="new"),
                          script("one", shell("echo current")), name="retry.jsonl")
    assert events.exec_events(retry, CID) == legacy.exec_events(retry, CID)


def test_history_budget_does_not_charge_fixed_code_mode_envelope(make_store, monkeypatch):
    source = shell("echo x") * scanner.CODE_MODE_MAX_CALLS
    path = write_rollout(make_store, META, script("one", source))
    # Scale the ceiling to the fixture's input. Each call has its own literal,
    # while the generated schema fields and rollout pathname are shared.
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", 4 * path.stat().st_size)
    assert events.exec_events(path, CID, "all") == legacy.exec_events(path, CID, "all")


def test_large_catalog_refuses_legacy_utf8_amplification(make_store):
    name = "😀" * 100_000
    tools = [{"name": "x%d" % index} for index in range(1000)]
    namespace = {"type": "namespace", "name": name, "tools": tools}
    # Measure the legacy projection without allocating all 400 MB of it.
    _, sample = legacy.offered_agent_tools({"tools": [{**namespace, "tools": tools[:1]}]}, 2)
    prefix_bytes = len(sample[0].encode()) - len(tools[0]["name"])
    assert sum(prefix_bytes + len(tool["name"]) for tool in tools) == 400_004_890
    path = write_rollout(make_store, META, response("additional_tools", tools=[namespace]))
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.multi_agent_state(path, CID)
    assert_refusal(caught, "too_large")


def test_large_option_union_refuses_repeated_legacy_projection(make_store):
    source = shell(options="".join(",opt%d:1" % index for index in range(7000)))
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample"})
    opened = script("one", source)
    path = write_rollout(make_store, META, opened, typed)
    # Legacy allocates this list independently at every matching completion.
    entry, = legacy.exec_events(path, CID)["command_executions"]
    assert len(entry["options"]) == 7000
    path = write_rollout(make_store, META, opened, *([typed] * 30_000))
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID)
    assert_refusal(caught, "too_large")


def test_unparsed_loops_keep_attribution_uncertain(make_store):
    from tools.hierarchy_probe_evidence import command_matches

    source = ('const a=["echo first"]; const b=["echo second"]; '
              'for (const cmd of a) text(await tools.exec_command({cmd,workdir:"elsewhere"})); '
              'for (const cmd of b) text(await tools.exec_command({cmd})); text(foo());')
    command = "echo first"
    typed = event("item_completed", item={"type": "CommandExecution", "command": command})
    path = write_rollout(make_store, META, script("one", source), typed)
    expected = legacy.exec_events(path, CID)
    actual = events.exec_events(path, CID)
    reference = expected["command_executions"][0]
    observed, = actual["command_executions"]
    assert_script_diagnostic(actual, "expected text ( await")
    assert command_matches(reference, command, True, events.CODE_MODE_SAFE_OPTIONS) == "exact"
    assert command_matches(observed, command, True, events.CODE_MODE_SAFE_OPTIONS) == "untrusted"
    write_rollout(make_store, META, typed)
    assert events.exec_events(path, CID) == legacy.exec_events(path, CID)


@pytest.mark.parametrize("placement", ["payload", "record"])
@pytest.mark.parametrize("refused", [False, True], ids=["restricted", "refused"])
def test_call_turn_cannot_remove_legacy_active_turn_restrictions(make_store, placement, refused):
    from tools.hierarchy_probe_evidence import command_matches

    options = ',workdir:"/attacker"' + (',cmd:"echo sample"' if refused else "")
    opened = script("one", shell(options=options))
    target = opened["payload"] if placement == "payload" else opened
    target["turn_id"] = "other"
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample", "exit_code": 0})
    path = write_rollout(make_store, META, event("task_started", turn_id="turn-1"), opened, typed)
    expected, actual = legacy.exec_events(path, CID), events.exec_events(path, CID)
    assert command_matches(expected["command_executions"][0], "echo sample", True,
                           events.CODE_MODE_SAFE_OPTIONS) == "untrusted"
    assert command_matches(actual["command_executions"][0], "echo sample", True,
                           events.CODE_MODE_SAFE_OPTIONS) == "untrusted"
    if not refused:
        assert actual == expected
    typed["payload"]["turn_id"] = None
    write_rollout(make_store, META, event("task_started", turn_id="turn-1"), opened, typed)
    expected, actual = legacy.exec_events(path, CID, "all"), events.exec_events(path, CID, "all")
    if refused:
        assert command_matches(actual["command_executions"][0], "echo sample", True,
                               events.CODE_MODE_SAFE_OPTIONS) == "untrusted"
    else:
        assert actual == expected


@pytest.mark.parametrize("call,item", [
    (patch(), {"type": "FileChange", "changes": [{"path": "sample.txt"}], "status": "completed"}),
    (shell(), {"type": "CommandExecution", "command": "echo sample"}),
    (shell(), {"type": "CommandExecution", "command": ["echo", "independent"]}),
], ids=["patch", "matching-shell", "unrelated-argv"])
def test_catalog_length_print_keeps_typed_evidence_untrusted(make_store, call, item):
    path = write_rollout(make_store, META, script("one", call + "text(ALL_TOOLS.length);"),
                         event("item_completed", item=item))
    actual = events.exec_events(path, CID)
    if item["type"] == "CommandExecution" and item["command"] == "echo sample":
        assert _exact(actual["command_executions"][0], "echo sample") == "untrusted"
    else:
        assert actual["patch_applies" if item["type"] == "FileChange" else "command_executions"][0]["options"] == [
            "code_mode_unparsed"]


@pytest.mark.parametrize("call", [shell(), patch()], ids=["shell", "patch"])
@pytest.mark.parametrize("error", ["[" * 35 + " error", "{" * 35 + " error", "[" * 35 + " error" + "]" * 35])
def test_bracket_prefixed_plain_catch_text_matches_legacy(make_store, call, error):
    source = "try { " + call + " } catch (e) { text(String(e)); }"
    path = write_rollout(make_store, META, script("one", source), printed("one", error))
    expected = legacy.exec_events(path, CID)
    entries = expected["command_executions"] or expected["patch_applies"]
    assert entries[0]["stderr"] == error and entries[0]["status"] == "failed"
    assert events.exec_events(path, CID) == expected


def _exact(entry, command):
    from tools.hierarchy_probe_evidence import command_matches

    return command_matches(entry, command, True, events.CODE_MODE_SAFE_OPTIONS)


def _watch_retained(monkeypatch, limit):
    """Count executions, patches, diagnostics and open call lists held at once."""
    peak = {"n": 0}
    original_open = events._ExecEvidence.open_script
    original_emit = events._ExecEvidence.emit
    original_typed = events._ExecEvidence.typed

    original_open_call = events._ExecEvidence.open_call

    def note(self):
        found = len(self.executions) + len(self.patches) + len(self.unparsed)
        found += sum(len(item["calls"]) for item in self.scripts.values())
        found += sum(1 for item in self.pending.values() if len(item) > 4 and item[4] is not None)
        peak["n"] = max(peak["n"], found)
        if limit is not None and found > limit:
            raise RuntimeError("retained %d derived objects" % found)

    def open_call(self, *args, **kwargs):
        original_open_call(self, *args, **kwargs)
        note(self)

    def open_script(self, *args, **kwargs):
        original_open(self, *args, **kwargs)
        note(self)

    def emit(self, *args, **kwargs):
        original_emit(self, *args, **kwargs)
        note(self)

    def typed(self, *args, **kwargs):
        original_typed(self, *args, **kwargs)
        note(self)

    monkeypatch.setattr(events._ExecEvidence, "open_call", open_call)
    monkeypatch.setattr(events._ExecEvidence, "open_script", open_script)
    monkeypatch.setattr(events._ExecEvidence, "emit", emit)
    monkeypatch.setattr(events._ExecEvidence, "typed", typed)
    return peak


@pytest.mark.parametrize("prefix", [
    'text("start");',
    "text('start');",
    "text(`plain`);",
    "text();",
    "text(1);",
    "text(true);",
    "text(false);",
    "text(null);",
    "text(undefined);",
])
def test_inert_prints_make_the_script_uncertain(prefix):
    assert_unparsed_script(prefix + shell())
    loop = ('const a=["echo one"]; for (const cmd of a) { %s'
            "text(await tools.exec_command({cmd})); }") % prefix
    assert_unparsed_script(loop)
    assert_unparsed_script("try { %s%s } catch (e) { text(String(e)); }" % (prefix, shell()))


def test_inert_statement_marks_typed_shell_uncertain(make_store):
    command = "echo sample"
    source = 'text("start"); ' + shell(command)
    typed = event("item_completed", item={"type": "CommandExecution", "command": command, "exit_code": 0})
    path = write_rollout(make_store, META, event("task_started", turn_id="one"), script("one", source), typed)
    actual = events.exec_events(path, CID, "all")
    # ROUND-1g OWNER-A: an inert print before a call is uncertain, not exact.
    assert _exact(actual["command_executions"][0], command) == "untrusted"


def test_inert_statement_marks_completed_patch_uncertain(make_store):
    source = 'text("start"); ' + patch()
    typed = event("item_completed", item={"type": "FileChange", "status": "completed",
                                          "changes": [{"path": "sample.txt"}]})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID, "all")
    # ROUND-1g OWNER-A: an inert print before a patch is uncertain, not exact.
    assert actual["patch_applies"][0]["success"] is True
    assert actual["patch_applies"][0]["options"] == ["code_mode_unparsed"]


@pytest.mark.parametrize("prefix", ['text(1);', "text(true);", "text(false);", "text(null);", "text('done');"])
def test_inert_print_siblings_keep_typed_commands_uncertain(make_store, prefix):
    command = "echo sample"
    source = shell(command) + prefix
    typed = event("item_completed", item={"type": "CommandExecution", "command": command, "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    # ROUND-1g OWNER-A: an inert print after a call is uncertain, not exact.
    assert _exact(actual["command_executions"][0], command) == "untrusted"


def test_inert_print_inside_braced_loop_is_uncertain(make_store):
    command = "echo one"
    source = ('const a=["echo one"]; for (const cmd of a) { text(await tools.exec_command({cmd})); '
              'text("done"); }')
    typed = event("item_completed", item={"type": "CommandExecution", "command": command, "exit_code": 0})
    path = write_rollout(make_store, META, event("task_started", turn_id="one"), script("one", source), typed,
                         event("task_started", turn_id="two"),
                         event("exec_command_end", command="echo later", exit_code=0))
    actual = events.exec_events(path, CID, "all")
    # ROUND-1g OWNER-A: an inert print inside a loop body is uncertain, not exact.
    assert _exact(actual["command_executions"][0], command) == "untrusted"
    assert [entry["command"] for entry in actual["command_executions"]][0] == command
    assert actual["command_executions"][-1]["command"] == "echo later"
    current = events.exec_events(path, CID, "current")
    assert current["current_turn_id"] == "two"
    assert current["command_executions"][0]["command"] == "echo later"


def test_numeric_literal_before_a_call_is_uncertain(make_store):
    # ROUND-1g OWNER-A: formal 1819 text(1.5) before a call is uncertain, not exact.
    command = "echo sample"
    source = "text(1.5); " + shell(command)
    typed = event("item_completed", item={"type": "CommandExecution", "command": command, "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    assert _exact(actual["command_executions"][0], command) == "untrusted"
    assert_unparsed_script(source)


def test_inert_only_loop_before_a_call_is_uncertain(make_store):
    # ROUND-1g OWNER-A: formal 1819 inert-only loop body before a call is uncertain, not exact.
    command = "echo sample"
    source = ('const commands=["ignored"]; for (const cmd of commands) { text("progress"); } '
              + shell(command))
    typed = event("item_completed", item={"type": "CommandExecution", "command": command, "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    assert _exact(actual["command_executions"][0], command) == "untrusted"
    assert all(entry["command"] != "ignored" for entry in actual["command_executions"])
    assert_unparsed_script(source)


@pytest.mark.parametrize("source", [
    ('const one=["echo one"]; for (const cmd of one) { '
     'text(await tools.exec_command({cmd,workdir:"/tmp"})); } '
     'const two=["echo two"]; for (const cmd of two) { text("progress"); }'),
    ('const one=["echo one"]; for (const cmd of one) { text("progress"); } '
     'const two=["echo two"]; for (const cmd of two) { text("later"); } '
     'text(await tools.exec_command({cmd,workdir:"/tmp"}));'),
])
def test_two_inert_only_loops_do_not_rebind_an_earlier_cmd(make_store, source):
    assert_unparsed_script(source)
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo one", "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    entry, = actual["command_executions"]
    assert _exact(entry, "echo one") == "untrusted"


def test_unparsed_script_keeps_typed_evidence_and_later_turns(make_store):
    source = ('const a=["echo one"]; for (const cmd of a) { text(await tools.exec_command({cmd})); } '
              "text(foo());")
    opened = script("one", source)
    opened["payload"]["turn_id"] = "wire"
    later = event("exec_command_end", command="echo later", exit_code=0)
    patches = [
        event("item_completed", turn_id="wire", item={"type": "FileChange", "status": "completed",
                                                      "changes": [{"path": "sample.txt"}]}),
        event("patch_apply_end", turn_id="wire", success=True, changes={"sample.txt": {}}),
        {"type": "item.completed", "item": {"type": "file_change", "status": "completed",
                                            "changes": [{"path": "sample.txt"}]}},
    ]
    for patch_event in patches:
        path = write_rollout(make_store, META, event("task_started", turn_id="one"), opened, patch_event,
                             event("task_started", turn_id="two"), later)
        actual = events.exec_events(path, CID, "all")
        commands = [entry["command"] for entry in actual["command_executions"]]
        assert commands == ["echo later"]
        assert_script_diagnostic(actual, "expected text ( await")
        marked = [entry for entry in actual["patch_applies"] if entry.get("options")]
        assert marked and all("code_mode_unparsed" in entry["options"] for entry in marked)
        current = events.exec_events(path, CID, "current")
        assert current["current_turn_id"] == "two"
        assert [entry["command"] for entry in current["command_executions"]] == ["echo later"]


def test_selected_turn_does_not_retain_earlier_turn_executions(make_store, monkeypatch):
    peak = _watch_retained(monkeypatch, None)
    array = json.dumps(["x"] * 4)
    source = "const a=%s;for(const cmd of a)text(await tools.exec_command({cmd}));" % array
    rows = [META]
    for turn in range(3):
        rows.append(event("task_started", turn_id="t%d" % turn))
        for index in range(2):
            call = "t%d-%d" % (turn, index)
            rows.append(script(call, source))
            rows.append(response("custom_tool_call_output", call_id=call, output="Script completed\n"))
    rows.append(event("task_started", turn_id="final"))
    path = write_rollout(make_store, *rows)
    current = events.exec_events(path, CID, "current")
    assert current["current_turn_id"] == "final"
    assert current["command_executions"] == current["patch_applies"] == current["code_mode_unparsed"] == []
    assert 0 < peak["n"] <= 24
    assert len(events.exec_events(path, CID, "all")["command_executions"]) == 24


def test_hostile_history_stays_inside_the_aggregate_budget(make_store, monkeypatch):
    """20 turns x 1,000 scripts x 1,000 commands refuses too_large before the budget is exceeded."""
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", 250000)
    peak = _watch_retained(monkeypatch, None)
    commands = ",".join('"x"' for _ in range(1000))
    source = "const a=[%s];for(const cmd of a)text(await tools.exec_command({cmd}));" % commands
    path = make_store / "hostile.jsonl"
    with path.open("wb") as stream:
        stream.write(record_bytes(META))
        sequence = 0
        for turn in range(20):
            stream.write(record_bytes(event("task_started", turn_id="t%d" % turn)))
            for _index in range(1000):
                call = str(sequence)
                sequence += 1
                stream.write(record_bytes(script(call, source)))
                stream.write(record_bytes(response("custom_tool_call_output", call_id=call,
                                                   output="Script completed\n")))
        stream.write(record_bytes(event("task_started", turn_id="final")))
    size = path.stat().st_size
    assert 120_000_000 < size < rollout.MAX_ROLLOUT_BYTES
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID, "current")
    assert_refusal(caught, "too_large")
    assert 0 < peak["n"] < 20_000_000
    (make_store / "hostile-peak.txt").write_text("%d\n" % peak["n"])


def test_catalog_length_print_keeps_the_strict_diagnostic(make_store):
    source = shell() + "text(ALL_TOOLS.length);"
    path = write_rollout(make_store, META, event("task_started", turn_id="one"), script("call", source),
                         printed("call", chunk(exit_code=0), "3"), event("task_started", turn_id="two"))
    actual = events.exec_events(path, CID, "all")
    assert_no_script_proposals(actual, "expected text ( await")


@pytest.mark.parametrize("prefix", [
    "text(ALL_TOOLS.length);",
    "text(1 + 2);",
    "text(foo());",
    'text(await tools.exec_command?.({cmd:"./probe",workdir:"/attacker"}));',
    'text(`${await tools.exec_command({cmd:"echo sample",workdir:"/attacker"})}`);',
    'text(a[0]="echo sample");',
    "text(1, 2);",
    "text(1.5);",
    "text(TRUE);",
    "text(++n);",
    "delete target;",
    'text(await tools.exec_command({cmd:await tools.exec_command({cmd:"echo sample"})}));',
    "text(fn`arg`);",
])
def test_nonliteral_prints_are_unparsed(prefix):
    assert_unparsed_script(prefix + shell())


def test_optional_call_print_stays_untrusted(make_store):
    source = 'text(await tools.exec_command?.({cmd:"./probe",workdir:"/attacker"}));'
    typed = event("item_completed", item={"type": "CommandExecution", "command": "./probe", "exit_code": 0})
    path = write_rollout(make_store, META, event("task_started", turn_id="one"), script("one", source), typed)
    actual = events.exec_events(path, CID)
    assert _exact(actual["command_executions"][0], "./probe") == "untrusted"


def test_template_interpolation_print_stays_untrusted(make_store):
    source = 'text(`${await tools.exec_command({cmd:"echo sample",workdir:"/attacker"})}`);'
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample", "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    assert _exact(actual["command_executions"][0], "echo sample") == "untrusted"


def test_assignment_print_keeps_the_typed_command_untrusted(make_store):
    source = ('const a=["echo benign"]; text(a[0]="echo sample"); for (const cmd of a) { '
              'text(await tools.exec_command({cmd,workdir:"/attacker"})); }')
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample", "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    typed_entries = [entry for entry in actual["command_executions"] if entry["command"] == "echo sample"]
    assert typed_entries
    assert all(_exact(entry, "echo sample") == "untrusted" for entry in typed_entries)


def test_current_scope_keeps_cross_turn_duplicate_key_uncertainty(make_store):
    opened = script("one", 'text(await tools.exec_command({cmd:"./probe",cmd:"./probe",workdir:"/attacker"}));')
    opened["payload"]["turn_id"] = "new"
    typed = event("item_completed", turn_id="new", item={"type": "CommandExecution", "command": "./probe",
                                                         "exit_code": 0})
    path = write_rollout(make_store, META, event("task_started", turn_id="old"), opened,
                         event("task_started", turn_id="new"), typed)
    for scope in ("current", "all"):
        result = events.exec_events(path, CID, scope)
        assert [entry["command"] for entry in result["command_executions"]] == ["./probe"]
        assert _exact(result["command_executions"][0], "./probe") == "untrusted"


@pytest.mark.parametrize("catch", [
    "text(null); text(String(e));",
    "text(String(e)); text(null);",
    'text("done"); text(String(e));',
    'text(String(e)); text("done");',
    "text(); text(String(e));",
    "text(undefined); text(String(e));",
    "text(1); text(String(e));",
    "text(String(e)); text();",
])
def test_catch_body_inert_prints_are_uncertain(make_store, catch):
    source = "try { text(null); %s } catch (e) { %s }" % (shell(), catch)
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample", "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID)
    # ROUND-1g OWNER-A: inert prints around a catch make the call uncertain, not exact.
    assert _exact(actual["command_executions"][0], "echo sample") == "untrusted"


def test_catch_object_form_with_inert_prints_is_uncertain(make_store):
    source = ('const a=["echo sample"]; for (const cmd of a) { try { text(await tools.exec_command({cmd})); } '
              'catch (e) { text(null); text({cmd, error: String(e)}); text("after"); } }')
    typed = event("item_completed", item={"type": "CommandExecution", "command": "echo sample", "exit_code": 0})
    path = write_rollout(make_store, META, script("one", source), typed)
    actual = events.exec_events(path, CID, "all")
    # ROUND-1g OWNER-A: inert prints around the error print make the loop uncertain, not exact.
    assert _exact(actual["command_executions"][0], "echo sample") == "untrusted"
    assert all(entry["command"] != "echo two" for entry in actual["command_executions"])


def test_catch_without_the_error_print_stays_refused():
    source = 'try { %s } catch (e) { text("done"); }' % shell()
    with pytest.raises(scanner.Unrecognized) as caught:
        scanner.scan_code_mode(source)
    assert_refusal(caught, "a catch that prints something else")
    _calls, paired, unparsed, unknown = scanner.code_mode_calls(source)
    assert paired is False and unknown is True
    assert unparsed[0]["reason"] == "a catch that prints something else"


def test_one_read_ignores_a_turn_appended_between_opens(make_store, monkeypatch):
    path = write_rollout(make_store, META, event("task_started", turn_id="turn-1"),
                         event("exec_command_end", command="echo old", exit_code=0))
    calls = {"n": 0}
    original = events.rollout_records

    def rollout_records(opened, tolerant=False):
        calls["n"] += 1
        if calls["n"] == 2:
            with path.open("ab") as stream:
                stream.write(record_bytes(event("task_started", turn_id="turn-2")))
                stream.write(record_bytes(event("exec_command_end", command="echo new", exit_code=0)))
        return original(opened, tolerant)

    monkeypatch.setattr(events, "rollout_records", rollout_records)
    result = events.exec_events(path, CID, "current")
    assert calls["n"] == 1
    assert result["current_turn_id"] == "turn-1"
    assert [entry["command"] for entry in result["command_executions"]] == ["echo old"]


def test_scope_current_reports_the_last_turn_of_one_snapshot(make_store):
    path = write_rollout(make_store, META, event("task_started", turn_id="turn-1"),
                         event("exec_command_end", command="echo old", exit_code=0),
                         event("task_started", turn_id="turn-2"),
                         event("exec_command_end", command="echo new", exit_code=0))
    current = events.exec_events(path, CID, "current")
    assert current["current_turn_id"] == "turn-2"
    assert [entry["command"] for entry in current["command_executions"]] == ["echo new"]
    assert events.exec_events(path, CID, "all") == legacy.exec_events(path, CID, "all")


@pytest.mark.parametrize("source", [shell(), patch()], ids=["shell", "patch"])
def test_failed_output_cannot_supply_evidence_for_an_unparsed_script(make_store, source):
    path = write_rollout(make_store, META, script("one", source + 'text("done");'), printed("one", failed="boom"))
    assert_no_script_proposals(events.exec_events(path, CID), "expected text ( await")


def test_leading_inert_print_prevents_patch_proposals(make_store):
    source = 'text("{}"); ' + patch("first.txt") + patch("second.txt")
    path = write_rollout(make_store, META, script("one", source),
                         printed("one", "{}", failed="patch rejected: Permission denied"))
    assert_no_script_proposals(events.exec_events(path, CID), "expected text ( await")


def test_unclosed_apply_patch_growth_shares_the_aggregate_budget(make_store, monkeypatch):
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", 2000)
    huge = "h" * 8000
    pending = response("custom_tool_call", name="apply_patch", call_id="pending", input=huge)
    oversized = write_rollout(make_store, META, event("task_started", turn_id="one"), pending, name="one-patch.jsonl")
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(oversized, CID, "all")
    assert_refusal(caught, "too_large")
    many = [response("custom_tool_call", name="apply_patch", call_id="p%d" % index, input="m" * 800)
            for index in range(20)]
    grown = write_rollout(make_store, META, *many, name="many-patches.jsonl")
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(grown, CID, "current")
    assert_refusal(caught, "too_large")
    opened = response("function_call", name="apply_patch", call_id="out", arguments="*** Add File: a.txt\n")
    closed = response("function_call_output", call_id="out", output=huge)
    answered = write_rollout(make_store, META, opened, closed, name="answered.jsonl")
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(answered, CID, "all")
    assert_refusal(caught, "too_large")
    small = response("custom_tool_call", name="apply_patch", call_id="small", input="*** Add File: a.txt\n")
    fitting = write_rollout(make_store, META, small, name="small-patch.jsonl")
    assert events.exec_events(fitting, CID)["patch_applies"][0]["call_id"] == "small"
    start = Barrier(2, timeout=5)

    def read(path, scope):
        start.wait()
        return events.exec_events(path, CID, scope)

    with ThreadPoolExecutor(max_workers=2) as workers:
        jobs = [workers.submit(read, oversized, scope) for scope in ("current", "all")]
        for job in jobs:
            with pytest.raises(rollout.NativeRolloutRefusal) as caught:
                job.result(timeout=5)
            assert_refusal(caught, "too_large")
    start_ok = Barrier(2, timeout=5)

    def read_fitting(scope):
        start_ok.wait()
        return events.exec_events(fitting, CID, scope)

    with ThreadPoolExecutor(max_workers=2) as workers:
        jobs = [workers.submit(read_fitting, scope) for scope in ("current", "all")]
        assert all(job.result(timeout=5)["patch_applies"][0]["call_id"] == "small" for job in jobs)


def test_patch_finalization_charges_the_payload_until_it_is_dropped(make_store, monkeypatch):
    """Refunding a pending patch before dropping it lets the emission fit alone."""
    body = "*** Add File: a.txt\n" + ("h" * 400)
    path = write_rollout(make_store, META, response("custom_tool_call", name="apply_patch", call_id="patch",
                                                    input=body), name="patch-final.jsonl")
    sizes = []
    original = events._ByteBudget.reserve

    def reserve(self, size):
        sizes.append(size)
        return original(self, size)

    monkeypatch.setattr(events._ByteBudget, "reserve", reserve)
    assert events.exec_events(path, CID, "all")["patch_applies"][0]["call_id"] == "patch"
    payload_charge, emission_charge = sizes
    assert payload_charge > emission_charge > 0
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", payload_charge + emission_charge - 1)
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(path, CID, "all")
    assert_refusal(caught, "too_large")
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", payload_charge + emission_charge)
    assert events.exec_events(path, CID, "all")["patch_applies"][0]["call_id"] == "patch"


def _write_script_history(path, source, closed, pending):
    with path.open("wb") as stream:
        stream.write(record_bytes(META))
        stream.write(record_bytes(event("task_started", turn_id="t")))
        for index in range(closed):
            call = "%06d" % index
            stream.write(record_bytes(script(call, source)))
            stream.write(record_bytes(response("custom_tool_call_output", call_id=call,
                                               output="Script completed\n")))
        for index in range(closed, closed + pending):
            call = "%06d" % index
            stream.write(record_bytes(script(call, source)))


def test_closed_and_pending_scripts_share_one_observation_budget(make_store, monkeypatch):
    """The mixed history exhausts the shared ceiling while either half fits."""
    # Scale both populations and byte ceilings together. Each script still
    # expands to the same number of calls as in the original workload.
    scale = 50
    script_count = 5000 // scale
    calls_per_script = 1000
    limit = events.MAX_OBSERVATION_BYTES // scale
    rollout_limit = rollout.MAX_ROLLOUT_BYTES // scale
    monkeypatch.setattr(events, "MAX_OBSERVATION_BYTES", limit)
    monkeypatch.setattr(rollout, "MAX_ROLLOUT_BYTES", rollout_limit)
    commands = ",".join('"x"' for _ in range(calls_per_script))
    source = "const a=[%s];for(const cmd of a)text(await tools.exec_command({cmd}));" % commands
    peak = {"charged": 0}
    charged = {"total": 0}
    original_init = events._ByteBudget.__init__
    original_reserve = events._ByteBudget.reserve
    original_release = events._ByteBudget.release

    def init(self, limit):
        original_init(self, limit)
        self._tracks_observation_charge = limit == events.MAX_OBSERVATION_BYTES

    def reserve(self, size):
        before = self.remaining
        allowed = original_reserve(self, size)
        if self._tracks_observation_charge:
            total = charged["total"] + before - self.remaining
            charged["total"] = total
            if total > peak["charged"]:
                peak["charged"] = total
        return allowed

    def release(self, size):
        before = self.remaining
        original_release(self, size)
        if self._tracks_observation_charge:
            charged["total"] -= self.remaining - before

    monkeypatch.setattr(events._ByteBudget, "__init__", init)
    monkeypatch.setattr(events._ByteBudget, "reserve", reserve)
    monkeypatch.setattr(events._ByteBudget, "release", release)
    combined = make_store / "closed-and-open.jsonl"
    _write_script_history(combined, source, script_count, script_count)
    assert 50_000_000 // scale < combined.stat().st_size < rollout_limit
    with pytest.raises(rollout.NativeRolloutRefusal) as caught:
        events.exec_events(combined, CID, "all")
    assert_refusal(caught, "too_large")
    # Both piles are retained together on split ceilings. One budget stays inside the ceiling.
    assert 285_000_000 // scale <= peak["charged"] <= limit
    combined.unlink()
    charged["total"] = 0

    peak["charged"] = 0
    closed = make_store / "closed.jsonl"
    _write_script_history(closed, source, script_count, 0)
    closed_result = events.exec_events(closed, CID, "all")
    assert len(closed_result["command_executions"]) == script_count * calls_per_script
    assert peak["charged"] <= limit
    del closed_result
    closed.unlink()
    charged["total"] = 0

    peak["charged"] = 0
    pending = make_store / "open.jsonl"
    _write_script_history(pending, source, 0, script_count)
    pending_result = events.exec_events(pending, CID, "all")
    assert len(pending_result["command_executions"]) == script_count * calls_per_script
    assert peak["charged"] <= limit
    del pending_result
    pending.unlink()


def test_unparsed_script_keeps_typed_shell_and_patch_without_partial_diagnostics(make_store):
    source = shell("echo prefix") + patch("prefix.txt")
    source += "text(await tools.exec_command({cmd:private_marker}));"
    source += "text(await tools.apply_patch(private_patch));"
    assert_unparsed_script(source)
    completed = event("item_completed", item={
        "type": "CommandExecution", "command": "echo prefix", "exit_code": 0,
    })
    changed = event("item_completed", item={
        "type": "FileChange", "changes": [{"path": "prefix.txt"}], "status": "completed",
    })
    path = write_rollout(make_store, META, script("one", source), completed, changed,
                         printed("one", chunk(exit_code=0), "{}"))
    result = events.exec_events(path, CID)
    command, = result["command_executions"]
    patch_entry, = result["patch_applies"]
    assert (command["command"], command["exit_code"], command["source"]) == ("echo prefix", 0, "item_completed")
    assert (patch_entry["paths"], patch_entry["success"], patch_entry["source"]) == (
        ["prefix.txt"], True, "item_completed")
    assert command["options"] == patch_entry["options"] == ["code_mode_unparsed"]
    assert result["code_mode_unparsed"] == [{
        **script_diagnostic("cmd is not a string literal"), "turn_id": None, "call_id": "one", "line": 2,
    }]


def test_interleaved_strict_and_unparsed_scripts_keep_attribution_local():
    source = shell()
    start = Barrier(2, timeout=5)

    def observe(script_text):
        start.wait()
        return scanner.code_mode_calls(script_text)

    with ThreadPoolExecutor(max_workers=2) as workers:
        accepted = workers.submit(observe, source)
        refused = workers.submit(observe, source + 'text("done");')
        assert refused.result(timeout=5) == ([], False, [script_diagnostic("expected text ( await")], True)
        admitted = accepted.result(timeout=5)
    calls, paired, diagnostics, unknown = admitted
    assert (paired, diagnostics, unknown) == (True, [], False)
    call, = calls
    assert call["command"] == "echo sample"
    assert scanner.code_mode_calls(source) == admitted


def test_token_work_is_bounded_before_parsing_and_after_retry(monkeypatch):
    observed = {"tokens": 0}

    class MeasuredLimit(int):
        def __eq__(self, size):
            observed["tokens"] += 1
            return super().__eq__(size)

    limit_count = 32
    monkeypatch.setattr(scanner, "MAX_CODE_MODE_TOKENS", MeasuredLimit(limit_count))
    limit = {
        "tool": "exec", "reason": "code-mode input exceeds token limit", "code": 2,
        "next_action": "Reduce the code-mode script to the observation limits, then retry.",
    }
    for size in (64, 10000):
        observed["tokens"] = 0
        assert scanner.code_mode_calls(shell() + "?" * size) == ([], False, [limit], True)
        assert observed["tokens"] == limit_count + 1
    calls, paired, diagnostics, unknown = scanner.code_mode_calls(shell())
    assert (paired, diagnostics, unknown) == (True, [], False)
    call, = calls
    assert call["command"] == "echo sample"
